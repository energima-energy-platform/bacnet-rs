//! Concurrent asynchronous BACnet/IP client.
//!
//! One endpoint task owns the UDP socket, receives every datagram, and routes
//! confirmed responses to callers through per-transaction one-shot channels.
//! Cloned client handles submit commands through a bounded queue; requests are
//! sent without waiting for earlier transactions to complete. Discovery
//! (Who-Is, Who-Is-Router-To-Network) registers a response sink with the
//! endpoint, which forwards matching unconfirmed frames until the timeout
//! window closes.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
    time::{sleep_until, Instant},
};

use crate::{
    app::{Apdu, MaxApduSize, MaxSegments},
    datalink::bip::BACNET_IP_PORT,
    network::{NetworkAddress, Npdu},
    object::{ObjectIdentifier, ObjectType, PropertyIdentifier, Segmentation},
    property::{encode_property_value, PropertyValue},
    service::{
        cov_notification::CovNotification, AbortReason, ConfirmedServiceChoice, PropertyReference,
        ReadAccessSpecification, ReadPropertyMultipleRequest, ReadPropertyMultipleResponse,
        ReadPropertyRequest, ReadPropertyResponse, RejectReason, SubscribeCovRequest,
        UnconfirmedServiceChoice, WhoIsRequest, WritePropertyRequest,
    },
};

use super::{
    create_unconfirmed_frame, create_who_is_network_frame, create_who_is_router_frame,
    decode_bacnet_ip_frame, decode_object_list_value, is_broadcast_target,
    parse_i_am_router_response, parse_iam_response, property_read_result, BacnetTarget,
    ClientConfig, ClientError, DeviceInfo, DiscoveredRouter, ObjectSnapshot, PropertyReadResult,
    BVLC_ORIGINAL_UNICAST,
};

const COMMAND_QUEUE_CAPACITY: usize = 256;
const MAX_BACNET_IP_FRAME: usize = 65_535;

/// Cloneable handle to a concurrent BACnet/IP endpoint.
///
/// The handle does not own or receive from the UDP socket. All clones submit
/// work to one endpoint task, which permits unrelated requests to remain in
/// flight at the same time without competing for datagrams.
#[derive(Clone)]
pub struct AsyncBacnetClient {
    commands: mpsc::Sender<EndpointCommand>,
    local_addr: SocketAddr,
}

impl AsyncBacnetClient {
    /// Bind using the default client configuration.
    pub async fn new() -> Result<Self, ClientError> {
        Self::from_config(ClientConfig::default()).await
    }

    /// Bind a concurrent client using an explicit configuration.
    pub async fn from_config(config: ClientConfig) -> Result<Self, ClientError> {
        let socket = UdpSocket::bind(config.bind_addr()).await?;
        Self::from_socket(socket, config.timeout, config.retries)
    }

    /// Build a client around an already-bound Tokio UDP socket.
    pub fn from_socket(
        socket: UdpSocket,
        timeout: Duration,
        retries: u8,
    ) -> Result<Self, ClientError> {
        let local_addr = socket.local_addr()?;
        // Discovery may target broadcast addresses.
        socket.set_broadcast(true)?;
        let (commands, receiver) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        tokio::spawn(Endpoint::new(socket, receiver, timeout, retries).run());
        Ok(Self {
            commands,
            local_addr,
        })
    }

    /// Address of the endpoint's single UDP socket.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Broadcast a Who-Is on the local subnet and collect every device that
    /// answers with an I-Am, until the configured timeout elapses.
    ///
    /// Results are de-duplicated by device id.
    pub async fn who_is(
        &self,
        low_limit: Option<u32>,
        high_limit: Option<u32>,
    ) -> Result<Vec<DeviceInfo>, ClientError> {
        let broadcast = SocketAddr::from(([255, 255, 255, 255], BACNET_IP_PORT));
        self.who_is_to(broadcast, low_limit, high_limit).await
    }

    /// Send a Who-Is to a specific address (broadcast or unicast) and collect
    /// all I-Am replies until the timeout elapses.
    ///
    /// Broadcast targets are framed as a global-broadcast NPDU inside an
    /// Original-Broadcast-NPDU BVLC, matching the sync client.
    pub async fn who_is_to(
        &self,
        target_addr: SocketAddr,
        low_limit: Option<u32>,
        high_limit: Option<u32>,
    ) -> Result<Vec<DeviceInfo>, ClientError> {
        let frame = create_unconfirmed_frame(
            UnconfirmedServiceChoice::WhoIs as u8,
            &encode_who_is(low_limit, high_limit)?,
            is_broadcast_target(target_addr),
        );
        self.discover_devices(frame, target_addr).await
    }

    /// Send Who-Is through a known BACnet router to every station on a
    /// downstream BACnet network and collect the resulting I-Am responses.
    pub async fn who_is_network(
        &self,
        router_addr: SocketAddr,
        destination_network: u16,
        low_limit: Option<u32>,
        high_limit: Option<u32>,
    ) -> Result<Vec<DeviceInfo>, ClientError> {
        let frame = create_who_is_network_frame(
            destination_network,
            &encode_who_is(low_limit, high_limit)?,
        );
        self.discover_devices(frame, router_addr).await
    }

    /// Discover every BACnet router visible through the limited IP broadcast.
    pub async fn who_is_router(
        &self,
        destination_network: Option<u16>,
    ) -> Result<Vec<DiscoveredRouter>, ClientError> {
        let broadcast = SocketAddr::from(([255, 255, 255, 255], BACNET_IP_PORT));
        self.who_is_router_to(broadcast, destination_network).await
    }

    /// Send Who-Is-Router-To-Network to an explicit UDP destination and
    /// collect I-Am-Router-To-Network responses until the timeout elapses.
    pub async fn who_is_router_to(
        &self,
        target_addr: SocketAddr,
        destination_network: Option<u16>,
    ) -> Result<Vec<DiscoveredRouter>, ClientError> {
        let frame =
            create_who_is_router_frame(destination_network, is_broadcast_target(target_addr));
        let (sink, mut responses) = mpsc::unbounded_channel();
        self.commands
            .send(EndpointCommand::DiscoverRouters {
                frame,
                destination: target_addr,
                sink,
            })
            .await
            .map_err(|_| ClientError::EndpointClosed)?;

        let mut routers: Vec<DiscoveredRouter> = Vec::new();
        while let Some(response) = responses.recv().await {
            let response = response?;
            if let Some(existing) = routers
                .iter_mut()
                .find(|router| router.address == response.address)
            {
                for network in response.networks {
                    if !existing.networks.contains(&network) {
                        existing.networks.push(network);
                    }
                }
                existing.networks.sort_unstable();
            } else {
                routers.push(response);
            }
        }
        routers.sort_by_key(|router| router.address);
        Ok(routers)
    }

    async fn discover_devices(
        &self,
        frame: Vec<u8>,
        destination: SocketAddr,
    ) -> Result<Vec<DeviceInfo>, ClientError> {
        let (sink, mut responses) = mpsc::unbounded_channel();
        self.commands
            .send(EndpointCommand::DiscoverDevices {
                frame,
                destination,
                sink,
            })
            .await
            .map_err(|_| ClientError::EndpointClosed)?;

        let mut devices = Vec::new();
        let mut seen = HashSet::new();
        while let Some(device) = responses.recv().await {
            let device = device?;
            if seen.insert(device.device_id) {
                devices.push(device);
            }
        }
        Ok(devices)
    }

    async fn send_confirmed_request(
        &self,
        target: &BacnetTarget,
        service_choice: ConfirmedServiceChoice,
        service_data: Vec<u8>,
    ) -> Result<Vec<u8>, ClientError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(EndpointCommand::Confirmed {
                target: target.clone(),
                service_choice,
                service_data,
                response,
            })
            .await
            .map_err(|_| ClientError::EndpointClosed)?;
        receiver.await.map_err(|_| ClientError::EndpointClosed)?
    }

    /// Read a property and return every decoded value in its response.
    pub async fn read_property<T>(
        &self,
        target: T,
        object: ObjectIdentifier,
        property: PropertyIdentifier,
    ) -> Result<Vec<PropertyValue>, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
        Ok(self
            .read_property_response(&target, object, property, None)
            .await?
            .property_values)
    }

    /// Read one explicit array index with a single ReadProperty transaction.
    pub async fn read_property_at<T>(
        &self,
        target: T,
        object: ObjectIdentifier,
        property: PropertyIdentifier,
        array_index: u32,
    ) -> Result<Vec<PropertyValue>, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
        Ok(self
            .read_property_response(&target, object, property, Some(array_index))
            .await?
            .property_values)
    }

    async fn read_property_response(
        &self,
        target: &BacnetTarget,
        object: ObjectIdentifier,
        property: PropertyIdentifier,
        array_index: Option<u32>,
    ) -> Result<ReadPropertyResponse, ClientError> {
        let request = match array_index {
            Some(index) => ReadPropertyRequest::with_array_index(object, property, index),
            None => ReadPropertyRequest::new(object, property),
        };
        let mut service_data = Vec::new();
        request.encode(&mut service_data)?;
        let response_data = self
            .send_confirmed_request(target, ConfirmedServiceChoice::ReadProperty, service_data)
            .await?;
        let response = ReadPropertyResponse::decode(&response_data)?;
        if response.object_identifier != object
            || response.property_identifier != property
            || response.property_array_index != array_index
        {
            return Err(ClientError::Decode(format!(
                "ReadProperty response did not match {object:?} {property:?}[{array_index:?}]"
            )));
        }
        Ok(response)
    }

    /// Execute one ReadPropertyMultiple request.
    pub async fn read_property_multiple<T>(
        &self,
        target: T,
        request: &ReadPropertyMultipleRequest,
    ) -> Result<ReadPropertyMultipleResponse, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
        let mut service_data = Vec::new();
        request.encode(&mut service_data)?;
        let response_data = self
            .send_confirmed_request(
                &target,
                ConfirmedServiceChoice::ReadPropertyMultiple,
                service_data,
            )
            .await?;
        Ok(ReadPropertyMultipleResponse::decode(&response_data)?)
    }

    /// Write one property and await its SimpleAck.
    pub async fn write_property<T>(
        &self,
        target: T,
        object: ObjectIdentifier,
        property: PropertyIdentifier,
        value: &PropertyValue,
        priority: Option<u8>,
    ) -> Result<(), ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
        let mut encoded_value = Vec::new();
        encode_property_value(value, &mut encoded_value)?;
        let request = match priority {
            Some(priority) => WritePropertyRequest::with_priority(
                object,
                property.into(),
                encoded_value,
                priority,
            ),
            None => WritePropertyRequest::new(object, property.into(), encoded_value),
        };
        let mut service_data = Vec::new();
        request.encode(&mut service_data)?;
        self.send_confirmed_request(&target, ConfirmedServiceChoice::WriteProperty, service_data)
            .await?;
        Ok(())
    }

    /// Read the complete Device Object_List.
    pub async fn read_object_list<T>(
        &self,
        target: T,
        device_id: u32,
    ) -> Result<Vec<ObjectIdentifier>, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        self.read_property(
            target,
            ObjectIdentifier::new(ObjectType::Device, device_id),
            PropertyIdentifier::ObjectList,
        )
        .await?
        .into_iter()
        .map(decode_object_list_value)
        .collect()
    }

    /// Read every property exposed by an object with one RPM `ALL` request.
    ///
    /// The returned snapshot retains per-property BACnet errors. No fallback
    /// request is issued when RPM fails or the response is too large.
    pub async fn read_object_properties<T>(
        &self,
        target: T,
        object: ObjectIdentifier,
    ) -> Result<ObjectSnapshot, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
        let properties = self.read_all_properties_rpm(&target, object).await?;
        Ok(ObjectSnapshot {
            object_identifier: object,
            properties,
        })
    }

    async fn read_all_properties_rpm(
        &self,
        target: &BacnetTarget,
        object: ObjectIdentifier,
    ) -> Result<Vec<PropertyReadResult>, ClientError> {
        let request = ReadPropertyMultipleRequest::new(vec![ReadAccessSpecification::new(
            object,
            vec![PropertyReference::new(PropertyIdentifier::All)],
        )]);
        let response = self.read_property_multiple(target, &request).await?;
        let access = response
            .read_access_results
            .into_iter()
            .find(|access| access.object_identifier == object)
            .ok_or_else(|| ClientError::Decode(format!("RPM response omitted {object:?}")))?;
        Ok(access
            .results
            .into_iter()
            .map(property_read_result)
            .collect())
    }

    /// Subscribe to Change-of-Value notifications for one object.
    ///
    /// `device_instance` is the instance number of the device being subscribed
    /// to - not the address it is reached at. It and
    /// `monitored_object_identifier` are how arriving notifications are routed
    /// back to this subscription, because they are what a notification says
    /// about itself. Once the device's SimpleAck confirms the subscription,
    /// notifications arrive through [`CovSubscription::recv`]. A confirmed
    /// notification is acknowledged back to the device automatically; the
    /// caller only ever sees the decoded value.
    ///
    /// `subscriber_process_identifier` goes on the wire and is echoed back, but
    /// nothing here routes on it. Pick one derived from the object's identity
    /// rather than from a counter: a device keys a subscription on the
    /// subscriber's address and that number, so a client that restarts and asks
    /// again with the same one is renewing what the device already holds, while
    /// a fresh number leaves a duplicate subscription in place until its
    /// lifetime lapses. Two objects picking the same number is harmless.
    ///
    /// `lifetime` is `None` for a subscription that does not expire. The
    /// confirmation preference is not optional: ASHRAE 135 clause 13.14.1.4
    /// requires it whenever a lifetime is present, and a request with neither is
    /// the cancellation form, which is [`CovSubscription::unsubscribe`]'s job.
    pub async fn subscribe_cov<T>(
        &self,
        target: T,
        device_instance: u32,
        subscriber_process_identifier: u32,
        monitored_object_identifier: ObjectIdentifier,
        issue_confirmed_notifications: bool,
        lifetime: Option<u32>,
    ) -> Result<CovSubscription, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
        let request = SubscribeCovRequest::subscribe(
            subscriber_process_identifier,
            monitored_object_identifier,
            issue_confirmed_notifications,
            lifetime,
        );
        let mut service_data = Vec::new();
        request.encode(&mut service_data)?;

        let (sink, notifications) = mpsc::unbounded_channel();
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(EndpointCommand::SubscribeCov {
                target: target.clone(),
                key: (device_instance, monitored_object_identifier),
                service_data,
                sink,
                response,
            })
            .await
            .map_err(|_| ClientError::EndpointClosed)?;
        let ack = receiver.await.map_err(|_| ClientError::EndpointClosed)?;
        ack?;

        Ok(CovSubscription {
            subscriber_process_identifier,
            monitored_object_identifier,
            target,
            client: self.clone(),
            notifications,
        })
    }
}

/// A live Change-of-Value subscription.
///
/// Notifications arrive through [`Self::recv`] until the device's subscription
/// lifetime lapses, the connection is lost, or [`Self::unsubscribe`] cancels it
/// explicitly. Dropping this value without unsubscribing just lets the
/// subscription lapse on its own; nothing tells the device to stop early.
pub struct CovSubscription {
    subscriber_process_identifier: u32,
    monitored_object_identifier: ObjectIdentifier,
    target: BacnetTarget,
    client: AsyncBacnetClient,
    notifications: mpsc::UnboundedReceiver<CovNotification>,
}

impl CovSubscription {
    /// The object this subscription monitors.
    pub fn monitored_object_identifier(&self) -> ObjectIdentifier {
        self.monitored_object_identifier
    }

    /// Wait for the next notification.
    ///
    /// Returns `None` once the client endpoint has shut down. A renewal does
    /// not interrupt this: the channel a subscription is created with is the
    /// one it keeps for its whole life.
    pub async fn recv(&mut self) -> Option<CovNotification> {
        self.notifications.recv().await
    }

    /// Refreshes the subscription before its lifetime lapses, re-sending
    /// SubscribeCOV with the same identifiers so the device treats it as a
    /// renewal rather than a competing second subscription.
    ///
    /// Sent as a plain confirmed request rather than through
    /// [`AsyncBacnetClient::subscribe_cov`], because this subscription's
    /// channel is already registered under a key the renewal does not change.
    /// Going the other way would build a second channel and register it over
    /// the first *before* the request goes out - so a renewal that then timed
    /// out would leave this subscription alive but permanently silent, its
    /// sink evicted by an attempt that never succeeded. A refresh must not be
    /// able to cost the caller the subscription it is refreshing.
    ///
    /// `self` is unchanged either way: on success the device has simply been
    /// told to keep reporting, and on error nothing here has moved.
    pub async fn renew(
        &mut self,
        issue_confirmed_notifications: bool,
        lifetime: Option<u32>,
    ) -> Result<(), ClientError> {
        let request = SubscribeCovRequest::subscribe(
            self.subscriber_process_identifier,
            self.monitored_object_identifier,
            issue_confirmed_notifications,
            lifetime,
        );
        let mut service_data = Vec::new();
        request.encode(&mut service_data)?;
        self.client
            .send_confirmed_request(
                &self.target,
                ConfirmedServiceChoice::SubscribeCOV,
                service_data,
            )
            .await?;
        Ok(())
    }

    /// Cancel the subscription with the device.
    ///
    /// A SubscribeCOV request with neither `issue_confirmed_notifications` nor
    /// `lifetime` set is the BACnet idiom for cancellation.
    pub async fn unsubscribe(self) -> Result<(), ClientError> {
        let request = SubscribeCovRequest::new(
            self.subscriber_process_identifier,
            self.monitored_object_identifier,
        );
        let mut service_data = Vec::new();
        request.encode(&mut service_data)?;
        self.client
            .send_confirmed_request(
                &self.target,
                ConfirmedServiceChoice::SubscribeCOV,
                service_data,
            )
            .await?;
        Ok(())
    }
}

enum EndpointCommand {
    Confirmed {
        target: BacnetTarget,
        service_choice: ConfirmedServiceChoice,
        service_data: Vec<u8>,
        response: oneshot::Sender<Result<Vec<u8>, ClientError>>,
    },
    DiscoverDevices {
        frame: Vec<u8>,
        destination: SocketAddr,
        sink: mpsc::UnboundedSender<Result<DeviceInfo, ClientError>>,
    },
    DiscoverRouters {
        frame: Vec<u8>,
        destination: SocketAddr,
        sink: mpsc::UnboundedSender<Result<DiscoveredRouter, ClientError>>,
    },
    SubscribeCov {
        target: BacnetTarget,
        /// What notifications for this subscription will identify themselves
        /// as, and therefore how they are routed back here.
        key: CovKey,
        service_data: Vec<u8>,
        sink: mpsc::UnboundedSender<CovNotification>,
        response: oneshot::Sender<Result<Vec<u8>, ClientError>>,
    },
}

/// One in-progress discovery: responses are forwarded to `sink` until
/// `deadline`, when dropping the sender closes the caller's channel.
struct ActiveDiscovery<T> {
    sink: mpsc::UnboundedSender<Result<T, ClientError>>,
    deadline: Instant,
}

/// Segments this client accepts in one reassembled response, sent in every
/// request's `max_segments` so a device is told before it starts. Sixty-four
/// at a 1476-byte APDU is ~94 KB.
const MAX_SEGMENTS_ACCEPTED: MaxSegments = MaxSegments::SixtyFour;

/// The count behind [`MAX_SEGMENTS_ACCEPTED`], bounding a reassembly buffer
/// and refusing an outbound request that cannot fit.
const MAX_SEGMENTS: usize = 64;

/// The window granted to a device sending us segments.
///
/// One, so every segment is acknowledged before the next. Costs a round trip
/// per segment, but the only gap that can exist is the next one. Clause 5.4
/// leaves the actual size to the receiver, so a device proposing sixteen is
/// told one and must honour it.
const GRANTED_WINDOW: u8 = 1;

/// Proposed when this client is the sender; the peer's first SegmentAck
/// carries what it will actually accept.
const PROPOSED_WINDOW: u8 = 16;

/// A response arriving in pieces.
///
/// Held on the transaction rather than in a table of its own: reassembly is per
/// `(peer, invoke id)` and [`Endpoint::pending`] is already keyed that way.
/// Keying on invoke ID alone would let two devices segmenting under the same ID
/// overwrite each other.
struct Reassembly {
    data: Vec<u8>,
    /// The last segment accepted in order, or `None` before any. With a window
    /// of one, every decision is made against this.
    last_in_order: Option<u8>,
    /// Kept so a timeout can re-send it: a lost ack stalls the device silently,
    /// waiting on permission it will never get.
    last_ack: Arc<[u8]>,
    /// Accepted so far, to enforce [`MAX_SEGMENTS`].
    segments: usize,
}

/// A request being sent in pieces.
struct OutboundSegments {
    /// Framed up front, so a retransmission re-sends bytes rather than
    /// re-encoding them.
    frames: Vec<Arc<[u8]>>,
    /// Acknowledged up to and including this, or `None` before the peer speaks.
    acked: Option<u8>,
    /// From the peer's first SegmentAck. One until then: nothing says a second
    /// segment would be looked at.
    window: u8,
}

impl OutboundSegments {
    fn next_unsent(&self) -> u8 {
        match self.acked {
            Some(acked) => acked.wrapping_add(1),
            None => 0,
        }
    }

    /// What may be in flight now: everything after the last acknowledged
    /// segment, up to the peer's window.
    fn window_after_ack(&self) -> std::ops::Range<usize> {
        let first = usize::from(self.next_unsent());
        let last = (first + usize::from(self.window.max(1))).min(self.frames.len());
        first..last
    }

    /// Every segment acknowledged, so the peer now owes us the response.
    fn all_acked(&self) -> bool {
        self.acked
            .is_some_and(|acked| usize::from(acked) + 1 >= self.frames.len())
    }
}

/// What an arriving segment means for its transfer.
enum SegmentOutcome {
    /// Take it and ask for the next.
    Accepted(u8),
    /// Already had it, so our acknowledgement was lost. Repeat it.
    Repeat,
    /// A gap. Name the last in-order segment so the peer resumes from there.
    Missing(u8),
    /// The last segment: acknowledge it and hand over the whole response.
    Complete(u8, Vec<u8>),
    Abandon(AbortReason),
}

struct PendingTransaction {
    service_choice: ConfirmedServiceChoice,
    frame: Arc<[u8]>,
    retries_remaining: u8,
    deadline: Instant,
    response: oneshot::Sender<Result<Vec<u8>, ClientError>>,
    /// Set when a device answers with a segmented ComplexAck.
    reassembly: Option<Reassembly>,
    /// Set when the request was too large for one APDU, cleared once every
    /// segment is acknowledged.
    outbound: Option<OutboundSegments>,
}

/// What one outstanding transaction is identified by.
///
/// The peer is half the key because ASHRAE 135 clause 5.4 scopes the
/// transaction state machine to a pair of devices: an invoke ID need only be
/// unique among the requests one device has outstanding *to one other device*.
/// Keying on the number alone would make the 256 available IDs a budget for
/// the whole network rather than for each peer, so a client talking to two
/// hundred controllers would run out against all of them at once.
type TransactionKey = (SocketAddr, u8);

/// What a COV notification is routed by: the device that says it sent it, and
/// the object it says the notification is about.
///
/// Deliberately not the subscriber process identifier. That number is chosen
/// by the subscriber and echoed by the device, so routing on it means two
/// subscriptions that happen to pick the same number are indistinguishable -
/// and since the routing table is a map, the second silently displaces the
/// first, whose notifications then stop arriving with nothing to say so. The
/// identity a notification asserts about itself cannot collide that way.
type CovKey = (u32, ObjectIdentifier);

struct Endpoint {
    socket: UdpSocket,
    commands: mpsc::Receiver<EndpointCommand>,
    pending: HashMap<TransactionKey, PendingTransaction>,
    /// Invoke IDs that timed out, and the instant each may be issued again.
    ///
    /// A device that answers after we have given up sends its response with
    /// the invoke ID we gave up on. If that ID has already been reissued, the
    /// late response matches the new transaction: same peer, same service
    /// choice, same ID. It is then delivered as the answer to a question it
    /// was never asked - and for a client that reads the same objects from
    /// the same device on a cycle, the stale answer can be structurally
    /// indistinguishable from the right one.
    ///
    /// Holding the ID back for one full transaction budget after it fails
    /// means the late response arrives when nothing is listening, which is
    /// where it belongs.
    ///
    /// Held back for the peer that failed to answer and not for the rest: one
    /// slow controller has no business narrowing the ID space available to
    /// every other device on the network.
    quarantined: HashMap<TransactionKey, Instant>,
    device_discoveries: Vec<ActiveDiscovery<DeviceInfo>>,
    router_discoveries: Vec<ActiveDiscovery<DiscoveredRouter>>,
    cov_subscribers: HashMap<CovKey, mpsc::UnboundedSender<CovNotification>>,
    next_invoke_id: u8,
    timeout: Duration,
    retries: u8,
    receive_buffer: Vec<u8>,
}

impl Endpoint {
    fn new(
        socket: UdpSocket,
        commands: mpsc::Receiver<EndpointCommand>,
        timeout: Duration,
        retries: u8,
    ) -> Self {
        Self {
            socket,
            commands,
            pending: HashMap::new(),
            quarantined: HashMap::new(),
            device_discoveries: Vec::new(),
            router_discoveries: Vec::new(),
            cov_subscribers: HashMap::new(),
            next_invoke_id: 0,
            timeout,
            retries,
            receive_buffer: vec![0; MAX_BACNET_IP_FRAME],
        }
    }

    async fn run(mut self) {
        loop {
            self.remove_cancelled();
            let next_deadline = self
                .pending
                .values()
                .map(|pending| pending.deadline)
                .chain(self.device_discoveries.iter().map(|d| d.deadline))
                .chain(self.router_discoveries.iter().map(|d| d.deadline))
                .min();
            let timeout_at = next_deadline.unwrap_or_else(|| {
                Instant::now()
                    .checked_add(Duration::from_secs(86_400))
                    .unwrap_or_else(Instant::now)
            });

            tokio::select! {
                command = self.commands.recv() => match command {
                    Some(command) => self.handle_command(command).await,
                    None => break,
                },
                received = self.socket.recv_from(&mut self.receive_buffer) => {
                    match received {
                        Ok((length, source)) => self.handle_packet(length, source).await,
                        Err(error) => {
                            self.fail_all(|| ClientError::Io(std::io::Error::new(error.kind(), error.to_string())));
                            break;
                        }
                    }
                }
                _ = sleep_until(timeout_at), if next_deadline.is_some() => {
                    self.handle_timeouts().await;
                }
            }
        }
        self.fail_all(|| ClientError::EndpointClosed);
    }

    async fn handle_command(&mut self, command: EndpointCommand) {
        match command {
            EndpointCommand::Confirmed {
                target,
                service_choice,
                service_data,
                response,
            } => {
                self.handle_confirmed_command(target, service_choice, service_data, response)
                    .await;
            }
            EndpointCommand::DiscoverDevices {
                frame,
                destination,
                sink,
            } => {
                if let Some(discovery) = self.start_discovery(&frame, destination, sink).await {
                    self.device_discoveries.push(discovery);
                }
            }
            EndpointCommand::DiscoverRouters {
                frame,
                destination,
                sink,
            } => {
                if let Some(discovery) = self.start_discovery(&frame, destination, sink).await {
                    self.router_discoveries.push(discovery);
                }
            }
            EndpointCommand::SubscribeCov {
                target,
                key,
                service_data,
                sink,
                response,
            } => {
                // Registered before the request goes out, so a notification
                // that arrives right behind the SimpleAck is never missed.
                //
                // A renewal re-registers the same key and replaces the sink,
                // which is the intended effect: one subscription to an object
                // has one channel, whatever process identifier it was asked
                // for with.
                self.cov_subscribers.insert(key, sink);
                self.handle_confirmed_command(
                    target,
                    ConfirmedServiceChoice::SubscribeCOV,
                    service_data,
                    response,
                )
                .await;
            }
        }
    }

    /// Send a discovery frame and open its response window. A failed send is
    /// reported through the sink instead, and no window is opened.
    async fn start_discovery<T>(
        &mut self,
        frame: &[u8],
        destination: SocketAddr,
        sink: mpsc::UnboundedSender<Result<T, ClientError>>,
    ) -> Option<ActiveDiscovery<T>> {
        if sink.is_closed() {
            return None;
        }
        if let Err(error) = self.socket.send_to(frame, destination).await {
            let _ = sink.send(Err(ClientError::Io(error)));
            return None;
        }
        Some(ActiveDiscovery {
            sink,
            deadline: Instant::now() + self.timeout,
        })
    }

    async fn handle_confirmed_command(
        &mut self,
        target: BacnetTarget,
        service_choice: ConfirmedServiceChoice,
        service_data: Vec<u8>,
        response: oneshot::Sender<Result<Vec<u8>, ClientError>>,
    ) {
        if response.is_closed() {
            return;
        }
        // A cancelled request may have released an invoke ID while the endpoint
        // was asleep in select. Reclaim those slots before admitting new work.
        self.remove_cancelled();
        let Some(invoke_id) = self.reserve_invoke_id(target.address) else {
            let _ = response.send(Err(ClientError::TooManyTransactions));
            return;
        };
        // Only the first segment goes out: until the peer names its window,
        // nothing says a second would be looked at.
        let (frame, outbound) =
            match split_request(&target, invoke_id, service_choice, service_data) {
                Ok(RequestFrames::Whole(frame)) => (Arc::<[u8]>::from(frame), None),
                Ok(RequestFrames::Segmented(frames)) => {
                    let first = Arc::clone(&frames[0]);
                    (
                        first,
                        Some(OutboundSegments {
                            frames,
                            acked: None,
                            window: 1,
                        }),
                    )
                }
                Err(error) => {
                    let _ = response.send(Err(error));
                    return;
                }
            };
        self.pending.insert(
            (target.address, invoke_id),
            PendingTransaction {
                service_choice,
                frame: Arc::clone(&frame),
                retries_remaining: self.retries,
                deadline: Instant::now() + self.timeout,
                response,
                reassembly: None,
                outbound,
            },
        );
        if let Err(error) = self.socket.send_to(&frame, target.address).await {
            if let Some(pending) = self.pending.remove(&(target.address, invoke_id)) {
                let _ = pending.response.send(Err(ClientError::Io(error)));
            }
        }
    }

    /// Reserve an invoke ID for a request to `peer`.
    ///
    /// Occupancy is checked per peer, so the 256 IDs are a budget for each
    /// device rather than for the whole client. `next_invoke_id` stays a
    /// single rotating cursor across every peer: it only decides where the
    /// search starts, and keeping one avoids a per-peer cursor that would have
    /// to be reaped along with the peer.
    fn reserve_invoke_id(&mut self, peer: SocketAddr) -> Option<u8> {
        let now = Instant::now();
        self.quarantined.retain(|_, until| *until > now);
        for _ in 0..=u8::MAX {
            let invoke_id = self.next_invoke_id;
            self.next_invoke_id = self.next_invoke_id.wrapping_add(1);
            let key = (peer, invoke_id);
            if !self.pending.contains_key(&key) && !self.quarantined.contains_key(&key) {
                return Some(invoke_id);
            }
        }
        None
    }

    /// How long one transaction may take before it is abandoned: the initial
    /// attempt plus every retransmission, each with its own timeout.
    ///
    /// Also how long a failed invoke ID stays quarantined. A device that has
    /// not answered within its whole budget is unlikely to answer after
    /// another one, and holding the ID longer would shrink the pool for no
    /// further protection.
    fn transaction_budget(&self) -> Duration {
        self.timeout
            .saturating_mul(u32::from(self.retries).saturating_add(1))
    }

    async fn handle_packet(&mut self, length: usize, source: SocketAddr) {
        // The network-layer source travels with the APDU because a SegmentAck
        // has to be addressed back the way the segment came - a peer behind a
        // router is not reachable by its address alone.
        let (apdu, route) = {
            let data = &self.receive_buffer[..length];
            let Some(frame) = decode_bacnet_ip_frame(data, source) else {
                return;
            };

            if frame.npdu.is_network_message() {
                if !self.router_discoveries.is_empty() {
                    if let Some(router) = parse_i_am_router_response(data, source) {
                        for discovery in &self.router_discoveries {
                            let _ = discovery.sink.send(Ok(router.clone()));
                        }
                    }
                }
                return;
            }

            // Unconfirmed-Request PDU: I-Am matters for device discovery, an
            // UnconfirmedCOVNotification for any live subscription.
            if frame.payload.first() == Some(&0x10) {
                if !self.device_discoveries.is_empty() {
                    if let Some(device) = parse_iam_response(data, source) {
                        for discovery in &self.device_discoveries {
                            let _ = discovery.sink.send(Ok(device.clone()));
                        }
                    }
                }
                if !self.cov_subscribers.is_empty() {
                    if let Ok(Apdu::UnconfirmedRequest {
                        service_choice: UnconfirmedServiceChoice::UnconfirmedCOVNotification,
                        service_data,
                    }) = Apdu::decode(frame.payload)
                    {
                        if let Ok(notification) = CovNotification::decode(&service_data) {
                            self.dispatch_cov_notification(notification);
                        }
                    }
                }
                return;
            }

            let Ok(apdu) = Apdu::decode(frame.payload) else {
                return;
            };

            // A ConfirmedCOVNotification is a confirmed *request* aimed at us,
            // not a response to one of ours - it needs its own ack, sent back
            // to wherever the notification actually came from.
            if let Apdu::ConfirmedRequest {
                invoke_id,
                segmented,
                service_choice: ConfirmedServiceChoice::ConfirmedCovNotification,
                ref service_data,
                ..
            } = apdu
            {
                self.handle_confirmed_cov_notification(
                    invoke_id,
                    segmented,
                    service_data,
                    source,
                    frame.npdu.source.clone(),
                );
                return;
            }

            (apdu, frame.npdu.source.clone())
        };
        let invoke_id = match &apdu {
            Apdu::ComplexAck { invoke_id, .. }
            | Apdu::SimpleAck { invoke_id, .. }
            | Apdu::Error { invoke_id, .. }
            | Apdu::Reject { invoke_id, .. }
            | Apdu::Abort { invoke_id, .. }
            | Apdu::SegmentAck { invoke_id, .. } => *invoke_id,
            _ => return,
        };
        // Keyed on where the response came from as well as the ID it carries,
        // so a reply from one device is never considered against a
        // transaction outstanding with another - which is what makes it safe
        // for the same invoke ID to be live with several peers at once.
        let key = (source, invoke_id);
        let Some(pending) = self.pending.get(&key) else {
            // Worth a line rather than a silent drop: a response on a
            // quarantined ID is this device answering after we gave up on it,
            // which is the thing you want to know when a site looks slow.
            if self.quarantined.contains_key(&key) {
                log::debug!("late response from {source} on invoke id {invoke_id}, discarded");
            }
            return;
        };
        let expecting = pending.service_choice;

        // A SegmentAck paces a request *this client* is sending. It answers
        // nothing and carries no service choice to check, so it is taken
        // before the checks below rather than being mistaken for a response.
        if let Apdu::SegmentAck {
            negative,
            sequence_number,
            window_size,
            ..
        } = &apdu
        {
            let (negative, sequence_number, window_size) =
                (*negative, *sequence_number, *window_size);
            self.advance_outbound(key, negative, sequence_number, window_size)
                .await;
            return;
        }

        if !response_matches_service(&apdu, expecting) {
            return;
        }

        // A segmented ComplexAck is not the response yet - it is one piece of
        // it, and the transaction stays open until the last piece lands.
        if matches!(
            apdu,
            Apdu::ComplexAck {
                segmented: true,
                ..
            }
        ) {
            if let Apdu::ComplexAck {
                more_follows,
                sequence_number,
                service_data,
                ..
            } = apdu
            {
                self.accept_response_segment(
                    key,
                    sequence_number,
                    more_follows,
                    service_data,
                    route,
                )
                .await;
            }
            return;
        }

        let result = response_result(apdu);
        if let Some(pending) = self.pending.remove(&key) {
            let _ = pending.response.send(result);
        }
    }

    /// Take one segment, acknowledge it, and complete the transaction once the
    /// last has landed.
    ///
    /// Clause 5.4.5. With a granted window of one the rules collapse to three
    /// cases: the segment awaited, the one just taken (our ack was lost), or a
    /// gap.
    async fn accept_response_segment(
        &mut self,
        key: TransactionKey,
        sequence_number: Option<u8>,
        more_follows: bool,
        service_data: Vec<u8>,
        route: Option<NetworkAddress>,
    ) {
        let (peer, invoke_id) = key;
        // Malformed: the sequence number is what every decision below needs.
        let Some(sequence) = sequence_number else {
            self.abandon(key, AbortReason::InvalidApduInThisState, route)
                .await;
            return;
        };

        let (outcome, previous_ack) = {
            let Some(pending) = self.pending.get_mut(&key) else {
                return;
            };
            let reassembly = pending.reassembly.get_or_insert_with(|| Reassembly {
                data: Vec::new(),
                last_in_order: None,
                last_ack: Arc::from(Vec::new()),
                segments: 0,
            });
            let previous_ack = Arc::clone(&reassembly.last_ack);
            let outcome = match reassembly.last_in_order {
                // Guessing where a transfer started would be worse than saying
                // we cannot follow it.
                None if sequence != 0 => {
                    SegmentOutcome::Abandon(AbortReason::InvalidApduInThisState)
                }
                Some(last) if sequence == last => SegmentOutcome::Repeat,
                Some(last) if sequence != last.wrapping_add(1) => SegmentOutcome::Missing(last),
                _ if reassembly.segments >= MAX_SEGMENTS => {
                    SegmentOutcome::Abandon(AbortReason::BufferOverflow)
                }
                _ => {
                    reassembly.data.extend_from_slice(&service_data);
                    reassembly.segments += 1;
                    reassembly.last_in_order = Some(sequence);
                    if more_follows {
                        SegmentOutcome::Accepted(sequence)
                    } else {
                        SegmentOutcome::Complete(sequence, std::mem::take(&mut reassembly.data))
                    }
                }
            };
            (outcome, previous_ack)
        };

        match outcome {
            SegmentOutcome::Accepted(sequence) | SegmentOutcome::Missing(sequence) => {
                let negative = matches!(outcome, SegmentOutcome::Missing(_));
                let frame: Arc<[u8]> =
                    segment_ack_frame(invoke_id, sequence, negative, route).into();
                if let Some(pending) = self.pending.get_mut(&key) {
                    if let Some(reassembly) = &mut pending.reassembly {
                        reassembly.last_ack = Arc::clone(&frame);
                    }
                    // Each segment is progress, so the clock restarts: a long
                    // transfer is bounded by MAX_SEGMENTS, not by the deadline.
                    pending.retries_remaining = self.retries;
                    pending.deadline = Instant::now() + self.timeout;
                }
                self.send_or_fail(key, &frame).await;
            }
            SegmentOutcome::Repeat => {
                if !previous_ack.is_empty() {
                    self.send_or_fail(key, &previous_ack).await;
                }
            }
            SegmentOutcome::Complete(sequence, data) => {
                // Acknowledged before the caller is answered, or the peer holds
                // the transaction open until its own timer expires.
                let frame = segment_ack_frame(invoke_id, sequence, false, route);
                let _ = self.socket.send_to(&frame, peer).await;
                if let Some(pending) = self.pending.remove(&key) {
                    let _ = pending.response.send(Ok(data));
                }
            }
            SegmentOutcome::Abandon(reason) => self.abandon(key, reason, route).await,
        }
    }

    /// Send the next window of a request going out in segments.
    ///
    /// Clause 5.4.4. A negative acknowledgement calls for the same action as a
    /// positive one - both say how far the peer got, and the answer either way
    /// is to continue from there.
    async fn advance_outbound(
        &mut self,
        key: TransactionKey,
        _negative: bool,
        sequence_number: u8,
        window_size: u8,
    ) {
        let frames = {
            let Some(pending) = self.pending.get_mut(&key) else {
                return;
            };
            // Not about anything this client is doing.
            let Some(outbound) = pending.outbound.as_mut() else {
                return;
            };
            if usize::from(sequence_number) >= outbound.frames.len() {
                return;
            }
            outbound.acked = Some(sequence_number);
            // Never zero, or the transfer stalls with nothing to prompt it.
            outbound.window = window_size.max(1);
            let all_acked = outbound.all_acked();
            let frames: Vec<Arc<[u8]>> = if all_acked {
                Vec::new()
            } else {
                outbound
                    .window_after_ack()
                    .map(|index| Arc::clone(&outbound.frames[index]))
                    .collect()
            };
            if all_acked {
                // The response now arrives on the ordinary path.
                pending.outbound = None;
                pending.frame = Arc::from(Vec::new());
            } else if let Some(first) = frames.first() {
                pending.frame = Arc::clone(first);
            }
            pending.retries_remaining = self.retries;
            pending.deadline = Instant::now() + self.timeout;
            frames
        };
        for frame in frames {
            if !self.send_or_fail(key, &frame).await {
                return;
            }
        }
    }

    /// Send one frame, failing the transaction if the socket refuses it.
    async fn send_or_fail(&mut self, key: TransactionKey, frame: &[u8]) -> bool {
        let (peer, _) = key;
        match self.socket.send_to(frame, peer).await {
            Ok(_) => true,
            Err(error) => {
                if let Some(pending) = self.pending.remove(&key) {
                    let _ = pending.response.send(Err(ClientError::Io(error)));
                }
                false
            }
        }
    }

    /// Stop a transfer, telling the peer and the caller why.
    async fn abandon(
        &mut self,
        key: TransactionKey,
        reason: AbortReason,
        route: Option<NetworkAddress>,
    ) {
        let (peer, invoke_id) = key;
        let frame = abort_frame(invoke_id, reason, route);
        let _ = self.socket.send_to(&frame, peer).await;
        if let Some(pending) = self.pending.remove(&key) {
            let _ = pending.response.send(Err(ClientError::Abort(reason)));
        }
    }

    async fn handle_timeouts(&mut self) {
        let now = Instant::now();
        // An expired discovery window simply closes its sink, which ends the
        // caller's collection loop.
        self.device_discoveries.retain(|d| d.deadline > now);
        self.router_discoveries.retain(|d| d.deadline > now);
        let expired = self
            .pending
            .iter()
            .filter_map(|(key, pending)| (pending.deadline <= now).then_some(*key))
            .collect::<Vec<_>>();
        for key in expired {
            let Some(pending) = self.pending.get_mut(&key) else {
                continue;
            };
            if pending.response.is_closed() {
                self.pending.remove(&key);
                continue;
            }
            if pending.retries_remaining == 0 {
                if let Some(pending) = self.pending.remove(&key) {
                    let _ = pending.response.send(Err(ClientError::Timeout));
                    self.quarantined
                        .insert(key, Instant::now() + self.transaction_budget());
                }
                continue;
            }
            pending.retries_remaining -= 1;
            pending.deadline = Instant::now() + self.timeout;
            // What a retransmission means depends on where the transaction
            // is: mid-reassembly the peer awaits an ack, and re-sending the
            // request would restart the transfer; mid-send it is the
            // unacknowledged window that needs repeating.
            let frames: Vec<Arc<[u8]>> = if let Some(reassembly) = &pending.reassembly {
                vec![Arc::clone(&reassembly.last_ack)]
            } else if let Some(outbound) = &pending.outbound {
                outbound
                    .window_after_ack()
                    .map(|index| Arc::clone(&outbound.frames[index]))
                    .collect()
            } else {
                vec![Arc::clone(&pending.frame)]
            };
            for frame in frames {
                if frame.is_empty() {
                    continue;
                }
                if !self.send_or_fail(key, &frame).await {
                    break;
                }
            }
        }
    }

    /// Route a decoded notification to the subscription for the object it says
    /// it is about.
    ///
    /// Routed on what the notification asserts - its initiating device and its
    /// monitored object - rather than on the process identifier it echoes.
    /// Those two are the subscription's identity; the process identifier is
    /// only a number the subscriber picked, and two subscriptions are free to
    /// pick the same one.
    ///
    /// A notification matching no live subscription is dropped. That covers
    /// both a subscription this client established before a restart and has
    /// not re-established, and a device reporting an object nobody here asked
    /// about - neither of which there is any honest way to deliver.
    fn dispatch_cov_notification(&mut self, notification: CovNotification) {
        let key = (
            notification.initiating_device.instance,
            notification.monitored_object,
        );
        if let Some(sink) = self.cov_subscribers.get(&key) {
            let _ = sink.send(notification);
            return;
        }
        log::debug!(
            "COV notification from device {} about {:?}, which nothing subscribed; discarded",
            notification.initiating_device.instance,
            notification.monitored_object
        );
    }

    /// Decode, dispatch, and acknowledge an inbound ConfirmedCOVNotification.
    ///
    /// The BACnet confirmed-service contract requires a reply regardless of
    /// whether a local subscription still matches the notification's
    /// subscriber_process_identifier - the device only needs to know its
    /// notification was received, not what became of it here.
    ///
    /// A segmented notification is aborted rather than decoded: reassembly
    /// isn't implemented, and attempting to decode one segment's worth of
    /// bytes as a complete notification would misread it as malformed data
    /// instead of failing honestly.
    fn handle_confirmed_cov_notification(
        &mut self,
        invoke_id: u8,
        segmented: bool,
        service_data: &[u8],
        source: SocketAddr,
        npdu_source: Option<NetworkAddress>,
    ) {
        let ack = if segmented {
            Apdu::Abort {
                server: true,
                invoke_id,
                abort_reason: AbortReason::SegmentationNotSupported,
            }
        } else {
            match CovNotification::decode(service_data) {
                Ok(notification) => {
                    self.dispatch_cov_notification(notification);
                    Apdu::SimpleAck {
                        invoke_id,
                        service_choice: ConfirmedServiceChoice::ConfirmedCovNotification as u8,
                    }
                }
                Err(_) => Apdu::Reject {
                    invoke_id,
                    reject_reason: RejectReason::InvalidTag,
                },
            }
        };
        let frame = build_response_frame(&ack, npdu_source);
        // Best-effort: handle_packet is synchronous, so this can't await the
        // socket being writable. A dropped ack just means the device may
        // retry the notification, which the caller sees as one more delivery.
        let _ = self.socket.try_send_to(&frame, source);
    }

    fn remove_cancelled(&mut self) {
        self.pending
            .retain(|_, pending| !pending.response.is_closed());
        self.device_discoveries
            .retain(|discovery| !discovery.sink.is_closed());
        self.router_discoveries
            .retain(|discovery| !discovery.sink.is_closed());
        self.cov_subscribers.retain(|_, sink| !sink.is_closed());
    }

    fn fail_all<F>(&mut self, mut error: F)
    where
        F: FnMut() -> ClientError,
    {
        for (_, pending) in self.pending.drain() {
            let _ = pending.response.send(Err(error()));
        }
        for discovery in self.device_discoveries.drain(..) {
            let _ = discovery.sink.send(Err(error()));
        }
        for discovery in self.router_discoveries.drain(..) {
            let _ = discovery.sink.send(Err(error()));
        }
    }
}

fn encode_who_is(low_limit: Option<u32>, high_limit: Option<u32>) -> Result<Vec<u8>, ClientError> {
    let whois = match (low_limit, high_limit) {
        (Some(low), Some(high)) => WhoIsRequest::for_range(low, high),
        _ => WhoIsRequest::new(),
    };
    let mut buffer = Vec::new();
    whois.encode(&mut buffer)?;
    Ok(buffer)
}

/// The largest APDU this client accepts.
///
/// Clause 20.1.2.5 makes `max-APDU-length-accepted` the *requester's* own
/// limit, so it is ours to state, not the peer's. It was derived from the
/// peer's figure to keep answers small enough to arrive whole; with
/// reassembly that trade inverts - a larger APDU means fewer segments.
const OUR_MAX_APDU: MaxApduSize = MaxApduSize::Up1476;

/// PDU type, segments/size, invoke ID, sequence, window, service choice.
const SEGMENTED_REQUEST_HEADER: usize = 6;

/// What a peer's advertised capabilities mean for a request aimed at it.
struct PeerLimits {
    /// The ceiling on one segment of a request to it.
    max_apdu: usize,
    sends_segments: bool,
    accepts_segments: bool,
}

/// Read a peer's limits, assuming the most capable peer when it has said
/// nothing - a too-large request then earns an Abort the caller can act on,
/// where assuming the smallest APDU would cap every uncached device.
fn peer_limits(target: &BacnetTarget) -> PeerLimits {
    match &target.capabilities {
        Some(caps) => PeerLimits {
            max_apdu: MaxApduSize::at_most(caps.max_apdu).size(),
            sends_segments: matches!(
                caps.segmentation,
                Segmentation::Both | Segmentation::Transmit
            ),
            accepts_segments: matches!(
                caps.segmentation,
                Segmentation::Both | Segmentation::Receive
            ),
        },
        None => PeerLimits {
            max_apdu: MaxApduSize::Up1476.size(),
            sends_segments: true,
            accepts_segments: true,
        },
    }
}

fn build_confirmed_frame(
    target: &BacnetTarget,
    invoke_id: u8,
    service_choice: ConfirmedServiceChoice,
    service_data: Vec<u8>,
) -> Vec<u8> {
    let limits = peer_limits(target);
    let apdu = Apdu::ConfirmedRequest {
        segmented: false,
        more_follows: false,
        segmented_response_accepted: limits.sends_segments,
        max_segments: MAX_SEGMENTS_ACCEPTED,
        max_response_size: OUR_MAX_APDU,
        invoke_id,
        sequence_number: None,
        proposed_window_size: None,
        service_choice,
        service_data,
    };
    wrap_request(target, &apdu)
}

/// One segment of a request too large to send whole.
fn build_request_segment_frame(
    target: &BacnetTarget,
    invoke_id: u8,
    service_choice: ConfirmedServiceChoice,
    sequence_number: u8,
    more_follows: bool,
    chunk: &[u8],
) -> Vec<u8> {
    let limits = peer_limits(target);
    let apdu = Apdu::ConfirmedRequest {
        segmented: true,
        more_follows,
        segmented_response_accepted: limits.sends_segments,
        max_segments: MAX_SEGMENTS_ACCEPTED,
        max_response_size: OUR_MAX_APDU,
        invoke_id,
        sequence_number: Some(sequence_number),
        proposed_window_size: Some(PROPOSED_WINDOW),
        service_choice,
        service_data: chunk.to_vec(),
    };
    wrap_request(target, &apdu)
}

/// How a request will go out.
enum RequestFrames {
    /// Fits one APDU - the common case.
    Whole(Vec<u8>),
    /// Every segment, in order.
    Segmented(Vec<Arc<[u8]>>),
}

/// Decide whether a request needs segmenting, and build its frames.
///
/// Returns an Abort because that is what the exchange would produce anyway,
/// without spending a round trip to learn it.
fn split_request(
    target: &BacnetTarget,
    invoke_id: u8,
    service_choice: ConfirmedServiceChoice,
    service_data: Vec<u8>,
) -> Result<RequestFrames, ClientError> {
    let limits = peer_limits(target);
    // Sized on the segmented header, two bytes longer, to keep a request that
    // only just fits off the boundary.
    if service_data.len() + SEGMENTED_REQUEST_HEADER <= limits.max_apdu {
        return Ok(RequestFrames::Whole(build_confirmed_frame(
            target,
            invoke_id,
            service_choice,
            service_data,
        )));
    }
    if !limits.accepts_segments {
        return Err(ClientError::Abort(AbortReason::SegmentationNotSupported));
    }
    let payload = limits
        .max_apdu
        .saturating_sub(SEGMENTED_REQUEST_HEADER)
        .max(1);
    let chunks: Vec<&[u8]> = service_data.chunks(payload).collect();
    if chunks.len() > MAX_SEGMENTS {
        return Err(ClientError::Abort(AbortReason::ApduTooLong));
    }
    let last = chunks.len() - 1;
    let frames = chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            build_request_segment_frame(
                target,
                invoke_id,
                service_choice,
                index as u8,
                index != last,
                chunk,
            )
            .into()
        })
        .collect();
    Ok(RequestFrames::Segmented(frames))
}

/// Wrap a request APDU, routed if the target is behind a router.
fn wrap_request(target: &BacnetTarget, apdu: &Apdu) -> Vec<u8> {
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;
    if let Some(route) = &target.route {
        npdu.set_destination(route.clone());
        npdu.hop_count = Some(255);
    }
    wrap_unicast(&npdu, apdu)
}

/// Acknowledge a segment, or ask for one again.
///
/// `server: false` - this client made the request, so it is the client half.
fn segment_ack_frame(
    invoke_id: u8,
    sequence_number: u8,
    negative: bool,
    route: Option<NetworkAddress>,
) -> Vec<u8> {
    build_response_frame(
        &Apdu::SegmentAck {
            negative,
            server: false,
            invoke_id,
            sequence_number,
            window_size: GRANTED_WINDOW,
        },
        route,
    )
}

/// Tell a peer to stop a transfer this client will not finish.
fn abort_frame(invoke_id: u8, abort_reason: AbortReason, route: Option<NetworkAddress>) -> Vec<u8> {
    build_response_frame(
        &Apdu::Abort {
            server: false,
            invoke_id,
            abort_reason,
        },
        route,
    )
}

/// Build a reply APDU (SimpleAck/Reject/...) addressed back at `route`, the
/// network-layer source echoed from the request that prompted it - absent for
/// a peer on the same IP subnet, since only a routed request carries one.
fn build_response_frame(apdu: &Apdu, route: Option<NetworkAddress>) -> Vec<u8> {
    let mut npdu = Npdu::new();
    if let Some(route) = route {
        npdu.set_destination(route);
        npdu.hop_count = Some(255);
    }
    wrap_unicast(&npdu, apdu)
}

/// Wrap an NPDU + APDU pair in a unicast BACnet/IP (BVLC) header.
fn wrap_unicast(npdu: &Npdu, apdu: &Apdu) -> Vec<u8> {
    let mut payload = npdu.encode();
    payload.extend_from_slice(&apdu.encode());
    let total_length = payload.len() + 4;
    let mut frame = Vec::with_capacity(total_length);
    frame.extend_from_slice(&[
        0x81,
        BVLC_ORIGINAL_UNICAST,
        (total_length >> 8) as u8,
        total_length as u8,
    ]);
    frame.extend_from_slice(&payload);
    frame
}

fn response_matches_service(apdu: &Apdu, expected: ConfirmedServiceChoice) -> bool {
    match apdu {
        Apdu::ComplexAck { service_choice, .. } | Apdu::Error { service_choice, .. } => {
            *service_choice == expected
        }
        Apdu::SimpleAck { service_choice, .. } => *service_choice == expected as u8,
        Apdu::Reject { .. } | Apdu::Abort { .. } => true,
        _ => false,
    }
}

fn response_result(apdu: Apdu) -> Result<Vec<u8>, ClientError> {
    match apdu {
        Apdu::ComplexAck { service_data, .. } => Ok(service_data),
        Apdu::SimpleAck { .. } => Ok(Vec::new()),
        Apdu::Error {
            error_class,
            error_code,
            ..
        } => Err(ClientError::PropertyError {
            class: error_class.into(),
            code: error_code.into(),
        }),
        Apdu::Reject { reject_reason, .. } => Err(ClientError::Rejected(reject_reason)),
        Apdu::Abort { abort_reason, .. } => {
            Err(ClientError::Abort(AbortReason::from(abort_reason)))
        }
        _ => Err(ClientError::NoResponse),
    }
}
