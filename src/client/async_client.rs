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
    collections::{HashMap, HashSet, VecDeque},
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
        cov_notification::CovNotification, AbortReason, ConfirmedServiceChoice,
        PropertyReference, ReadAccessSpecification, ReadPropertyMultipleRequest,
        ReadPropertyMultipleResponse, ReadPropertyRequest, ReadPropertyResponse, RejectReason,
        SubscribeCovRequest, UnconfirmedServiceChoice, WhoIsRequest, WritePropertyRequest,
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
    /// `subscriber_process_identifier` is echoed back on every notification, so
    /// the endpoint can route it to this subscription rather than another one
    /// live on the same client. Once the device's SimpleAck confirms the
    /// subscription, notifications arrive through [`CovSubscription::recv`]. A
    /// confirmed notification is acknowledged back to the device automatically;
    /// the caller only ever sees the decoded value.
    pub async fn subscribe_cov<T>(
        &self,
        target: T,
        subscriber_process_identifier: u32,
        monitored_object_identifier: ObjectIdentifier,
        issue_confirmed_notifications: Option<bool>,
        lifetime: Option<u32>,
    ) -> Result<CovSubscription, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
        let request = SubscribeCovRequest {
            subscriber_process_identifier,
            monitored_object_identifier,
            issue_confirmed_notifications,
            lifetime,
        };
        let mut service_data = Vec::new();
        request.encode(&mut service_data)?;

        let (sink, notifications) = mpsc::unbounded_channel();
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(EndpointCommand::SubscribeCov {
                target: target.clone(),
                subscriber_process_identifier,
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
            carryover: VecDeque::new(),
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
    carryover: VecDeque<CovNotification>,
}

impl CovSubscription {
    /// The object this subscription monitors.
    pub fn monitored_object_identifier(&self) -> ObjectIdentifier {
        self.monitored_object_identifier
    }

    /// Wait for the next notification.
    ///
    /// Returns `None` once the client endpoint has shut down.
    pub async fn recv(&mut self) -> Option<CovNotification> {
        if let Some(notification) = self.carryover.pop_front() {
            return Some(notification);
        }
        self.notifications.recv().await
    }

    /// Refreshes the subscription before its lifetime lapses, re-sending
    /// SubscribeCOV with the same identifiers so the device treats it as a
    /// renewal rather than a competing second subscription. Anything that
    /// arrived on the old channel during the round trip is preserved and
    /// served before newer notifications. On error, `self` is unchanged.
    pub async fn renew(
        &mut self,
        issue_confirmed_notifications: Option<bool>,
        lifetime: Option<u32>,
    ) -> Result<(), ClientError> {
        let renewed = self
            .client
            .subscribe_cov(
                self.target.clone(),
                self.subscriber_process_identifier,
                self.monitored_object_identifier,
                issue_confirmed_notifications,
                lifetime,
            )
            .await?;
        while let Ok(notification) = self.notifications.try_recv() {
            self.carryover.push_back(notification);
        }
        self.notifications = renewed.notifications;
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
        subscriber_process_identifier: u32,
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

struct PendingTransaction {
    peer: SocketAddr,
    service_choice: ConfirmedServiceChoice,
    frame: Arc<[u8]>,
    retries_remaining: u8,
    deadline: Instant,
    response: oneshot::Sender<Result<Vec<u8>, ClientError>>,
}

struct Endpoint {
    socket: UdpSocket,
    commands: mpsc::Receiver<EndpointCommand>,
    pending: HashMap<u8, PendingTransaction>,
    device_discoveries: Vec<ActiveDiscovery<DeviceInfo>>,
    router_discoveries: Vec<ActiveDiscovery<DiscoveredRouter>>,
    cov_subscribers: HashMap<u32, mpsc::UnboundedSender<CovNotification>>,
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
                        Ok((length, source)) => self.handle_packet(length, source),
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
                subscriber_process_identifier,
                service_data,
                sink,
                response,
            } => {
                // Registered before the request goes out, so a notification
                // that arrives right behind the SimpleAck is never missed.
                self.cov_subscribers.insert(subscriber_process_identifier, sink);
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
        let Some(invoke_id) = self.reserve_invoke_id() else {
            let _ = response.send(Err(ClientError::TooManyTransactions));
            return;
        };
        let frame: Arc<[u8]> =
            build_confirmed_frame(&target, invoke_id, service_choice, service_data).into();
        self.pending.insert(
            invoke_id,
            PendingTransaction {
                peer: target.address,
                service_choice,
                frame: Arc::clone(&frame),
                retries_remaining: self.retries,
                deadline: Instant::now() + self.timeout,
                response,
            },
        );
        if let Err(error) = self.socket.send_to(&frame, target.address).await {
            if let Some(pending) = self.pending.remove(&invoke_id) {
                let _ = pending.response.send(Err(ClientError::Io(error)));
            }
        }
    }

    fn reserve_invoke_id(&mut self) -> Option<u8> {
        for _ in 0..=u8::MAX {
            let invoke_id = self.next_invoke_id;
            self.next_invoke_id = self.next_invoke_id.wrapping_add(1);
            if !self.pending.contains_key(&invoke_id) {
                return Some(invoke_id);
            }
        }
        None
    }

    fn handle_packet(&mut self, length: usize, source: SocketAddr) {
        let apdu = {
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

            apdu
        };
        let invoke_id = match &apdu {
            Apdu::ComplexAck { invoke_id, .. }
            | Apdu::SimpleAck { invoke_id, .. }
            | Apdu::Error { invoke_id, .. }
            | Apdu::Reject { invoke_id, .. }
            | Apdu::Abort { invoke_id, .. } => *invoke_id,
            _ => return,
        };
        let Some(pending) = self.pending.get(&invoke_id) else {
            return;
        };
        if pending.peer != source || !response_matches_service(&apdu, pending.service_choice) {
            return;
        }
        let result = response_result(apdu);
        if let Some(pending) = self.pending.remove(&invoke_id) {
            let _ = pending.response.send(result);
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
            .filter_map(|(invoke_id, pending)| (pending.deadline <= now).then_some(*invoke_id))
            .collect::<Vec<_>>();
        for invoke_id in expired {
            let Some(pending) = self.pending.get_mut(&invoke_id) else {
                continue;
            };
            if pending.response.is_closed() {
                self.pending.remove(&invoke_id);
                continue;
            }
            if pending.retries_remaining == 0 {
                if let Some(pending) = self.pending.remove(&invoke_id) {
                    let _ = pending.response.send(Err(ClientError::Timeout));
                }
                continue;
            }
            pending.retries_remaining -= 1;
            pending.deadline = Instant::now() + self.timeout;
            let frame = Arc::clone(&pending.frame);
            let peer = pending.peer;
            if let Err(error) = self.socket.send_to(&frame, peer).await {
                if let Some(pending) = self.pending.remove(&invoke_id) {
                    let _ = pending.response.send(Err(ClientError::Io(error)));
                }
            }
        }
    }

    /// Route a decoded notification to whichever subscription asked for it.
    ///
    /// A subscriber_process_identifier with no matching (or already-dropped)
    /// subscription is silently ignored - the notification simply isn't ours
    /// to deliver anywhere.
    fn dispatch_cov_notification(&mut self, notification: CovNotification) {
        if let Some(sink) = self
            .cov_subscribers
            .get(&notification.subscriber_process_identifier)
        {
            let _ = sink.send(notification);
        }
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

fn build_confirmed_frame(
    target: &BacnetTarget,
    invoke_id: u8,
    service_choice: ConfirmedServiceChoice,
    service_data: Vec<u8>,
) -> Vec<u8> {
    let (max_response_size, segmented_response_accepted) = match &target.capabilities {
        Some(caps) => (
            MaxApduSize::at_most(caps.max_apdu),
            matches!(caps.segmentation, Segmentation::Both | Segmentation::Transmit),
        ),
        None => (MaxApduSize::Up1476, true),
    };
    let apdu = Apdu::ConfirmedRequest {
        segmented: false,
        more_follows: false,
        segmented_response_accepted,
        max_segments: MaxSegments::Unspecified,
        max_response_size,
        invoke_id,
        sequence_number: None,
        proposed_window_size: None,
        service_choice,
        service_data,
    };
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;
    if let Some(route) = &target.route {
        npdu.set_destination(route.clone());
        npdu.hop_count = Some(255);
    }
    wrap_unicast(&npdu, &apdu)
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
            class: error_class,
            code: error_code,
        }),
        Apdu::Reject { reject_reason, .. } => Err(ClientError::Rejected(reject_reason)),
        Apdu::Abort { abort_reason, .. } => {
            Err(ClientError::Abort(AbortReason::from(abort_reason)))
        }
        _ => Err(ClientError::NoResponse),
    }
}
