//! Many hosted devices behind one BACnet/IP port.
//!
//! [`VirtualRouter`] answers as a BACnet router whose far side is one or more
//! networks that exist only in this process. Each hosted device sits on one of
//! them at a MAC address, and is reached the way any device behind a router is:
//! by DNET/DADR in the request's NPDU. That is what an MS/TP trunk behind a
//! B/IP router looks like to a client, so a site of a thousand devices needs one
//! socket and one port rather than a thousand addresses.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    sync::{Arc, PoisonError, RwLock},
};

use crate::{
    app::Apdu,
    datalink::bip::{BvlcFunction, BvlcHeader},
    network::{NetworkAddress, NetworkLayerMessage, NetworkMessageType, Npdu},
};

use super::{
    bip::{
        answer, decode_bacnet_ip_frame, encode_response, wrap_bvlc_parts, RequestObserver,
        ServedRequest,
    },
    DatagramSocket, Notifier, ServerDispatcher, ServerError,
};

const MAX_BACNET_IP_FRAME: usize = 65_535;
const GLOBAL_BROADCAST: u16 = 0xFFFF;
/// Reject-Message-To-Network reason 1: not directly connected to DNET, and no
/// router to it is known.
const REJECT_UNKNOWN_NETWORK: u8 = 1;

/// The devices behind a [`VirtualRouter`], and the networks they sit on.
///
/// A cheap handle onto shared state: clone it into whatever manages the site,
/// and devices inserted or removed there are served or dropped by the router on
/// its next datagram.
#[derive(Clone, Default)]
pub struct RouterDevices {
    routes: Arc<RwLock<Routes>>,
}

#[derive(Default)]
struct Routes {
    /// Kept apart from the devices so a network with none on it is still
    /// announced: a router's networks are its wiring, not its population.
    networks: BTreeSet<u16>,
    devices: BTreeMap<NetworkAddress, ServerDispatcher>,
}

impl RouterDevices {
    pub fn new() -> Self {
        Self::default()
    }

    /// Put a network behind the router. Adding one that is already there does
    /// nothing.
    pub fn add_network(&self, network: u16) -> Result<(), ServerError> {
        if network == 0 || network == GLOBAL_BROADCAST {
            return Err(ServerError::InvalidConfiguration(format!(
                "{network} cannot be a routed network number"
            )));
        }
        self.write().networks.insert(network);
        Ok(())
    }

    /// Take a network away, along with every device on it.
    pub fn remove_network(&self, network: u16) {
        let mut routes = self.write();
        routes.networks.remove(&network);
        routes
            .devices
            .retain(|address, _| address.network != network);
    }

    pub fn networks(&self) -> Vec<u16> {
        self.read().networks.iter().copied().collect()
    }

    /// Serve `dispatcher` at `address`, replacing whatever was there.
    pub fn insert(
        &self,
        address: NetworkAddress,
        dispatcher: ServerDispatcher,
    ) -> Result<Option<ServerDispatcher>, ServerError> {
        if address.address.is_empty() {
            return Err(ServerError::InvalidConfiguration(
                "a routed device needs a MAC address".to_string(),
            ));
        }
        let mut routes = self.write();
        if !routes.networks.contains(&address.network) {
            return Err(ServerError::InvalidConfiguration(format!(
                "network {} is not behind this router",
                address.network
            )));
        }
        Ok(routes.devices.insert(address, dispatcher))
    }

    pub fn remove(&self, address: &NetworkAddress) -> Option<ServerDispatcher> {
        self.write().devices.remove(address)
    }

    pub fn addresses(&self) -> Vec<NetworkAddress> {
        self.read().devices.keys().cloned().collect()
    }

    /// The devices a destination reaches, or `None` when it names a network
    /// this router has never heard of.
    ///
    /// Cloned out so no lock is held while a device answers: a dispatcher is a
    /// few `Arc`s, and a site being edited should not wait on a slow request.
    fn reached_by(
        &self,
        destination: &NetworkAddress,
    ) -> Option<Vec<(NetworkAddress, ServerDispatcher)>> {
        let routes = self.read();
        let clone = |(address, dispatcher): (&NetworkAddress, &ServerDispatcher)| {
            (address.clone(), dispatcher.clone())
        };
        if destination.network == GLOBAL_BROADCAST {
            return Some(routes.devices.iter().map(clone).collect());
        }
        if !routes.networks.contains(&destination.network) {
            return None;
        }
        if destination.address.is_empty() {
            let network = routes
                .devices
                .range(NetworkAddress::new(destination.network, Vec::new())..)
                .take_while(|(address, _)| address.network == destination.network);
            return Some(network.map(clone).collect());
        }
        // A MAC nobody holds is not an error: on a real trunk the frame goes
        // out and simply is not answered.
        Some(
            routes
                .devices
                .get_key_value(destination)
                .map(clone)
                .into_iter()
                .collect(),
        )
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Routes> {
        self.routes.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Routes> {
        self.routes.write().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A BACnet/IP endpoint that routes to devices hosted in this process.
///
/// A request with no DNET is for the router itself, which is not a device, so
/// it goes unanswered — a local Who-Is finds nothing here, exactly as with a
/// real router. Clients find the devices through Who-Is-Router-To-Network and a
/// Who-Is sent to each network, or through a global broadcast.
pub struct VirtualRouter {
    socket: Arc<dyn DatagramSocket>,
    devices: RouterDevices,
    receive_buffer: Vec<u8>,
    observer: Option<RequestObserver>,
}

impl VirtualRouter {
    pub fn bind<A: ToSocketAddrs>(address: A, devices: RouterDevices) -> Result<Self, ServerError> {
        Ok(Self::from_socket(UdpSocket::bind(address)?, devices))
    }

    pub fn from_socket(socket: UdpSocket, devices: RouterDevices) -> Self {
        Self::over(Arc::new(socket), devices)
    }

    /// Route over a transport the application provides; see
    /// [`BacnetIpServer::over`](super::BacnetIpServer::over).
    pub fn over(socket: Arc<dyn DatagramSocket>, devices: RouterDevices) -> Self {
        Self {
            socket,
            devices,
            receive_buffer: vec![0; MAX_BACNET_IP_FRAME],
            observer: None,
        }
    }

    /// Show every request a device decoded, and its answer, to `observer`.
    /// [`ServedRequest::device`] says which device it was.
    pub fn observe_requests(
        &mut self,
        observer: impl Fn(&ServedRequest<'_>) + Send + Sync + 'static,
    ) {
        self.observer = Some(Box::new(observer));
    }

    pub fn devices(&self) -> &RouterDevices {
        &self.devices
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ServerError> {
        Ok(self.socket.local_addr()?)
    }

    pub fn socket(&self) -> &Arc<dyn DatagramSocket> {
        &self.socket
    }

    /// A notifier on the router's socket. Give each device its own with
    /// [`Notifier::routed_from`].
    pub fn notifier(&self) -> Result<Notifier, ServerError> {
        Notifier::over(Arc::clone(&self.socket))
    }

    /// Receive one datagram and send whatever it earns — one reply per device
    /// a broadcast reached. Returns whether anything was sent.
    pub fn serve_once(&mut self) -> Result<bool, ServerError> {
        let (length, source) = self.socket.recv_from(&mut self.receive_buffer)?;
        let replies = route(
            &self.devices,
            &self.receive_buffer[..length],
            source,
            self.observer.as_ref(),
        )?;
        for (frame, destination) in &replies {
            self.socket.send_to(frame, *destination)?;
        }
        Ok(!replies.is_empty())
    }
}

type Reply = (Vec<u8>, SocketAddr);

fn route(
    devices: &RouterDevices,
    data: &[u8],
    source: SocketAddr,
    observer: Option<&RequestObserver>,
) -> Result<Vec<Reply>, ServerError> {
    let Ok(header) = BvlcHeader::decode(data) else {
        return Ok(Vec::new());
    };
    let Some((npdu, payload, origin)) = decode_bacnet_ip_frame(data) else {
        return Ok(Vec::new());
    };
    // A Forwarded-NPDU names who really sent it; the BBMD is only the carrier.
    let reply_to = origin.unwrap_or(source);

    if npdu.is_network_message() {
        return Ok(network_message(devices, &npdu, payload)
            .map(|frame| (frame, reply_to))
            .into_iter()
            .collect());
    }

    let Some(destination) = &npdu.destination else {
        return Ok(Vec::new());
    };
    let Some(reached) = devices.reached_by(destination) else {
        // Rejecting a broadcast would answer traffic meant for some other
        // router on the same wire.
        let unicast = header.function == BvlcFunction::OriginalUnicastNpdu;
        return Ok(unicast
            .then(|| (reject(&npdu, destination.network), reply_to))
            .into_iter()
            .collect());
    };

    let request = Apdu::decode(payload);
    let mut replies = Vec::new();
    for (address, dispatcher) in &reached {
        let request = match &request {
            Ok(apdu) => Ok(apdu.clone()),
            // Only a device addressed on its own rejects what it cannot read;
            // a thousand rejects to one malformed broadcast helps nobody.
            Err(_) if reached.len() == 1 && !destination.address.is_empty() => Err(payload),
            Err(_) => continue,
        };
        let response = answer(
            dispatcher,
            &npdu,
            request,
            Some(source),
            observer,
            Some(address),
        )?;
        if let Some(mut response) = response {
            response.npdu.set_source(address.clone());
            replies.push((encode_response(&response), reply_to));
        }
    }
    Ok(replies)
}

/// Answer the one network-layer question a router must: which networks it
/// reaches.
fn network_message(devices: &RouterDevices, npdu: &Npdu, payload: &[u8]) -> Option<Vec<u8>> {
    let message = NetworkLayerMessage::decode(payload).ok()?;
    if message.message_type != NetworkMessageType::WhoIsRouterToNetwork {
        return None;
    }

    let networks = devices.networks();
    let announced = match message.data() {
        None | Some([]) => networks,
        Some([high, low, ..]) => {
            let asked = u16::from_be_bytes([*high, *low]);
            if !networks.contains(&asked) {
                return None;
            }
            vec![asked]
        }
        Some(_) => return None,
    };
    if announced.is_empty() {
        return None;
    }

    let data = announced
        .iter()
        .flat_map(|network| network.to_be_bytes())
        .collect();
    // Answered to whoever asked rather than broadcast as the standard has it:
    // the asker is the one that wants it, and a unicast reaches a client bound
    // to one address, which a broadcast does not.
    Some(network_frame(
        npdu,
        NetworkLayerMessage::new(NetworkMessageType::IAmRouterToNetwork, Some(data)),
    ))
}

fn reject(npdu: &Npdu, network: u16) -> Vec<u8> {
    let [high, low] = network.to_be_bytes();
    network_frame(
        npdu,
        NetworkLayerMessage::new(
            NetworkMessageType::RejectMessageToNetwork,
            Some(vec![REJECT_UNKNOWN_NETWORK, high, low]),
        ),
    )
}

/// A network-layer reply, sent back through whatever router the request came
/// from.
fn network_frame(request: &Npdu, message: NetworkLayerMessage) -> Vec<u8> {
    let mut npdu = Npdu::new();
    npdu.control.network_message = true;
    if let Some(source) = request.source.clone() {
        npdu.set_destination(source);
        npdu.hop_count = Some(255);
    }
    wrap_bvlc_parts(
        BvlcFunction::OriginalUnicastNpdu,
        &[&npdu.encode(), &message.encode()],
    )
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        thread,
        time::Duration,
    };

    use crate::{
        client::{BacnetClient, BacnetTarget},
        object::{
            database::ObjectDatabase, AnalogValue, Device, ObjectIdentifier, ObjectType,
            PropertyIdentifier, PropertyValue,
        },
        server::{NotificationTarget, ObjectService},
        service::cov_notification::{CovNotification, CovPropertyValue},
    };

    use super::*;

    const NETWORK: u16 = 1001;
    const OTHER_NETWORK: u16 = 1002;

    fn device(instance: u32) -> ServerDispatcher {
        let database = ObjectDatabase::new(Device::new(instance, format!("Device {instance}")));
        let mut value = AnalogValue::new(1, "Setpoint".to_string());
        value.present_value = instance as f32;
        database.add_object(Box::new(value)).unwrap();
        ServerDispatcher::new(ObjectService::new(Arc::new(database)))
    }

    fn at(network: u16, mac: u8) -> NetworkAddress {
        NetworkAddress::new(network, vec![mac])
    }

    /// Devices 11 and 12 on one network, 21 on another.
    fn site() -> RouterDevices {
        let devices = RouterDevices::new();
        devices.add_network(NETWORK).unwrap();
        devices.add_network(OTHER_NETWORK).unwrap();
        devices.insert(at(NETWORK, 1), device(11)).unwrap();
        devices.insert(at(NETWORK, 2), device(12)).unwrap();
        devices.insert(at(OTHER_NETWORK, 1), device(21)).unwrap();
        devices
    }

    fn source() -> SocketAddr {
        "127.0.0.1:47809".parse().unwrap()
    }

    fn frame(function: BvlcFunction, npdu: Npdu, payload: &[u8]) -> Vec<u8> {
        wrap_bvlc_parts(function, &[&npdu.encode(), payload])
    }

    fn who_is_router(network: Option<u16>) -> Vec<u8> {
        let mut npdu = Npdu::new();
        npdu.control.network_message = true;
        let data = network.map(|network| network.to_be_bytes().to_vec());
        let message = NetworkLayerMessage::new(NetworkMessageType::WhoIsRouterToNetwork, data);
        frame(BvlcFunction::OriginalBroadcastNpdu, npdu, &message.encode())
    }

    const WHO_IS: [u8; 2] = [0x10, 0x08];

    fn who_is_to(function: BvlcFunction, destination: Option<NetworkAddress>) -> Vec<u8> {
        let mut npdu = Npdu::new();
        if let Some(destination) = destination {
            npdu.set_destination(destination);
            npdu.hop_count = Some(255);
        }
        frame(function, npdu, &WHO_IS)
    }

    fn decoded(reply: &Reply) -> (Npdu, Vec<u8>) {
        let (npdu, payload, _) = decode_bacnet_ip_frame(&reply.0).expect("a BACnet/IP frame");
        (npdu, payload.to_vec())
    }

    /// Which devices answered a Who-Is, by the SNET/SADR on their I-Am.
    fn answered_by(replies: &[Reply]) -> Vec<NetworkAddress> {
        replies
            .iter()
            .map(|reply| {
                let (npdu, apdu) = decoded(reply);
                assert_eq!(apdu[..2], [0x10, 0x00], "an I-Am");
                npdu.source.expect("a routed reply names its device")
            })
            .collect()
    }

    fn announced(reply: &Reply) -> Vec<u16> {
        let (npdu, payload) = decoded(reply);
        assert!(npdu.is_network_message());
        let message = NetworkLayerMessage::decode(&payload).unwrap();
        assert_eq!(message.message_type, NetworkMessageType::IAmRouterToNetwork);
        message
            .data()
            .unwrap()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
            .collect()
    }

    /// A router is found before any device behind it, and names every network
    /// it reaches, empty or not.
    #[test]
    fn who_is_router_with_no_network_is_told_every_network() {
        let devices = site();
        devices.add_network(1003).unwrap();

        let replies = route(&devices, &who_is_router(None), source(), None).unwrap();

        assert_eq!(replies.len(), 1);
        assert_eq!(announced(&replies[0]), [NETWORK, OTHER_NETWORK, 1003]);
        assert_eq!(replies[0].1, source());
    }

    #[test]
    fn who_is_router_for_one_network_is_answered_only_by_its_router() {
        let devices = site();

        let ours = route(
            &devices,
            &who_is_router(Some(OTHER_NETWORK)),
            source(),
            None,
        )
        .unwrap();
        let theirs = route(&devices, &who_is_router(Some(7)), source(), None).unwrap();

        assert_eq!(announced(&ours[0]), [OTHER_NETWORK]);
        assert!(theirs.is_empty());
    }

    /// The router is not a device: a Who-Is on the local network finds nothing
    /// here, which is what sends a client looking for routers.
    #[test]
    fn a_local_who_is_is_not_answered() {
        let frame = who_is_to(BvlcFunction::OriginalBroadcastNpdu, None);

        assert!(route(&site(), &frame, source(), None).unwrap().is_empty());
    }

    #[test]
    fn a_global_who_is_reaches_every_device_on_every_network() {
        let frame = who_is_to(
            BvlcFunction::OriginalBroadcastNpdu,
            Some(NetworkAddress::new(GLOBAL_BROADCAST, Vec::new())),
        );

        let replies = route(&site(), &frame, source(), None).unwrap();

        assert_eq!(
            answered_by(&replies),
            [at(NETWORK, 1), at(NETWORK, 2), at(OTHER_NETWORK, 1)]
        );
        assert!(replies.iter().all(|reply| reply.1 == source()));
    }

    #[test]
    fn a_who_is_to_one_network_reaches_only_the_devices_on_it() {
        let frame = who_is_to(
            BvlcFunction::OriginalUnicastNpdu,
            Some(NetworkAddress::new(NETWORK, Vec::new())),
        );

        let replies = route(&site(), &frame, source(), None).unwrap();

        assert_eq!(answered_by(&replies), [at(NETWORK, 1), at(NETWORK, 2)]);
    }

    #[test]
    fn a_request_to_one_mac_reaches_only_that_device() {
        let frame = who_is_to(BvlcFunction::OriginalUnicastNpdu, Some(at(NETWORK, 2)));

        let replies = route(&site(), &frame, source(), None).unwrap();

        assert_eq!(answered_by(&replies), [at(NETWORK, 2)]);
    }

    #[test]
    fn a_mac_nobody_holds_goes_unanswered() {
        let frame = who_is_to(BvlcFunction::OriginalUnicastNpdu, Some(at(NETWORK, 9)));

        assert!(route(&site(), &frame, source(), None).unwrap().is_empty());
    }

    /// A unicast to a network this router does not reach is rejected, so the
    /// client stops waiting; a broadcast is left for whichever router does.
    #[test]
    fn an_unknown_network_is_rejected_only_when_asked_directly() {
        let unicast = who_is_to(BvlcFunction::OriginalUnicastNpdu, Some(at(7, 1)));
        let broadcast = who_is_to(BvlcFunction::OriginalBroadcastNpdu, Some(at(7, 1)));

        let replies = route(&site(), &unicast, source(), None).unwrap();
        let (npdu, payload) = decoded(&replies[0]);
        let message = NetworkLayerMessage::decode(&payload).unwrap();

        assert!(npdu.is_network_message());
        assert_eq!(
            message.message_type,
            NetworkMessageType::RejectMessageToNetwork
        );
        assert_eq!(message.data(), Some(&[REJECT_UNKNOWN_NETWORK, 0, 7][..]));
        assert!(route(&site(), &broadcast, source(), None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_device_can_only_be_put_on_a_network_behind_the_router() {
        let devices = RouterDevices::new();

        assert!(devices.insert(at(NETWORK, 1), device(11)).is_err());
        assert!(devices.add_network(0).is_err());
        assert!(devices.add_network(GLOBAL_BROADCAST).is_err());
    }

    #[test]
    fn removing_a_network_removes_the_devices_on_it() {
        let devices = site();

        devices.remove_network(NETWORK);

        assert_eq!(devices.networks(), [OTHER_NETWORK]);
        assert_eq!(devices.addresses(), [at(OTHER_NETWORK, 1)]);
    }

    #[test]
    fn a_routed_notification_names_the_device_that_sent_it() {
        let router = VirtualRouter::bind("127.0.0.1:0", RouterDevices::new()).unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let notifier = router.notifier().unwrap().routed_from(at(NETWORK, 2));

        let notification = CovNotification {
            subscriber_process_identifier: 0,
            initiating_device: ObjectIdentifier::new(ObjectType::Device, 12),
            monitored_object: ObjectIdentifier::new(ObjectType::AnalogValue, 1),
            time_remaining: 0,
            list_of_values: vec![CovPropertyValue::new(
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(12.0),
            )],
        };
        notifier
            .send_cov_notification(
                NotificationTarget::Unicast(receiver.local_addr().unwrap()),
                &notification,
                false,
            )
            .unwrap();

        let mut buffer = [0u8; MAX_BACNET_IP_FRAME];
        let (length, _) = receiver.recv_from(&mut buffer).unwrap();
        let (npdu, _, _) = decode_bacnet_ip_frame(&buffer[..length]).unwrap();
        assert_eq!(npdu.source, Some(at(NETWORK, 2)));
    }

    /// The whole path a client takes: find the router, find the devices behind
    /// it, read from each — and a device taken away mid-run stops answering.
    #[test]
    fn a_client_finds_and_reads_each_device_behind_the_router() {
        let devices = site();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let router_address = socket.local_addr().unwrap();
        let mut router = VirtualRouter::from_socket(socket, devices.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let serving = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = router.serve_once();
                }
            })
        };

        let client = BacnetClient::builder()
            .local_addr("127.0.0.1")
            .port(0)
            .timeout(Duration::from_millis(300))
            .build()
            .unwrap();
        let mut found = client
            .who_is_network(router_address, NETWORK, None, None)
            .unwrap();
        found.sort_by_key(|device| device.device_id);
        assert_eq!(
            found
                .iter()
                .map(|device| (device.device_id, device.route.clone()))
                .collect::<Vec<_>>(),
            [(11, Some(at(NETWORK, 1))), (12, Some(at(NETWORK, 2)))]
        );

        let setpoint = ObjectIdentifier::new(ObjectType::AnalogValue, 1);
        for device in &found {
            let value = client
                .read_property(device.target(), setpoint, PropertyIdentifier::PresentValue)
                .unwrap();
            assert_eq!(value, [PropertyValue::Real(device.device_id as f32)]);
        }

        devices.remove(&at(NETWORK, 2));
        let gone = BacnetTarget::routed(router_address, at(NETWORK, 2));
        assert!(client
            .read_property(gone, setpoint, PropertyIdentifier::PresentValue)
            .is_err());

        stop.store(true, Ordering::Relaxed);
        serving.join().unwrap();
    }
}
