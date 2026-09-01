#![cfg(feature = "async")]

use std::{sync::Arc, time::Duration};

use bacnet_rs::{
    app::Apdu,
    client::{AsyncBacnetClient, ClientConfig, DiscoveredRouter},
    network::{NetworkAddress, Npdu},
    object::{
        database::ObjectDatabase, AnalogValue, Device, ObjectIdentifier, ObjectType,
        PropertyIdentifier, Segmentation,
    },
    property::PropertyValue,
    server::AsyncBacnetIpServer,
    service::{
        ConfirmedServiceChoice, IAmRequest, ReadPropertyRequest, ReadPropertyResponse,
        UnconfirmedServiceChoice,
    },
};
use tokio::net::UdpSocket;

fn parse_confirmed_request(frame: &[u8]) -> Apdu {
    let (_, npdu_length) = Npdu::decode(&frame[4..]).expect("decode NPDU");
    Apdu::decode(&frame[4 + npdu_length..]).expect("decode APDU")
}

fn read_property_ack(request: Apdu) -> (u32, Vec<u8>) {
    let Apdu::ConfirmedRequest {
        invoke_id,
        service_choice: ConfirmedServiceChoice::ReadProperty,
        service_data,
        ..
    } = request
    else {
        panic!("expected ReadProperty request")
    };
    let request = ReadPropertyRequest::decode(&service_data).unwrap();
    let instance = request.object_identifier.instance;
    let mut response = ReadPropertyResponse::new(
        request.object_identifier,
        request.property_identifier,
        vec![PropertyValue::Real(instance as f32)],
    );
    response.property_array_index = request.property_array_index;
    let mut service_data = Vec::new();
    response.encode(&mut service_data).unwrap();
    let apdu = Apdu::ComplexAck {
        segmented: false,
        more_follows: false,
        invoke_id,
        sequence_number: None,
        proposed_window_size: None,
        service_choice: ConfirmedServiceChoice::ReadProperty,
        service_data,
    };
    (instance, wrap_response(apdu))
}

fn wrap_response(apdu: Apdu) -> Vec<u8> {
    let mut payload = Npdu::new().encode();
    payload.extend_from_slice(&apdu.encode());
    let length = payload.len() + 4;
    let mut frame = vec![0x81, 0x0A, (length >> 8) as u8, length as u8];
    frame.extend_from_slice(&payload);
    frame
}

fn i_am_frame(device_id: u32, route: Option<NetworkAddress>) -> Vec<u8> {
    let mut npdu = Npdu::new();
    if let Some(route) = route {
        npdu.set_source(route);
    }
    let iam = IAmRequest::new(
        ObjectIdentifier::new(ObjectType::Device, device_id),
        1476,
        Segmentation::NoSegmentation,
        99,
    );
    let mut service_data = Vec::new();
    iam.encode(&mut service_data).unwrap();
    let mut payload = npdu.encode();
    payload.extend_from_slice(&[0x10, UnconfirmedServiceChoice::IAm as u8]);
    payload.extend_from_slice(&service_data);
    let length = payload.len() + 4;
    let mut frame = vec![0x81, 0x0A, (length >> 8) as u8, length as u8];
    frame.extend_from_slice(&payload);
    frame
}

async fn test_client(timeout: Duration, retries: u8) -> AsyncBacnetClient {
    AsyncBacnetClient::from_config(ClientConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        timeout,
        retries,
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn concurrent_reads_are_sent_before_either_response_arrives() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (length, source) = device.recv_from(&mut buffer).await.unwrap();
            requests.push((parse_confirmed_request(&buffer[..length]), source));
        }

        // Respond in reverse order to prove invoke-ID routing, rather than
        // request ordering, selects each waiting caller.
        for (request, source) in requests.into_iter().rev() {
            let (_, frame) = read_property_ack(request);
            device.send_to(&frame, source).await.unwrap();
        }
    });

    let client = test_client(Duration::from_secs(1), 0).await;
    let first = ObjectIdentifier::new(ObjectType::AnalogValue, 1);
    let second = ObjectIdentifier::new(ObjectType::AnalogValue, 2);
    let (first_result, second_result) = tokio::join!(
        client.read_property(address, first, PropertyIdentifier::PresentValue),
        client.read_property(address, second, PropertyIdentifier::PresentValue),
    );

    assert_eq!(first_result.unwrap(), vec![PropertyValue::Real(1.0)]);
    assert_eq!(second_result.unwrap(), vec![PropertyValue::Real(2.0)]);
    responder.await.unwrap();
}

#[tokio::test]
async fn timed_out_transaction_is_retried_without_blocking_the_endpoint() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        let (first_length, _) = device.recv_from(&mut buffer).await.unwrap();
        let first = parse_confirmed_request(&buffer[..first_length]);

        let (second_length, source) = device.recv_from(&mut buffer).await.unwrap();
        let second = parse_confirmed_request(&buffer[..second_length]);
        let (
            Apdu::ConfirmedRequest { invoke_id: a, .. },
            Apdu::ConfirmedRequest { invoke_id: b, .. },
        ) = (&first, &second)
        else {
            unreachable!()
        };
        assert_eq!(a, b, "a retry must retain its transaction invoke ID");
        let (_, frame) = read_property_ack(second);
        device.send_to(&frame, source).await.unwrap();
    });

    let client = test_client(Duration::from_millis(40), 1).await;
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 7);
    assert_eq!(
        client
            .read_property(address, object, PropertyIdentifier::PresentValue)
            .await
            .unwrap(),
        vec![PropertyValue::Real(7.0)]
    );
    responder.await.unwrap();
}

#[tokio::test]
async fn cancelled_requests_release_invoke_ids_before_new_work_is_admitted() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();
    let (all_received, received) = tokio::sync::oneshot::channel();
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        for _ in 0..=u8::MAX {
            device.recv_from(&mut buffer).await.unwrap();
        }
        all_received.send(()).unwrap();

        let (length, source) = device.recv_from(&mut buffer).await.unwrap();
        let (_, frame) = read_property_ack(parse_confirmed_request(&buffer[..length]));
        device.send_to(&frame, source).await.unwrap();
    });

    let client = test_client(Duration::from_secs(5), 0).await;
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 9);
    let mut requests = Vec::new();
    for _ in 0..=u8::MAX {
        let client = client.clone();
        requests.push(tokio::spawn(async move {
            client
                .read_property(address, object, PropertyIdentifier::PresentValue)
                .await
        }));
    }
    received.await.unwrap();
    for request in requests {
        request.abort();
    }
    tokio::task::yield_now().await;

    assert_eq!(
        client
            .read_property(address, object, PropertyIdentifier::PresentValue)
            .await
            .unwrap(),
        vec![PropertyValue::Real(9.0)]
    );
    responder.await.unwrap();
}

#[tokio::test]
async fn who_is_collects_and_dedupes_i_am_responses() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        let (_, source) = device.recv_from(&mut buffer).await.unwrap();
        let frame = i_am_frame(1234, None);
        device.send_to(&frame, source).await.unwrap();
        device.send_to(&frame, source).await.unwrap();
    });

    let client = test_client(Duration::from_millis(200), 0).await;
    let devices = client.who_is_to(address, None, None).await.unwrap();
    assert_eq!(devices.len(), 1, "duplicate I-Am must be de-duplicated");
    assert_eq!(devices[0].device_id, 1234);
    assert_eq!(devices[0].address, address);
    assert_eq!(devices[0].route, None);
    assert_eq!(devices[0].max_apdu, 1476);
    responder.await.unwrap();
}

#[tokio::test]
async fn routed_i_am_yields_route_used_for_confirmed_requests() {
    let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = router.local_addr().unwrap();
    let route = NetworkAddress::new(100, vec![146, 52]);
    let responder = tokio::spawn({
        let route = route.clone();
        async move {
            let mut buffer = [0_u8; 1500];
            let (_, source) = router.recv_from(&mut buffer).await.unwrap();
            router
                .send_to(&i_am_frame(13458, Some(route.clone())), source)
                .await
                .unwrap();

            // The follow-up confirmed request must carry the discovered
            // route as its NPDU destination.
            let (length, source) = router.recv_from(&mut buffer).await.unwrap();
            let (npdu, npdu_length) = Npdu::decode(&buffer[4..length]).unwrap();
            assert_eq!(npdu.destination, Some(route));
            let apdu = Apdu::decode(&buffer[4 + npdu_length..length]).unwrap();
            let (_, frame) = read_property_ack(apdu);
            router.send_to(&frame, source).await.unwrap();
        }
    });

    let client = test_client(Duration::from_millis(200), 0).await;
    let devices = client.who_is_to(address, None, None).await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].route, Some(route));

    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 5);
    let values = client
        .read_property(
            devices[0].target(),
            object,
            PropertyIdentifier::PresentValue,
        )
        .await
        .unwrap();
    assert_eq!(values, vec![PropertyValue::Real(5.0)]);
    responder.await.unwrap();
}

#[tokio::test]
async fn who_is_router_collects_advertised_networks() {
    let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = router.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        let (length, source) = router.recv_from(&mut buffer).await.unwrap();
        assert_eq!(buffer[..2], [0x81, 0x0A], "expected unicast Who-Is-Router");
        assert!(length >= 7);
        let frame = [
            0x81, 0x0A, 0x00, 0x0B, // BVLC Original-Unicast-NPDU
            0x01, 0x80, // NPDU network-layer message
            0x01, // I-Am-Router-To-Network
            0x00, 0x64, // network 100
            0x01, 0x2C, // network 300
        ];
        router.send_to(&frame, source).await.unwrap();
    });

    let client = test_client(Duration::from_millis(200), 0).await;
    let routers = client.who_is_router_to(address, None).await.unwrap();
    assert_eq!(
        routers,
        vec![DiscoveredRouter {
            address,
            networks: vec![100, 300],
        }]
    );
    responder.await.unwrap();
}

#[tokio::test]
async fn discovery_window_does_not_block_confirmed_requests() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        // The Who-Is arrives first but is answered only after the confirmed
        // read has been served, proving the window doesn't serialize traffic.
        let (_, whois_source) = device.recv_from(&mut buffer).await.unwrap();
        let (length, source) = device.recv_from(&mut buffer).await.unwrap();
        let (_, frame) = read_property_ack(parse_confirmed_request(&buffer[..length]));
        device.send_to(&frame, source).await.unwrap();
        device
            .send_to(&i_am_frame(77, None), whois_source)
            .await
            .unwrap();
    });

    let client = test_client(Duration::from_millis(500), 0).await;
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 3);
    let (devices, values) = tokio::join!(
        client.who_is_to(address, None, None),
        client.read_property(address, object, PropertyIdentifier::PresentValue),
    );
    assert_eq!(values.unwrap(), vec![PropertyValue::Real(3.0)]);
    let devices = devices.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, 77);
    responder.await.unwrap();
}

#[tokio::test]
async fn hosted_server_supports_async_object_inspection_and_writes() {
    let database = Arc::new(ObjectDatabase::new(Device::new(
        1234,
        "Async test device".to_string(),
    )));
    let mut value = AnalogValue::new(1, "Setpoint".to_string());
    value.present_value = 21.5;
    let object = value.identifier;
    database.add_object(Box::new(value)).unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = AsyncBacnetIpServer::from_socket(socket, Arc::clone(&database));
    let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(server.run_until(async {
        let _ = stopped.await;
    }));

    let client = test_client(Duration::from_secs(1), 0).await;
    let (objects, snapshot) = tokio::join!(
        client.read_object_list(address, 1234),
        client.read_object_properties(address, object),
    );
    let objects = objects.unwrap();
    assert!(objects.contains(&ObjectIdentifier::new(ObjectType::Device, 1234)));
    assert!(objects.contains(&object));
    assert!(snapshot
        .unwrap()
        .properties
        .iter()
        .any(|property| property.property_identifier == PropertyIdentifier::PresentValue));

    client
        .write_property(
            address,
            object,
            PropertyIdentifier::PresentValue,
            &PropertyValue::Real(24.0),
            Some(8),
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .read_property(address, object, PropertyIdentifier::PresentValue)
            .await
            .unwrap(),
        vec![PropertyValue::Real(24.0)]
    );

    shutdown.send(()).unwrap();
    server_task.await.unwrap().unwrap();
}

/// Answer every request promptly, reporting the invoke ID each one carried.
///
/// Used to walk the endpoint's invoke ID counter all the way round, which is
/// the only way a previously-abandoned ID comes up for reuse.
fn quick_responder(device: UdpSocket, count: usize) -> tokio::task::JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        let mut seen = Vec::with_capacity(count);
        for _ in 0..count {
            let (length, source) = device.recv_from(&mut buffer).await.unwrap();
            let request = parse_confirmed_request(&buffer[..length]);
            if let Apdu::ConfirmedRequest { invoke_id, .. } = &request {
                seen.push(*invoke_id);
            }
            let (_, frame) = read_property_ack(request);
            device.send_to(&frame, source).await.unwrap();
        }
        seen
    })
}

/// A device that answers after the client has given up must not have its
/// answer handed to whatever question came next.
///
/// The invoke ID is the only thing the endpoint routes a response on, so an ID
/// that comes back into circulation makes a late response indistinguishable
/// from the right one: same peer, same service choice, same ID. The counter
/// advances monotonically, so this only bites once it has been all the way
/// round - which on a busy client takes no time at all. Hence the 256 requests
/// here: without them the IDs differ for a reason that has nothing to do with
/// the quarantine, and the test would pass whether or not it worked.
#[tokio::test]
async fn an_abandoned_invoke_id_is_skipped_when_the_counter_comes_round() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();

    let ignored = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        let (length, _) = device.recv_from(&mut buffer).await.unwrap();
        let request = parse_confirmed_request(&buffer[..length]);
        let Apdu::ConfirmedRequest { invoke_id, .. } = request else {
            unreachable!()
        };
        (device, invoke_id)
    });

    // Long enough that the quarantine is still in force while the 256 requests
    // below run - they are loopback round trips and take a few tens of ms.
    let client = test_client(Duration::from_millis(500), 0).await;
    let abandoned = ObjectIdentifier::new(ObjectType::AnalogValue, 11);
    assert!(
        client
            .read_property(address, abandoned, PropertyIdentifier::PresentValue)
            .await
            .is_err(),
        "the unanswered request should time out"
    );
    let (device, abandoned_id) = ignored.await.unwrap();

    let responder = quick_responder(device, 256);
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 3);
    for _ in 0..256 {
        client
            .read_property(address, object, PropertyIdentifier::PresentValue)
            .await
            .unwrap();
    }

    let used = responder.await.unwrap();
    assert!(
        !used.contains(&abandoned_id),
        "invoke id {abandoned_id} was reissued while its transaction could still \
         be answered late, so that answer would be delivered as another request's"
    );
}

/// And it comes back afterwards, so a device having a bad minute does not
/// permanently shrink a 256-entry pool.
#[tokio::test]
async fn a_quarantined_invoke_id_returns_once_its_budget_passes() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();

    let ignored = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        let (length, _) = device.recv_from(&mut buffer).await.unwrap();
        let request = parse_confirmed_request(&buffer[..length]);
        let Apdu::ConfirmedRequest { invoke_id, .. } = request else {
            unreachable!()
        };
        (device, invoke_id)
    });

    let client = test_client(Duration::from_millis(40), 0).await;
    let abandoned = ObjectIdentifier::new(ObjectType::AnalogValue, 11);
    let _ = client
        .read_property(address, abandoned, PropertyIdentifier::PresentValue)
        .await;
    let (device, abandoned_id) = ignored.await.unwrap();

    // Past the 40ms budget, so the hold has lapsed.
    tokio::time::sleep(Duration::from_millis(120)).await;

    let responder = quick_responder(device, 256);
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 3);
    for _ in 0..256 {
        client
            .read_property(address, object, PropertyIdentifier::PresentValue)
            .await
            .unwrap();
    }

    let used = responder.await.unwrap();
    assert!(
        used.contains(&abandoned_id),
        "invoke id {abandoned_id} never came back, so a timing-out device would \
         whittle the pool away a transaction at a time"
    );
}

/// One device's outstanding transactions must not consume another device's
/// invoke IDs.
///
/// ASHRAE 135 scopes the transaction state machine to a pair of devices, so
/// each peer has its own 256. Keyed globally, a client with many devices in
/// flight at once runs out against all of them together - and a site is
/// exactly that shape: two hundred controllers, each polled and subscribed
/// concurrently. Two slow devices here stand in for that: neither answers, so
/// both hold their transactions open, and a third request to a *different*
/// peer still has to be admitted.
#[tokio::test]
async fn one_peer_holding_transactions_open_does_not_exhaust_another() {
    // Two devices that receive and never answer, so their transactions stay
    // outstanding for the length of the test.
    let silent_one = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_two = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_one_addr = silent_one.local_addr().unwrap();
    let silent_two_addr = silent_two.local_addr().unwrap();

    let answering = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let answering_addr = answering.local_addr().unwrap();
    let responder = quick_responder(answering, 1);

    let client = test_client(Duration::from_secs(30), 0).await;
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);

    // Fill both silent peers' tables well past what a single shared table
    // would have left over.
    let mut outstanding = Vec::new();
    for address in [silent_one_addr, silent_two_addr] {
        for _ in 0..200 {
            let client = client.clone();
            outstanding.push(tokio::spawn(async move {
                client
                    .read_property(address, object, PropertyIdentifier::PresentValue)
                    .await
            }));
        }
    }

    // Let those requests reach the endpoint before asking the third device for
    // anything, so the budget is genuinely occupied when it is admitted.
    //
    // Bounded rather than counted: with a single shared budget most of these
    // are refused an invoke ID and never reach the wire at all, and waiting
    // for a fixed 400 would hang instead of failing. How many arrived is not
    // the assertion - the third device answering is.
    let mut buffer = [0_u8; 1500];
    for socket in [&silent_one, &silent_two] {
        for _ in 0..200 {
            if tokio::time::timeout(Duration::from_millis(200), socket.recv_from(&mut buffer))
                .await
                .is_err()
            {
                break;
            }
        }
    }

    let answered = tokio::time::timeout(
        Duration::from_secs(5),
        client.read_property(answering_addr, object, PropertyIdentifier::PresentValue),
    )
    .await
    .expect("a third device must still be reachable");
    assert_eq!(
        answered.unwrap(),
        vec![PropertyValue::Real(1.0)],
        "400 transactions outstanding with two other devices must not deny a third an invoke ID"
    );

    responder.await.unwrap();
    for task in outstanding {
        task.abort();
    }
}

/// A response is matched to the peer that sent it, not to the ID alone.
///
/// This property is older than the per-peer budget - it used to be an explicit
/// `pending.peer != source` comparison - but the budget is what makes it load
/// bearing, because an ID can now legitimately be outstanding with two devices
/// at once. The check now lives in the shape of the routing key rather than in
/// a line of its own, so it is worth a test that would notice it going missing:
/// for a client reading the same property from similar devices, one device's
/// answer delivered to another's caller is indistinguishable from the truth.
#[tokio::test]
async fn a_response_is_matched_to_the_peer_that_sent_it() {
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let first_addr = first.local_addr().unwrap();
    let second_addr = second.local_addr().unwrap();

    // Each device answers with its own object instance as the value, so the
    // two answers are told apart by content.
    let first_responder = quick_responder(first, 1);
    let second_responder = quick_responder(second, 1);

    let client = test_client(Duration::from_secs(5), 0).await;
    let (first_result, second_result) = tokio::join!(
        client.read_property(
            first_addr,
            ObjectIdentifier::new(ObjectType::AnalogValue, 11),
            PropertyIdentifier::PresentValue
        ),
        client.read_property(
            second_addr,
            ObjectIdentifier::new(ObjectType::AnalogValue, 22),
            PropertyIdentifier::PresentValue
        ),
    );

    assert_eq!(first_result.unwrap(), vec![PropertyValue::Real(11.0)]);
    assert_eq!(second_result.unwrap(), vec![PropertyValue::Real(22.0)]);

    first_responder.await.unwrap();
    second_responder.await.unwrap();
}
