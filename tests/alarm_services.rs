#![cfg(feature = "async")]

//! A recipient enrolling itself and catching up on alarm state, against the
//! stack's own server.

use std::{sync::Arc, time::Duration};

use bacnet_rs::{
    app::{Apdu, MaxApduSize, MaxSegments},
    client::{AsyncBacnetClient, ClientConfig, ClientError},
    event::EventEngine,
    network::Npdu,
    object::{
        database::ObjectDatabase, intrinsic::EventTransitionBits, BinaryPV, BinaryValue, Device,
        EventState, NotificationClass, ObjectIdentifier, ObjectType, PropertyIdentifier,
    },
    property::{BacnetAddress, DestinationValue, PropertyValue, Recipient, TimestampValue},
    server::AsyncBacnetIpServer,
    service::{
        acknowledge_alarm::AcknowledgeAlarmRequest,
        event_information::{GetEventInformationAck, GetEventInformationRequest},
        ConfirmedServiceChoice,
    },
};
use tokio::net::UdpSocket;

const CLASS: u32 = 1;

fn class() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::NotificationClass, CLASS)
}

fn pump() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::BinaryValue, 1)
}

fn us() -> PropertyValue {
    PropertyValue::Destination(DestinationValue {
        valid_days: vec![true; 7],
        from_time: (0, 0, 0, 0),
        to_time: (23, 59, 59, 99),
        recipient: Recipient::Address(BacnetAddress {
            network: 0,
            mac_address: vec![10, 0, 0, 5, 0xba, 0xc0],
        }),
        process_identifier: 0xbac8,
        issue_confirmed_notifications: true,
        transitions: vec![true; 3],
    })
}

/// A device with one pump whose fault is in alarm and unacknowledged, and
/// one recipient someone else enrolled.
fn database() -> Arc<ObjectDatabase> {
    let database = Arc::new(ObjectDatabase::new(Device::new(3016, "Plant".to_string())));
    database
        .add_object(Box::new(
            NotificationClass::new(CLASS, "Alarms".to_string())
                .with_priority(100, 50, 200)
                .with_ack_required(EventTransitionBits::all())
                .with_recipient(ObjectIdentifier::new(ObjectType::Device, 9000), 1),
        ))
        .unwrap();
    database
        .add_object(Box::new(
            BinaryValue::new(1, "Pump fault".to_string())
                .with_intrinsic_reporting(CLASS, BinaryPV::Active),
        ))
        .unwrap();
    database
        .set_property(
            pump(),
            PropertyIdentifier::PresentValue,
            PropertyValue::Enumerated(1),
        )
        .unwrap();
    EventEngine::new(3016).tick(&database, 0, TimestampValue::SequenceNumber(7));
    database
}

async fn serve() -> (
    AsyncBacnetClient,
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = AsyncBacnetIpServer::from_socket(socket, database());
    let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(server.run_until(async {
        let _ = stopped.await;
    }));
    let client = AsyncBacnetClient::from_config(ClientConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        timeout: Duration::from_secs(1),
        retries: 0,
    })
    .await
    .unwrap();
    (client, address, shutdown)
}

async fn recipients(
    client: &AsyncBacnetClient,
    address: std::net::SocketAddr,
) -> Vec<PropertyValue> {
    client
        .read_property(address, class(), PropertyIdentifier::RecipientList)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_recipient_adds_and_removes_itself_without_touching_the_others() {
    let (client, address, _shutdown) = serve().await;
    let before = recipients(&client, address).await;
    assert_eq!(before.len(), 1);

    for _ in 0..2 {
        client
            .add_list_element(
                address,
                class(),
                PropertyIdentifier::RecipientList,
                vec![us()],
            )
            .await
            .unwrap();
    }
    let enrolled = recipients(&client, address).await;
    assert_eq!(enrolled.len(), 2, "adding twice adds once");
    assert_eq!(enrolled[0], before[0]);
    assert_eq!(enrolled[1], us());

    client
        .remove_list_element(
            address,
            class(),
            PropertyIdentifier::RecipientList,
            vec![us()],
        )
        .await
        .unwrap();
    assert_eq!(recipients(&client, address).await, before);

    let error = client
        .remove_list_element(
            address,
            class(),
            PropertyIdentifier::RecipientList,
            vec![us()],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, ClientError::PropertyError { .. }),
        "removing what is not there is refused: {error:?}"
    );
}

#[tokio::test]
async fn a_recipient_catches_up_and_acknowledges() {
    let (client, address, _shutdown) = serve().await;

    let summaries = client.get_event_information(address).await.unwrap();
    assert_eq!(summaries.len(), 1);
    let summary = &summaries[0];
    assert_eq!(summary.object_identifier, pump());
    assert_eq!(summary.event_state, EventState::Offnormal);
    assert_eq!(summary.acknowledged_transitions, [false, true, true]);
    assert_eq!(summary.event_priorities, [100, 50, 200]);
    assert_eq!(
        summary.event_time_stamps[0],
        TimestampValue::SequenceNumber(7)
    );

    let alarms = client.get_alarm_summary(address).await.unwrap();
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].alarm_state, EventState::Offnormal);

    client
        .acknowledge_alarm(
            address,
            &AcknowledgeAlarmRequest {
                acknowledging_process_identifier: 0xbac8,
                event_object_identifier: pump(),
                event_state_acknowledged: EventState::Offnormal,
                time_stamp: summary.event_time_stamps[0].clone(),
                acknowledgment_source: "bacr8".to_string(),
                time_of_acknowledgment: TimestampValue::SequenceNumber(8),
            },
        )
        .await
        .unwrap();
    let summaries = client.get_event_information(address).await.unwrap();
    assert_eq!(summaries[0].acknowledged_transitions, [true, true, true]);
}

/// Nine alarms stamped with a date and time are over 480 bytes as one page,
/// so a client that takes no more than that must get them in several.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_taking_480_bytes_is_paged_within_them() {
    let database = Arc::new(ObjectDatabase::new(Device::new(3016, "Plant".to_string())));
    database
        .add_object(Box::new(
            NotificationClass::new(CLASS, "Alarms".to_string())
                .with_ack_required(EventTransitionBits::all())
                .with_recipient(ObjectIdentifier::new(ObjectType::Device, 9000), 1),
        ))
        .unwrap();
    for instance in 1..=9 {
        database
            .add_object(Box::new(
                BinaryValue::new(instance, format!("Pump {instance}"))
                    .with_intrinsic_reporting(CLASS, BinaryPV::Active),
            ))
            .unwrap();
        database
            .set_property(
                ObjectIdentifier::new(ObjectType::BinaryValue, instance),
                PropertyIdentifier::PresentValue,
                PropertyValue::Enumerated(1),
            )
            .unwrap();
    }
    // Off-normal, back to normal, then a fault: all three transitions
    // stamped with a date and time, as a summary is at its largest.
    let mut engine = EventEngine::new(3016);
    let at = |minute| TimestampValue::DateTime {
        date: (2026, 11, 17, 2),
        time: (10, minute, 0, 0),
    };
    engine.tick(&database, 0, at(15));
    for instance in 1..=9 {
        database
            .set_property(
                ObjectIdentifier::new(ObjectType::BinaryValue, instance),
                PropertyIdentifier::PresentValue,
                PropertyValue::Enumerated(0),
            )
            .unwrap();
    }
    engine.tick(&database, 60, at(16));
    for instance in 1..=9 {
        database
            .set_property(
                ObjectIdentifier::new(ObjectType::BinaryValue, instance),
                PropertyIdentifier::Reliability,
                PropertyValue::Enumerated(7),
            )
            .unwrap();
    }
    engine.tick(&database, 120, at(17));

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = AsyncBacnetIpServer::from_socket(socket, database);
    tokio::spawn(server.run_until(std::future::pending::<()>()));
    // Asked as a device that takes neither more than 480 bytes nor segments.
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut last = None;
    let mut seen = 0;
    loop {
        let mut service_data = Vec::new();
        GetEventInformationRequest {
            last_received_object_identifier: last,
        }
        .encode(&mut service_data)
        .unwrap();
        let request = Apdu::ConfirmedRequest {
            segmented: false,
            more_follows: false,
            segmented_response_accepted: false,
            max_segments: MaxSegments::Unspecified,
            max_response_size: MaxApduSize::Up480,
            invoke_id: 1,
            sequence_number: None,
            proposed_window_size: None,
            service_choice: ConfirmedServiceChoice::GetEventInformation,
            service_data,
        };
        let mut payload = Npdu::new().encode();
        payload.extend_from_slice(&request.encode());
        let mut frame = vec![0x81, 0x0a, 0, (payload.len() + 4) as u8];
        frame.extend_from_slice(&payload);
        peer.send_to(&frame, address).unwrap();

        let mut buffer = [0u8; 1500];
        let (length, _) = peer.recv_from(&mut buffer).unwrap();
        assert!(
            length - 4 <= 480 + 2,
            "a {length}-byte frame for a 480-byte APDU"
        );
        let (_, npdu_length) = Npdu::decode(&buffer[4..length]).unwrap();
        let reply = Apdu::decode(&buffer[4 + npdu_length..length]).unwrap();
        let Apdu::ComplexAck { service_data, .. } = reply else {
            panic!("not a page of summaries: {reply:?}")
        };
        let page = GetEventInformationAck::decode(&service_data).unwrap();
        assert!(page.list_of_event_summaries.iter().all(|summary| summary
            .event_time_stamps
            .iter()
            .all(|stamp| matches!(stamp, TimestampValue::DateTime { .. }))));
        seen += page.list_of_event_summaries.len();
        last = page
            .list_of_event_summaries
            .last()
            .map(|summary| summary.object_identifier);
        if !page.more_events {
            break;
        }
    }
    assert_eq!(seen, 9);
}

/// A device whose pages run in a circle - each ends on another object, each
/// says more follow - is read once round, not forever.
#[tokio::test(flavor = "multi_thread")]
async fn paging_stops_when_a_device_goes_round_in_circles() {
    use bacnet_rs::{object::intrinsic::NotifyType, service::event_information::EventSummary};
    let device = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = device.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 1500];
        for answered in 0.. {
            let Ok((length, peer)) = device.recv_from(&mut buffer) else {
                return;
            };
            let (_, npdu_length) = Npdu::decode(&buffer[4..length]).unwrap();
            let Apdu::ConfirmedRequest { invoke_id, .. } =
                Apdu::decode(&buffer[4 + npdu_length..length]).unwrap()
            else {
                continue;
            };
            let summary = EventSummary {
                object_identifier: ObjectIdentifier::new(ObjectType::AnalogInput, answered % 2),
                event_state: EventState::HighLimit,
                acknowledged_transitions: [false, true, true],
                event_time_stamps: [
                    TimestampValue::SequenceNumber(1),
                    TimestampValue::SequenceNumber(0),
                    TimestampValue::SequenceNumber(0),
                ],
                notify_type: NotifyType::Alarm,
                event_enable: [true; 3],
                event_priorities: [100; 3],
            };
            let mut service_data = Vec::new();
            GetEventInformationAck {
                list_of_event_summaries: vec![summary],
                more_events: true,
            }
            .encode(&mut service_data)
            .unwrap();
            let reply = Apdu::ComplexAck {
                segmented: false,
                more_follows: false,
                invoke_id,
                sequence_number: None,
                proposed_window_size: None,
                service_choice: ConfirmedServiceChoice::GetEventInformation,
                service_data,
            };
            let mut payload = Npdu::new().encode();
            payload.extend_from_slice(&reply.encode());
            let mut frame = vec![0x81, 0x0a, 0, (payload.len() + 4) as u8];
            frame.extend_from_slice(&payload);
            device.send_to(&frame, peer).unwrap();
        }
    });

    let client = AsyncBacnetClient::from_config(ClientConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        timeout: Duration::from_secs(1),
        retries: 0,
    })
    .await
    .unwrap();
    let summaries = tokio::time::timeout(
        Duration::from_secs(5),
        client.get_event_information(address),
    )
    .await
    .expect("paging ends")
    .unwrap();
    assert_eq!(summaries.len(), 2);
}

/// Asked of one router, What-Is-Network-Number goes as a unicast, and its
/// answer's number and configured flag are read.
#[tokio::test(flavor = "multi_thread")]
async fn a_router_asked_directly_says_its_network_number() {
    let router = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    router
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let address = router.local_addr().unwrap();
    let answering = std::thread::spawn(move || {
        let mut buffer = [0u8; 64];
        let (length, peer) = router.recv_from(&mut buffer).unwrap();
        // BVLC original-unicast, NPDU with the network-message bit, What-Is.
        assert_eq!(&buffer[..2], &[0x81, 0x0a]);
        assert_eq!(&buffer[4..7], &[0x01, 0x80, 0x12]);
        assert_eq!(length, 7);
        // Network-Number-Is: network 26001, configured.
        let reply = [0x81, 0x0a, 0x00, 0x0a, 0x01, 0x80, 0x13, 0x65, 0x91, 0x01];
        router.send_to(&reply, peer).unwrap();
    });

    let client = AsyncBacnetClient::from_config(ClientConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        timeout: Duration::from_millis(500),
        retries: 0,
    })
    .await
    .unwrap();
    let answers = client.what_is_network_number_to(address).await.unwrap();
    answering.join().unwrap();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].network, 26001);
    assert!(answers[0].configured);
}
