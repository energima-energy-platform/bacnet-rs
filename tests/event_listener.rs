#![cfg(feature = "async")]

//! Event notifications arriving at a client: delivered to every listener,
//! acknowledged as the service they came as, and a retransmission after a lost
//! acknowledgement delivered only once.

use std::time::Duration;

use bacnet_rs::{
    app::{Apdu, MaxApduSize, MaxSegments},
    client::{AsyncBacnetClient, ClientConfig},
    network::Npdu,
    object::{intrinsic::NotifyType, EventState, ObjectIdentifier, ObjectType},
    property::TimestampValue,
    service::{
        event_notification::{
            EventNotification, NotificationParameters, PropertyStates, StatusFlags,
        },
        ConfirmedServiceChoice, RejectReason, UnconfirmedServiceChoice,
    },
};
use tokio::{net::UdpSocket, time::timeout};

const PATIENCE: Duration = Duration::from_secs(2);
const SILENCE: Duration = Duration::from_millis(300);

async fn client() -> AsyncBacnetClient {
    AsyncBacnetClient::from_config(ClientConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        timeout: Duration::from_secs(1),
        retries: 0,
    })
    .await
    .unwrap()
}

fn event(sequence: u32) -> EventNotification {
    EventNotification {
        process_identifier: 0xbac8,
        initiating_device: ObjectIdentifier::new(ObjectType::Device, 3016),
        event_object: ObjectIdentifier::new(ObjectType::BinaryInput, 1),
        timestamp: TimestampValue::SequenceNumber(sequence),
        notification_class: 1,
        priority: 100,
        notify_type: NotifyType::Alarm,
        ack_required: true,
        from_state: EventState::Normal,
        to_state: EventState::Offnormal,
        message_text: None,
        parameters: NotificationParameters::ChangeOfState {
            new_state: PropertyStates::BinaryValue(true),
            status_flags: StatusFlags::for_event_state(EventState::Offnormal, false),
        },
    }
}

fn frame(apdu: Apdu) -> Vec<u8> {
    let mut payload = Npdu::new().encode();
    payload.extend_from_slice(&apdu.encode());
    let length = payload.len() + 4;
    let mut frame = vec![0x81, 0x0A, (length >> 8) as u8, length as u8];
    frame.extend_from_slice(&payload);
    frame
}

fn confirmed(invoke_id: u8, notification: &EventNotification) -> Vec<u8> {
    let mut service_data = Vec::new();
    notification.encode(&mut service_data).unwrap();
    frame(Apdu::ConfirmedRequest {
        segmented: false,
        more_follows: false,
        segmented_response_accepted: false,
        max_segments: MaxSegments::Unspecified,
        max_response_size: MaxApduSize::Up480,
        invoke_id,
        sequence_number: None,
        proposed_window_size: None,
        service_choice: ConfirmedServiceChoice::ConfirmedEventNotification,
        service_data,
    })
}

fn unconfirmed(notification: &EventNotification) -> Vec<u8> {
    let mut service_data = Vec::new();
    notification.encode(&mut service_data).unwrap();
    frame(Apdu::UnconfirmedRequest {
        service_choice: UnconfirmedServiceChoice::UnconfirmedEventNotification,
        service_data,
    })
}

async fn reply(device: &UdpSocket) -> Apdu {
    let mut buffer = [0u8; 1500];
    let (length, _) = timeout(PATIENCE, device.recv_from(&mut buffer))
        .await
        .expect("a reply")
        .unwrap();
    let (_, npdu_length) = Npdu::decode(&buffer[4..length]).unwrap();
    Apdu::decode(&buffer[4 + npdu_length..length]).unwrap()
}

#[tokio::test]
async fn a_confirmed_notification_is_delivered_and_acknowledged() {
    let client = client().await;
    let mut listener = client.event_notifications().await.unwrap();
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    device
        .send_to(&confirmed(7, &event(1)), client.local_addr())
        .await
        .unwrap();

    let received = timeout(PATIENCE, listener.recv()).await.unwrap().unwrap();
    assert!(received.confirmed);
    assert_eq!(received.notification, event(1));
    assert_eq!(received.source, device.local_addr().unwrap());
    assert!(matches!(
        reply(&device).await,
        Apdu::SimpleAck { invoke_id: 7, service_choice } if service_choice == ConfirmedServiceChoice::ConfirmedEventNotification as u8
    ));
}

#[tokio::test]
async fn a_retransmission_is_acknowledged_but_delivered_once() {
    let client = client().await;
    let mut listener = client.event_notifications().await.unwrap();
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    for _ in 0..2 {
        device
            .send_to(&confirmed(9, &event(1)), client.local_addr())
            .await
            .unwrap();
        assert!(matches!(
            reply(&device).await,
            Apdu::SimpleAck { invoke_id: 9, .. }
        ));
    }
    // A new notification reusing the invoke id is a different one.
    device
        .send_to(&confirmed(9, &event(2)), client.local_addr())
        .await
        .unwrap();
    assert!(matches!(
        reply(&device).await,
        Apdu::SimpleAck { invoke_id: 9, .. }
    ));

    let first = timeout(PATIENCE, listener.recv()).await.unwrap().unwrap();
    let second = timeout(PATIENCE, listener.recv()).await.unwrap().unwrap();
    assert_eq!(first.notification, event(1));
    assert_eq!(second.notification, event(2));
    assert!(timeout(SILENCE, listener.recv()).await.is_err());
}

#[tokio::test]
async fn with_no_listener_a_confirmed_notification_is_rejected() {
    let client = client().await;
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    device
        .send_to(&confirmed(3, &event(1)), client.local_addr())
        .await
        .unwrap();

    assert!(matches!(
        reply(&device).await,
        Apdu::Reject {
            invoke_id: 3,
            reject_reason: RejectReason::UnrecognizedService
        }
    ));
}

#[tokio::test]
async fn every_listener_hears_an_unconfirmed_notification() {
    let client = client().await;
    let mut first = client.event_notifications().await.unwrap();
    let mut second = client.event_notifications().await.unwrap();
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    device
        .send_to(&unconfirmed(&event(4)), client.local_addr())
        .await
        .unwrap();

    for listener in [&mut first, &mut second] {
        let received = timeout(PATIENCE, listener.recv()).await.unwrap().unwrap();
        assert!(!received.confirmed);
        assert_eq!(received.notification, event(4));
    }
}
