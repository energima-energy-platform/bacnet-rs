#![cfg(feature = "async")]

//! A recipient enrolling itself and catching up on alarm state, against the
//! stack's own server.

use std::{sync::Arc, time::Duration};

use bacnet_rs::{
    client::{AsyncBacnetClient, ClientConfig, ClientError},
    event::EventEngine,
    object::{
        database::ObjectDatabase, intrinsic::EventTransitionBits, BinaryPV, BinaryValue, Device,
        EventState, NotificationClass, ObjectIdentifier, ObjectType, PropertyIdentifier,
    },
    property::{BacnetAddress, DestinationValue, PropertyValue, Recipient, TimestampValue},
    server::AsyncBacnetIpServer,
    service::acknowledge_alarm::AcknowledgeAlarmRequest,
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
