#![cfg(feature = "async")]

//! How an arriving COV notification finds the subscription that wanted it.
//!
//! The routing key is what the notification asserts about itself - the device
//! that sent it and the object it is about - and deliberately not the
//! subscriber process identifier it echoes. That number is chosen by the
//! subscriber, so two subscriptions are free to pick the same one; routing on
//! it means the second silently displaces the first in the routing table, and
//! the first object then stops reporting with nothing anywhere to say so. A
//! caller cannot detect that from the outside, which is what makes it worth
//! pinning down here.

use std::{net::SocketAddr, time::Duration};

use bacnet_rs::{
    app::Apdu,
    client::{AsyncBacnetClient, ClientConfig, CovSubscription},
    network::Npdu,
    object::{ObjectIdentifier, ObjectType, PropertyIdentifier},
    property::PropertyValue,
    service::{
        cov_notification::{CovNotification, CovPropertyValue},
        ConfirmedServiceChoice, UnconfirmedServiceChoice,
    },
};
use tokio::net::UdpSocket;

const DEVICE: u32 = 4001;
/// Long enough that a passing test never waits it out, short enough that a
/// failing one does not hold the suite up.
const PATIENCE: Duration = Duration::from_secs(2);
/// How long to wait before concluding nothing is coming. Only ever spent by
/// the tests that assert silence.
const SILENCE: Duration = Duration::from_millis(300);

fn wrap(payload: Vec<u8>) -> Vec<u8> {
    let length = payload.len() + 4;
    let mut frame = vec![0x81, 0x0A, (length >> 8) as u8, length as u8];
    frame.extend_from_slice(&payload);
    frame
}

/// The SimpleAck a device answers a SubscribeCOV with.
fn subscribe_ack(request: &[u8]) -> Vec<u8> {
    let (_, npdu_length) = Npdu::decode(&request[4..]).expect("decode NPDU");
    let Apdu::ConfirmedRequest { invoke_id, .. } =
        Apdu::decode(&request[4 + npdu_length..]).expect("decode APDU")
    else {
        panic!("expected a confirmed request")
    };
    let mut payload = Npdu::new().encode();
    payload.extend_from_slice(
        &Apdu::SimpleAck {
            invoke_id,
            service_choice: ConfirmedServiceChoice::SubscribeCOV as u8,
        }
        .encode(),
    );
    wrap(payload)
}

/// An unconfirmed COV notification, as a device puts one on the wire.
///
/// `process_id` is a parameter precisely because routing must not depend on
/// it: several tests here pass one that matches nothing.
fn notification(process_id: u32, device: u32, object: ObjectIdentifier, value: f32) -> Vec<u8> {
    let notification = CovNotification {
        subscriber_process_identifier: process_id,
        initiating_device: ObjectIdentifier::new(ObjectType::Device, device),
        monitored_object: object,
        time_remaining: 3600,
        list_of_values: vec![CovPropertyValue::new(
            PropertyIdentifier::PresentValue,
            PropertyValue::Real(value),
        )],
    };
    let mut service_data = Vec::new();
    notification.encode(&mut service_data).expect("encode");

    let mut payload = Npdu::new().encode();
    payload.extend_from_slice(&[
        0x10,
        UnconfirmedServiceChoice::UnconfirmedCOVNotification as u8,
    ]);
    payload.extend_from_slice(&service_data);
    wrap(payload)
}

async fn client() -> AsyncBacnetClient {
    AsyncBacnetClient::from_config(ClientConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        timeout: PATIENCE,
        retries: 0,
    })
    .await
    .expect("bind client")
}

fn object(instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::AnalogValue, instance)
}

/// A device that acknowledges `count` subscribe requests and then stops
/// reading, leaving the socket free for the test to send notifications from.
fn acknowledging_device(device: UdpSocket, count: usize) -> tokio::task::JoinHandle<UdpSocket> {
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        for _ in 0..count {
            let (length, source) = device.recv_from(&mut buffer).await.expect("a subscribe");
            device
                .send_to(&subscribe_ack(&buffer[..length]), source)
                .await
                .expect("ack the subscribe");
        }
        device
    })
}

async fn subscribed(
    client: &AsyncBacnetClient,
    address: SocketAddr,
    process_id: u32,
    object: ObjectIdentifier,
) -> CovSubscription {
    client
        .subscribe_cov(address, DEVICE, process_id, object, false, Some(3600))
        .await
        .unwrap_or_else(|error| panic!("subscribe to {object:?}: {error}"))
}

/// The regression this keying exists for. Both subscriptions deliberately ask
/// with the same process identifier; when that number was the routing key, the
/// second evicted the first and object 1 went silent for good.
#[tokio::test]
async fn two_subscriptions_sharing_a_process_identifier_both_receive() {
    let device = UdpSocket::bind("127.0.0.1:0").await.expect("bind device");
    let address = device.local_addr().expect("device address");
    let responder = acknowledging_device(device, 2);
    let client = client().await;

    let mut first = subscribed(&client, address, 7, object(1)).await;
    let mut second = subscribed(&client, address, 7, object(2)).await;
    let device = responder.await.expect("responder");

    for (object, value) in [(object(1), 21.5), (object(2), 19.0)] {
        device
            .send_to(&notification(7, DEVICE, object, value), client.local_addr())
            .await
            .expect("send a notification");
    }

    let one = tokio::time::timeout(PATIENCE, first.recv())
        .await
        .expect("object 1 must still be routed to after object 2 subscribed")
        .expect("a notification");
    assert_eq!(one.monitored_object, object(1));

    let two = tokio::time::timeout(PATIENCE, second.recv())
        .await
        .expect("object 2 must be routed to")
        .expect("a notification");
    assert_eq!(two.monitored_object, object(2));
}

/// The identity wins over the echoed number. A device that returns a process
/// identifier we never sent - or none we recognise - is still telling us about
/// an object we subscribed to, and that reading is not ours to throw away.
#[tokio::test]
async fn a_notification_routes_by_identity_even_when_the_process_identifier_is_wrong() {
    let device = UdpSocket::bind("127.0.0.1:0").await.expect("bind device");
    let address = device.local_addr().expect("device address");
    let responder = acknowledging_device(device, 1);
    let client = client().await;

    let mut subscription = subscribed(&client, address, 7, object(1)).await;
    let device = responder.await.expect("responder");

    device
        .send_to(
            &notification(999_999, DEVICE, object(1), 21.5),
            client.local_addr(),
        )
        .await
        .expect("send a notification");

    let received = tokio::time::timeout(PATIENCE, subscription.recv())
        .await
        .expect("the object was subscribed, so its notification belongs here")
        .expect("a notification");
    assert_eq!(received.monitored_object, object(1));
}

/// A notification about an object nobody subscribed to has nowhere honest to
/// go. Delivering it to whichever channel happened to share its process
/// identifier is what this keying exists to prevent.
#[tokio::test]
async fn a_notification_about_an_unsubscribed_object_is_not_delivered() {
    let device = UdpSocket::bind("127.0.0.1:0").await.expect("bind device");
    let address = device.local_addr().expect("device address");
    let responder = acknowledging_device(device, 1);
    let client = client().await;

    let mut subscription = subscribed(&client, address, 7, object(1)).await;
    let device = responder.await.expect("responder");

    // Same device, same process identifier, different object.
    device
        .send_to(
            &notification(7, DEVICE, object(2), 19.0),
            client.local_addr(),
        )
        .await
        .expect("send a notification");

    assert!(
        tokio::time::timeout(SILENCE, subscription.recv())
            .await
            .is_err(),
        "a notification about object 2 must not arrive on object 1's subscription"
    );
}

/// And the same for a notification claiming a device this subscription is not
/// talking to. Object instance numbers repeat between devices, so the object
/// alone cannot place a notification.
#[tokio::test]
async fn a_notification_from_another_device_is_not_delivered() {
    let device = UdpSocket::bind("127.0.0.1:0").await.expect("bind device");
    let address = device.local_addr().expect("device address");
    let responder = acknowledging_device(device, 1);
    let client = client().await;

    let mut subscription = subscribed(&client, address, 7, object(1)).await;
    let device = responder.await.expect("responder");

    device
        .send_to(
            &notification(7, DEVICE + 1, object(1), 19.0),
            client.local_addr(),
        )
        .await
        .expect("send a notification");

    assert!(
        tokio::time::timeout(SILENCE, subscription.recv())
            .await
            .is_err(),
        "a notification claiming another device must not be delivered here"
    );
}

/// A client whose requests give up quickly, for the tests that deliberately
/// let one time out.
async fn impatient_client() -> AsyncBacnetClient {
    AsyncBacnetClient::from_config(ClientConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        timeout: Duration::from_millis(200),
        retries: 0,
    })
    .await
    .expect("bind client")
}

/// The regression this exists for, and the expensive one to diagnose in the
/// field: a renewal that fails must not cost the caller the subscription it
/// was refreshing.
///
/// Renewing used to go through `subscribe_cov`, which registers its new
/// channel under the subscription's routing key *before* the request goes on
/// the wire. A renewal that then timed out - a controller briefly unreachable
/// is the ordinary case - had already evicted the live channel, so `recv`
/// returned `None` for ever after. The subscription looked healthy from the
/// device's side and was silent from ours, and nothing in between said so.
#[tokio::test]
async fn a_renewal_that_fails_leaves_the_subscription_receiving() {
    let device = UdpSocket::bind("127.0.0.1:0").await.expect("bind device");
    let address = device.local_addr().expect("device address");
    // One ack, for the initial subscribe. The renewal that follows is never
    // answered, which is the whole point.
    let responder = acknowledging_device(device, 1);
    let client = impatient_client().await;

    let mut subscription = subscribed(&client, address, 7, object(1)).await;
    let device = responder.await.expect("responder");

    assert!(
        subscription.renew(false, Some(3600)).await.is_err(),
        "the device is not answering, so the renewal must be reported as failed"
    );

    device
        .send_to(
            &notification(7, DEVICE, object(1), 21.5),
            client.local_addr(),
        )
        .await
        .expect("send a notification");

    let received = tokio::time::timeout(PATIENCE, subscription.recv())
        .await
        .expect("a failed renewal must not silence the subscription it refreshes")
        .expect("the channel must still be open");
    assert_eq!(received.monitored_object, object(1));
}

/// And the ordinary path: a renewal that succeeds is invisible to the caller,
/// who keeps receiving on the channel it already had.
#[tokio::test]
async fn a_renewal_that_succeeds_keeps_the_same_channel() {
    let device = UdpSocket::bind("127.0.0.1:0").await.expect("bind device");
    let address = device.local_addr().expect("device address");
    let responder = acknowledging_device(device, 2);
    let client = client().await;

    let mut subscription = subscribed(&client, address, 7, object(1)).await;
    subscription
        .renew(false, Some(3600))
        .await
        .expect("the device acknowledged the renewal");
    let device = responder.await.expect("responder");

    device
        .send_to(
            &notification(7, DEVICE, object(1), 19.0),
            client.local_addr(),
        )
        .await
        .expect("send a notification");

    let received = tokio::time::timeout(PATIENCE, subscription.recv())
        .await
        .expect("a renewed subscription must go on reporting")
        .expect("a notification");
    assert_eq!(received.monitored_object, object(1));
}
