//! The segmentation cases a cooperative peer will not produce on demand: a
//! lost acknowledgement, a gap in the sequence, a transfer that will not end,
//! a peer that cannot receive segments. `interop_segmentation.rs` covers the
//! happy path against a real stack.

#![cfg(feature = "async")]

use std::{net::SocketAddr, time::Duration};

use bacnet_rs::{
    app::Apdu,
    client::{AsyncBacnetClient, BacnetTarget, ClientConfig, ClientError, DeviceCapabilities},
    network::Npdu,
    object::{ObjectIdentifier, ObjectType, PropertyIdentifier, Segmentation},
    property::PropertyValue,
    service::{
        AbortReason, ConfirmedServiceChoice, PropertyReference, ReadAccessSpecification,
        ReadPropertyMultipleRequest, ReadPropertyRequest, ReadPropertyResponse,
    },
};
use tokio::net::UdpSocket;

fn wrap(apdu: &Apdu) -> Vec<u8> {
    let mut payload = Npdu::new().encode();
    payload.extend_from_slice(&apdu.encode());
    let length = (payload.len() + 4) as u16;
    let mut frame = vec![0x81, 0x0A, (length >> 8) as u8, length as u8];
    frame.extend_from_slice(&payload);
    frame
}

fn decode_apdu(frame: &[u8]) -> Apdu {
    let (_, npdu_length) = Npdu::decode(&frame[4..]).expect("decode NPDU");
    Apdu::decode(&frame[4 + npdu_length..]).expect("decode APDU")
}

/// One segment of a ComplexAck answering `invoke_id`.
fn segment(invoke_id: u8, sequence: u8, more_follows: bool, data: &[u8]) -> Vec<u8> {
    wrap(&Apdu::ComplexAck {
        segmented: true,
        more_follows,
        invoke_id,
        sequence_number: Some(sequence),
        proposed_window_size: Some(1),
        service_choice: ConfirmedServiceChoice::ReadProperty,
        service_data: data.to_vec(),
    })
}

/// Long enough to be worth splitting, and decodable only if reassembled in
/// order.
fn encoded_response(count: usize) -> Vec<u8> {
    let values: Vec<PropertyValue> = (0..count).map(|n| PropertyValue::Real(n as f32)).collect();
    let response = ReadPropertyResponse::new(
        ObjectIdentifier::new(ObjectType::AnalogValue, 1),
        PropertyIdentifier::PriorityArray,
        values,
    );
    let mut encoded = Vec::new();
    response.encode(&mut encoded).expect("encode");
    encoded
}

async fn client(timeout: Duration) -> AsyncBacnetClient {
    AsyncBacnetClient::from_config(ClientConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        timeout,
        retries: 2,
    })
    .await
    .expect("bind client")
}

/// Read whatever the client sends next, as an APDU.
async fn next_apdu(device: &UdpSocket, buffer: &mut [u8]) -> (Apdu, SocketAddr) {
    let (length, from) = device.recv_from(buffer).await.expect("receive");
    (decode_apdu(&buffer[..length]), from)
}

fn ack_of(apdu: &Apdu) -> (u8, bool) {
    match apdu {
        Apdu::SegmentAck {
            sequence_number,
            negative,
            ..
        } => (*sequence_number, *negative),
        other => panic!("expected a SegmentAck, got {other:?}"),
    }
}

fn invoke_id_of(apdu: &Apdu) -> u8 {
    match apdu {
        Apdu::ConfirmedRequest { invoke_id, .. } => *invoke_id,
        other => panic!("expected a ConfirmedRequest, got {other:?}"),
    }
}

/// A lost acknowledgement means the device repeats a segment. Repeat the ack,
/// and do *not* append it twice - that would decode to nonsense far from
/// here.
#[tokio::test]
async fn a_repeated_segment_is_acknowledged_again_and_not_appended() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();
    let encoded = encoded_response(16);
    let (first, second) = encoded.split_at(encoded.len() / 2);
    let first = first.to_vec();
    let second = second.to_vec();

    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 2048];
        let (request, from) = next_apdu(&device, &mut buffer).await;
        let invoke_id = invoke_id_of(&request);

        device
            .send_to(&segment(invoke_id, 0, true, &first), from)
            .await
            .unwrap();
        let (ack, _) = next_apdu(&device, &mut buffer).await;
        assert_eq!(ack_of(&ack), (0, false));

        // The device never saw that acknowledgement, so it says segment zero
        // again.
        device
            .send_to(&segment(invoke_id, 0, true, &first), from)
            .await
            .unwrap();
        let (repeat, _) = next_apdu(&device, &mut buffer).await;
        assert_eq!(
            ack_of(&repeat),
            (0, false),
            "a repeated segment earns the same acknowledgement again"
        );

        device
            .send_to(&segment(invoke_id, 1, false, &second), from)
            .await
            .unwrap();
        let (final_ack, _) = next_apdu(&device, &mut buffer).await;
        assert_eq!(ack_of(&final_ack), (1, false));
    });

    let values = client(Duration::from_secs(2))
        .await
        .read_property(
            BacnetTarget::new(address),
            ObjectIdentifier::new(ObjectType::AnalogValue, 1),
            PropertyIdentifier::PriorityArray,
        )
        .await
        .expect("the response should reassemble");

    assert_eq!(
        values.len(),
        16,
        "the duplicate must not have been appended a second time"
    );
    responder.await.unwrap();
}

/// A gap is answered by naming the last in-order segment, so the device
/// resumes rather than starting over.
#[tokio::test]
async fn a_gap_asks_for_the_missing_segment_rather_than_the_whole_transfer() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();
    let encoded = encoded_response(24);
    let chunk = encoded.len() / 3;
    let parts: Vec<Vec<u8>> = vec![
        encoded[..chunk].to_vec(),
        encoded[chunk..chunk * 2].to_vec(),
        encoded[chunk * 2..].to_vec(),
    ];

    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 2048];
        let (request, from) = next_apdu(&device, &mut buffer).await;
        let invoke_id = invoke_id_of(&request);

        device
            .send_to(&segment(invoke_id, 0, true, &parts[0]), from)
            .await
            .unwrap();
        let (ack, _) = next_apdu(&device, &mut buffer).await;
        assert_eq!(ack_of(&ack), (0, false));

        // Segment one goes missing and two arrives in its place.
        device
            .send_to(&segment(invoke_id, 2, true, &parts[2]), from)
            .await
            .unwrap();
        let (nak, _) = next_apdu(&device, &mut buffer).await;
        assert_eq!(
            ack_of(&nak),
            (0, true),
            "the gap should be reported against the last in-order segment"
        );

        for (sequence, part) in parts.iter().enumerate().skip(1) {
            let last = sequence == parts.len() - 1;
            device
                .send_to(&segment(invoke_id, sequence as u8, !last, part), from)
                .await
                .unwrap();
            let (ack, _) = next_apdu(&device, &mut buffer).await;
            assert_eq!(ack_of(&ack), (sequence as u8, false));
        }
    });

    let values = client(Duration::from_secs(2))
        .await
        .read_property(
            BacnetTarget::new(address),
            ObjectIdentifier::new(ObjectType::AnalogValue, 1),
            PropertyIdentifier::PriorityArray,
        )
        .await
        .expect("the retransmitted segment should complete the response");

    assert_eq!(values.len(), 24);
    responder.await.unwrap();
}

/// A device that ignores the `max_segments` we stated is cut off rather than
/// allowed to grow the buffer without limit.
#[tokio::test]
async fn a_transfer_past_the_segment_limit_is_aborted() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();

    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 2048];
        let (request, from) = next_apdu(&device, &mut buffer).await;
        let invoke_id = invoke_id_of(&request);
        let filler = vec![0_u8; 32];

        // One past the advertised limit, every one claiming more to come.
        for sequence in 0..=64_u8 {
            device
                .send_to(&segment(invoke_id, sequence, true, &filler), from)
                .await
                .unwrap();
            let (reply, _) = next_apdu(&device, &mut buffer).await;
            if let Apdu::Abort { abort_reason, .. } = reply {
                return abort_reason;
            }
        }
        panic!("the client kept accepting segments past its own limit");
    });

    let error = client(Duration::from_secs(2))
        .await
        .read_property(
            BacnetTarget::new(address),
            ObjectIdentifier::new(ObjectType::AnalogValue, 1),
            PropertyIdentifier::PriorityArray,
        )
        .await
        .expect_err("an endless transfer should not succeed");

    assert!(
        matches!(error, ClientError::Abort(AbortReason::BufferOverflow)),
        "expected a buffer-overflow abort, got {error:?}"
    );
    assert_eq!(
        responder.await.unwrap(),
        AbortReason::BufferOverflow,
        "the device should be told why the transfer stopped"
    );
}

/// Refused from the peer's advertised capabilities rather than on the wire:
/// the exchange would end the same way, without the round trip.
#[tokio::test]
async fn an_oversized_request_to_a_peer_that_cannot_segment_is_refused() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();

    let specifications: Vec<ReadAccessSpecification> = (0..400)
        .map(|instance| ReadAccessSpecification {
            object_identifier: ObjectIdentifier::new(ObjectType::AnalogValue, instance),
            property_references: vec![PropertyReference {
                property_identifier: PropertyIdentifier::PresentValue,
                property_array_index: None,
            }],
        })
        .collect();

    let target = BacnetTarget {
        address,
        route: None,
        capabilities: Some(DeviceCapabilities {
            max_apdu: 1476,
            segmentation: Segmentation::NoSegmentation,
        }),
    };

    let error = client(Duration::from_millis(300))
        .await
        .read_property_multiple(target, &ReadPropertyMultipleRequest::new(specifications))
        .await
        .expect_err("a request this peer cannot receive should be refused");

    assert!(
        matches!(
            error,
            ClientError::Abort(AbortReason::SegmentationNotSupported)
        ),
        "expected a segmentation-not-supported abort, got {error:?}"
    );

    // And nothing should have been put on the wire to find that out.
    let mut buffer = [0_u8; 2048];
    assert!(
        tokio::time::timeout(Duration::from_millis(200), device.recv_from(&mut buffer))
            .await
            .is_err(),
        "no request should have been sent"
    );
}

/// The segmented path must not capture the ordinary one.
#[tokio::test]
async fn a_request_that_fits_is_not_segmented() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();

    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 2048];
        let (request, from) = next_apdu(&device, &mut buffer).await;
        let Apdu::ConfirmedRequest {
            segmented,
            invoke_id,
            service_data,
            ..
        } = request
        else {
            panic!("expected a ConfirmedRequest")
        };
        assert!(!segmented, "a small request must go out unsegmented");

        let request = ReadPropertyRequest::decode(&service_data).expect("decode");
        let mut encoded = Vec::new();
        ReadPropertyResponse::new(
            request.object_identifier,
            request.property_identifier,
            vec![PropertyValue::Real(21.5)],
        )
        .encode(&mut encoded)
        .expect("encode");
        device
            .send_to(
                &wrap(&Apdu::ComplexAck {
                    segmented: false,
                    more_follows: false,
                    invoke_id,
                    sequence_number: None,
                    proposed_window_size: None,
                    service_choice: ConfirmedServiceChoice::ReadProperty,
                    service_data: encoded,
                }),
                from,
            )
            .await
            .unwrap();
    });

    let values = client(Duration::from_secs(2))
        .await
        .read_property(
            BacnetTarget::new(address),
            ObjectIdentifier::new(ObjectType::AnalogValue, 1),
            PropertyIdentifier::PresentValue,
        )
        .await
        .expect("an ordinary read should still work");

    assert_eq!(values, vec![PropertyValue::Real(21.5)]);
    responder.await.unwrap();
}
