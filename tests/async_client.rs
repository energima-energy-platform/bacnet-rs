#![cfg(feature = "async")]

use std::{sync::Arc, time::Duration};

use bacnet_rs::{
    app::Apdu,
    client::{AsyncBacnetClient, ClientConfig},
    network::Npdu,
    object::{
        database::ObjectDatabase, AnalogValue, Device, ObjectIdentifier, ObjectType,
        PropertyIdentifier,
    },
    property::PropertyValue,
    server::AsyncBacnetIpServer,
    service::{ConfirmedServiceChoice, ReadPropertyRequest, ReadPropertyResponse},
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
