//! Concurrent asynchronous BACnet/IP client.
//!
//! One endpoint task owns the UDP socket, receives every datagram, and routes
//! confirmed responses to callers through per-transaction one-shot channels.
//! Cloned client handles submit commands through a bounded queue; requests are
//! sent without waiting for earlier transactions to complete.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
    time::{sleep_until, Instant},
};

use crate::{
    app::{Apdu, MaxApduSize, MaxSegments},
    network::Npdu,
    object::{ObjectIdentifier, ObjectType, PropertyIdentifier},
    property::{encode_property_value, PropertyValue},
    service::{
        AbortReason, ConfirmedServiceChoice, PropertyReference, ReadAccessSpecification,
        ReadPropertyMultipleRequest, ReadPropertyMultipleResponse, ReadPropertyRequest,
        ReadPropertyResponse, WritePropertyRequest,
    },
};

use super::{
    decode_object_list_value, property_read_result, BacnetTarget, ClientConfig, ClientError,
    ObjectSnapshot, PropertyReadResult, BVLC_ORIGINAL_UNICAST,
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
}

enum EndpointCommand {
    Confirmed {
        target: BacnetTarget,
        service_choice: ConfirmedServiceChoice,
        service_data: Vec<u8>,
        response: oneshot::Sender<Result<Vec<u8>, ClientError>>,
    },
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
            next_invoke_id: 0,
            timeout,
            retries,
            receive_buffer: vec![0; MAX_BACNET_IP_FRAME],
        }
    }

    async fn run(mut self) {
        loop {
            self.remove_cancelled();
            let next_deadline = self.pending.values().map(|pending| pending.deadline).min();
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
        let EndpointCommand::Confirmed {
            target,
            service_choice,
            service_data,
            response,
        } = command;
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
        let Some(apdu) = decode_response_apdu(&self.receive_buffer[..length]) else {
            return;
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

    fn remove_cancelled(&mut self) {
        self.pending
            .retain(|_, pending| !pending.response.is_closed());
    }

    fn fail_all<F>(&mut self, mut error: F)
    where
        F: FnMut() -> ClientError,
    {
        for (_, pending) in self.pending.drain() {
            let _ = pending.response.send(Err(error()));
        }
    }
}

fn build_confirmed_frame(
    target: &BacnetTarget,
    invoke_id: u8,
    service_choice: ConfirmedServiceChoice,
    service_data: Vec<u8>,
) -> Vec<u8> {
    let apdu = Apdu::ConfirmedRequest {
        segmented: false,
        more_follows: false,
        segmented_response_accepted: true,
        max_segments: MaxSegments::Unspecified,
        max_response_size: MaxApduSize::Up1476,
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

fn decode_response_apdu(frame: &[u8]) -> Option<Apdu> {
    if frame.len() < 6 || frame[0] != 0x81 {
        return None;
    }
    let frame_length = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    if frame_length != frame.len() {
        return None;
    }
    let npdu_start = if frame[1] == 0x04 {
        if frame.len() < 12 {
            return None;
        }
        10
    } else {
        4
    };
    let (_, npdu_length) = Npdu::decode(&frame[npdu_start..]).ok()?;
    Apdu::decode(frame.get(npdu_start + npdu_length..)?).ok()
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
