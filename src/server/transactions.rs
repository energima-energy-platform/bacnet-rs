//! Confirmed requests a device has sent, waiting for their answer.
//!
//! A device that sends a ConfirmedEventNotification or ConfirmedCOVNotification
//! is the requester in a transaction: it waits APDU_Timeout for the reply and
//! sends again up to Number_Of_APDU_Retries times before giving up (135-2020
//! 5.4.4). The replies arrive on the serve loop, so the dispatcher records them
//! here, and whoever owns the clock asks [`Notifier::poll`](super::Notifier::poll)
//! what has become of each.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use crate::{
    object::{database::ObjectDatabase, PropertyIdentifier, PropertyValue},
    service::ConfirmedServiceChoice,
};

/// What became of one confirmed request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The peer answered with the SimpleACK the service earns.
    Acknowledged,
    /// The peer answered with an Error, Reject or Abort. Not sent again.
    Refused,
    /// No answer within APDU_Timeout, so it went out again. `attempt` counts
    /// from 1 for the first retry.
    Retried { attempt: u8 },
    /// Still no answer after Number_Of_APDU_Retries.
    GaveUp,
}

/// One request and its outcome, as [`Notifier::poll`](super::Notifier::poll)
/// reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub destination: SocketAddr,
    pub invoke_id: u8,
    pub service: ConfirmedServiceChoice,
    pub outcome: Outcome,
}

/// The device's outstanding confirmed requests. A cheap handle, shared by the
/// notifier that sends them and the dispatcher that receives their replies.
#[derive(Clone)]
pub struct Transactions {
    database: Arc<ObjectDatabase>,
    table: Arc<Mutex<Table>>,
}

#[derive(Default)]
struct Table {
    pending: Vec<Pending>,
    /// Answered since the last poll.
    answered: Vec<Transaction>,
}

struct Pending {
    destination: SocketAddr,
    invoke_id: u8,
    service: ConfirmedServiceChoice,
    frame: Vec<u8>,
    sent_at: Instant,
    retries: u8,
}

/// What to send again, and what to report.
pub(super) struct Due {
    pub resend: Vec<(Vec<u8>, SocketAddr)>,
    pub transactions: Vec<Transaction>,
}

impl Transactions {
    /// Timeout and retries are read from `database`'s Device object each time,
    /// so a client that writes them changes what happens next.
    pub fn new(database: Arc<ObjectDatabase>) -> Self {
        Self {
            database,
            table: Arc::default(),
        }
    }

    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many requests are waiting for an answer.
    pub fn outstanding(&self) -> usize {
        self.table().pending.len()
    }

    /// The service of the request `invoke_id` is waiting on an answer from
    /// `destination`, if one is.
    pub fn pending_service(
        &self,
        destination: SocketAddr,
        invoke_id: u8,
    ) -> Option<ConfirmedServiceChoice> {
        self.table()
            .pending
            .iter()
            .find(|pending| pending.destination == destination && pending.invoke_id == invoke_id)
            .map(|pending| pending.service)
    }

    /// Whether an invoke id is waiting on an answer from `destination`, so the
    /// notifier can pick another.
    pub(super) fn in_flight(&self, destination: SocketAddr, invoke_id: u8) -> bool {
        self.table()
            .pending
            .iter()
            .any(|pending| pending.destination == destination && pending.invoke_id == invoke_id)
    }

    pub(super) fn register(
        &self,
        destination: SocketAddr,
        invoke_id: u8,
        service: ConfirmedServiceChoice,
        frame: Vec<u8>,
        now: Instant,
    ) {
        self.table().pending.push(Pending {
            destination,
            invoke_id,
            service,
            frame,
            sent_at: now,
            retries: 0,
        });
    }

    /// Forget a request that never went out.
    pub(super) fn withdraw(&self, destination: SocketAddr, invoke_id: u8) {
        self.table()
            .pending
            .retain(|pending| pending.destination != destination || pending.invoke_id != invoke_id);
    }

    /// A reply from `source` to `invoke_id`.
    ///
    /// Matched by peer and invoke id, which is what identifies a transaction
    /// (135-2020 5.4). A reply naming another service than the request's still
    /// ends it: a peer that gets the service choice wrong has answered all the
    /// same, and sending again would only repeat what it already has.
    pub(super) fn answer(&self, source: SocketAddr, invoke_id: u8, outcome: Outcome) {
        let mut table = self.table();
        let Some(index) = table
            .pending
            .iter()
            .position(|pending| pending.destination == source && pending.invoke_id == invoke_id)
        else {
            return;
        };
        let pending = table.pending.remove(index);
        table.answered.push(Transaction {
            destination: pending.destination,
            invoke_id: pending.invoke_id,
            service: pending.service,
            outcome,
        });
    }

    pub(super) fn due(&self, now: Instant) -> Due {
        let (timeout, retries) = self.policy();
        let mut table = self.table();
        let mut transactions = std::mem::take(&mut table.answered);
        let mut resend = Vec::new();
        table.pending.retain_mut(|pending| {
            if now.saturating_duration_since(pending.sent_at) < timeout {
                return true;
            }
            let report = |outcome| Transaction {
                destination: pending.destination,
                invoke_id: pending.invoke_id,
                service: pending.service,
                outcome,
            };
            if pending.retries >= retries {
                transactions.push(report(Outcome::GaveUp));
                return false;
            }
            pending.retries += 1;
            pending.sent_at = now;
            resend.push((pending.frame.clone(), pending.destination));
            transactions.push(report(Outcome::Retried {
                attempt: pending.retries,
            }));
            true
        });
        Due {
            resend,
            transactions,
        }
    }

    /// APDU_Timeout and Number_Of_APDU_Retries, from the Device object.
    fn policy(&self) -> (Duration, u8) {
        let device = self.database.get_device_id();
        let unsigned = |property| match self.database.get_property(device, property) {
            Ok(PropertyValue::Unsigned(value)) => Some(value),
            _ => None,
        };
        let timeout = unsigned(PropertyIdentifier::ApduTimeout).unwrap_or(3_000);
        let retries = unsigned(PropertyIdentifier::NumberOfApduRetries).unwrap_or(3);
        (
            Duration::from_millis(timeout),
            u8::try_from(retries).unwrap_or(u8::MAX),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;

    use super::*;
    use crate::{
        app::Apdu,
        network::Npdu,
        object::{Device, ObjectIdentifier, ObjectType},
        server::{NotificationTarget, Notifier, ObjectService, ServerDispatcher},
        service::cov_notification::CovNotification,
    };

    /// A device whose notifier follows up what it sends, and a peer to send
    /// to that answers only when told to.
    fn device() -> (Notifier, ServerDispatcher, UdpSocket) {
        let mut device = Device::new(1234, "Notifying".to_string());
        device.apdu_timeout = 50;
        device.number_of_apdu_retries = 2;
        let service = ObjectService::new(Arc::new(ObjectDatabase::new(device)));
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let notifier = Notifier::new(&socket)
            .unwrap()
            .with_transactions(service.transactions().clone());
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        (notifier, ServerDispatcher::new(service), peer)
    }

    fn notify(notifier: &Notifier, peer: &UdpSocket) -> u8 {
        let notification = CovNotification {
            subscriber_process_identifier: 1,
            initiating_device: ObjectIdentifier::new(ObjectType::Device, 1234),
            monitored_object: ObjectIdentifier::new(ObjectType::Device, 1234),
            time_remaining: 0,
            list_of_values: Vec::new(),
        };
        notifier
            .send_cov_notification(
                NotificationTarget::Unicast(peer.local_addr().unwrap()),
                &notification,
                true,
            )
            .unwrap();
        received_invoke_id(peer)
    }

    fn received_invoke_id(peer: &UdpSocket) -> u8 {
        let mut buffer = [0; 1500];
        let (length, _) = peer.recv_from(&mut buffer).unwrap();
        let (_, apdu, _) = crate::server::bip::decode_bacnet_ip_frame(&buffer[..length]).unwrap();
        match Apdu::decode(apdu).unwrap() {
            Apdu::ConfirmedRequest { invoke_id, .. } => invoke_id,
            other => panic!("expected a confirmed request, got {other:?}"),
        }
    }

    fn reply(dispatcher: &ServerDispatcher, peer: &UdpSocket, apdu: Apdu) {
        dispatcher
            .dispatch(&Npdu::new(), apdu, Some(peer.local_addr().unwrap()))
            .unwrap();
    }

    fn outcomes(notifier: &Notifier, at: Instant) -> Vec<Outcome> {
        notifier
            .poll(at)
            .unwrap()
            .into_iter()
            .map(|transaction| transaction.outcome)
            .collect()
    }

    #[test]
    fn an_unanswered_request_is_sent_again_then_given_up() {
        let (notifier, _, peer) = device();
        let start = Instant::now();
        let invoke_id = notify(&notifier, &peer);

        assert!(outcomes(&notifier, start).is_empty(), "not due yet");
        let later = start + Duration::from_millis(60);
        assert_eq!(
            outcomes(&notifier, later),
            [Outcome::Retried { attempt: 1 }]
        );
        assert_eq!(received_invoke_id(&peer), invoke_id, "the same request");
        let later = later + Duration::from_millis(60);
        assert_eq!(
            outcomes(&notifier, later),
            [Outcome::Retried { attempt: 2 }]
        );
        let later = later + Duration::from_millis(60);
        assert_eq!(outcomes(&notifier, later), [Outcome::GaveUp]);
    }

    #[test]
    fn the_right_acknowledgement_ends_the_transaction() {
        let (notifier, dispatcher, peer) = device();
        let invoke_id = notify(&notifier, &peer);

        reply(
            &dispatcher,
            &peer,
            Apdu::SimpleAck {
                invoke_id,
                service_choice: ConfirmedServiceChoice::ConfirmedCovNotification as u8,
            },
        );

        assert_eq!(
            outcomes(&notifier, Instant::now() + Duration::from_secs(1)),
            [Outcome::Acknowledged]
        );
    }

    /// The Go-IoT gateway's bug: a SimpleACK naming another service still
    /// answers the request, so a sloppy peer does not bring on a retry storm.
    #[test]
    fn an_acknowledgement_naming_another_service_still_ends_it() {
        let (notifier, dispatcher, peer) = device();
        let invoke_id = notify(&notifier, &peer);

        reply(
            &dispatcher,
            &peer,
            Apdu::SimpleAck {
                invoke_id,
                service_choice: ConfirmedServiceChoice::ConfirmedEventNotification as u8,
            },
        );

        assert_eq!(
            outcomes(&notifier, Instant::now() + Duration::from_millis(60)),
            [Outcome::Acknowledged]
        );
    }
}
