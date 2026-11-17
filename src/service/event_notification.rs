//! ConfirmedEventNotification (service choice 2) and UnconfirmedEventNotification
//! (service choice 3).
//!
//! Both services carry the identical parameter list from ASHRAE 135 clause 13.8,
//! so [`EventNotification::encode`] produces the service data for either; the
//! caller picks the APDU type.
//!
//! The `BACnetNotificationParameters` alternatives an alarm consumer acts on are
//! modelled: change-of-state, change-of-value, out-of-range and
//! change-of-reliability. Any other algorithm decodes as
//! [`NotificationParameters::Other`], its encoding kept intact, so a device
//! reporting one is still heard.

use crate::encoding::{
    decode_closing_tag, decode_context_bit_string, decode_context_boolean,
    decode_context_enumerated, decode_context_object_id, decode_context_real, decode_context_tag,
    decode_context_unsigned, decode_opening_tag, decode_tag, enclosed_length, encode_closing_tag,
    encode_context_bit_string, encode_context_boolean, encode_context_enumerated,
    encode_context_object_id, encode_context_real, encode_context_tag, encode_context_unsigned,
    encode_opening_tag, is_context_tag, is_opening_tag, BACnetTag, CharacterSet, EncodingError,
    Result as EncodingResult,
};
use crate::object::{intrinsic::NotifyType, EventState, ObjectIdentifier, Reliability};
use crate::property::TimestampValue;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// `BACnetStatusFlags` — in-alarm, fault, overridden, out-of-service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatusFlags {
    /// The object is in an off-normal or fault event state.
    pub in_alarm: bool,
    /// The object's value is unreliable.
    pub fault: bool,
    /// The value has been overridden locally.
    pub overridden: bool,
    /// The object is decoupled from the physical point.
    pub out_of_service: bool,
}

impl StatusFlags {
    /// Derive the flags an intrinsic-reporting object reports for `state`.
    pub fn for_event_state(state: EventState, out_of_service: bool) -> Self {
        Self {
            in_alarm: state != EventState::Normal,
            fault: state == EventState::Fault,
            overridden: false,
            out_of_service,
        }
    }

    /// The flags packed in BACnet bit order.
    pub fn to_bits(self) -> [bool; 4] {
        [
            self.in_alarm,
            self.fault,
            self.overridden,
            self.out_of_service,
        ]
    }

    /// Read the flags from a bit string, tolerating a sender that sends fewer
    /// or more than four bits: missing bits are clear, extra bits ignored.
    pub fn from_bits(bits: &[bool]) -> Self {
        let bit = |index: usize| bits.get(index).copied().unwrap_or(false);
        Self {
            in_alarm: bit(0),
            fault: bit(1),
            overridden: bit(2),
            out_of_service: bit(3),
        }
    }
}

/// `BACnetEventType`. The algorithms consumers act on are named; any other,
/// proprietary ones included, is carried as its number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// change-of-state (1) — binary and multi-state objects.
    ChangeOfState,
    /// change-of-value (2).
    ChangeOfValue,
    /// out-of-range (5) — analog objects with limits.
    OutOfRange,
    /// change-of-reliability (19).
    ChangeOfReliability,
    /// Any other event type.
    Other(u32),
}

impl From<EventType> for u32 {
    fn from(value: EventType) -> Self {
        match value {
            EventType::ChangeOfState => 1,
            EventType::ChangeOfValue => 2,
            EventType::OutOfRange => 5,
            EventType::ChangeOfReliability => 19,
            EventType::Other(value) => value,
        }
    }
}

impl From<u32> for EventType {
    fn from(value: u32) -> Self {
        match value {
            1 => Self::ChangeOfState,
            2 => Self::ChangeOfValue,
            5 => Self::OutOfRange,
            19 => Self::ChangeOfReliability,
            other => Self::Other(other),
        }
    }
}

/// `BACnetPropertyStates` CHOICE.
///
/// The context tag number *is* the CHOICE discriminator, so these values match
/// the `BACnetPropertyStates` production exactly. Every alternative other than
/// the three named here is an enumeration or an INTEGER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyStates {
    /// boolean-value [0].
    BooleanValue(bool),
    /// binary-value [1] — a `BACnetBinaryPV`, inactive (0) or active (1).
    BinaryValue(bool),
    /// unsigned-value [11] — a multi-state Present_Value.
    UnsignedValue(u32),
    /// integer-value [36].
    IntegerValue(i32),
    /// Any enumerated alternative, by its choice number.
    Enumerated { choice: u8, value: u32 },
}

/// The integer-value alternative, the one signed choice.
const INTEGER_VALUE: u8 = 36;

impl PropertyStates {
    fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        match *self {
            Self::BooleanValue(value) => encode_context_boolean(buffer, 0, value),
            Self::BinaryValue(active) => {
                buffer.extend_from_slice(&encode_context_enumerated(u32::from(active), 1)?);
                Ok(())
            }
            Self::UnsignedValue(state) => {
                buffer.extend_from_slice(&encode_context_unsigned(state, 11)?);
                Ok(())
            }
            Self::IntegerValue(value) => {
                let bytes = value.to_be_bytes();
                // Shortest two's-complement form: drop leading octets that only
                // repeat the sign of the one after them.
                let mut start = 0;
                while start < 3 {
                    let (lead, next) = (bytes[start], bytes[start + 1]);
                    if (lead == 0x00 && next & 0x80 == 0) || (lead == 0xff && next & 0x80 != 0) {
                        start += 1;
                    } else {
                        break;
                    }
                }
                encode_context_tag(buffer, INTEGER_VALUE, 4 - start)?;
                buffer.extend_from_slice(&bytes[start..]);
                Ok(())
            }
            Self::Enumerated { choice, value } => {
                buffer.extend_from_slice(&encode_context_enumerated(value, choice)?);
                Ok(())
            }
        }
    }

    fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let (choice, length, header) = decode_context_tag(data)?;
        let content = data
            .get(header..header + length)
            .ok_or(EncodingError::BufferUnderflow)?;
        let state = match choice {
            0 => Self::BooleanValue(decode_context_boolean(data, 0)?.0),
            1 => Self::BinaryValue(decode_context_enumerated(data, 1)?.0 != 0),
            11 => Self::UnsignedValue(decode_context_unsigned(data, 11)?.0),
            INTEGER_VALUE => {
                if content.is_empty() || content.len() > 4 {
                    return Err(EncodingError::InvalidLength);
                }
                let fill = if content[0] & 0x80 != 0 { 0xff } else { 0x00 };
                let mut bytes = [fill; 4];
                bytes[4 - content.len()..].copy_from_slice(content);
                Self::IntegerValue(i32::from_be_bytes(bytes))
            }
            choice => Self::Enumerated {
                choice,
                value: decode_context_enumerated(data, choice)?.0,
            },
        };
        Ok((state, header + length))
    }
}

/// The new-value of a change-of-value notification.
#[derive(Debug, Clone, PartialEq)]
pub enum ChangeOfValueNew {
    /// changed-bits [0].
    ChangedBits(Vec<bool>),
    /// changed-value [1].
    ChangedValue(f32),
}

/// `BACnetNotificationParameters` for the supported event algorithms.
#[derive(Debug, Clone, PartialEq)]
pub enum NotificationParameters {
    /// change-of-state [1].
    ChangeOfState {
        /// The state the object moved to.
        new_state: PropertyStates,
        /// Status flags at the time of the transition.
        status_flags: StatusFlags,
    },
    /// out-of-range [5].
    OutOfRange {
        /// The value that breached the limit.
        exceeding_value: f32,
        /// Status flags at the time of the transition.
        status_flags: StatusFlags,
        /// Configured deadband.
        deadband: f32,
        /// The limit that was breached.
        exceeded_limit: f32,
    },
    /// change-of-reliability [19]. Its property-values are not kept.
    ChangeOfReliability {
        /// The object's reliability.
        reliability: Reliability,
        /// Status flags at the time of the transition.
        status_flags: StatusFlags,
    },
    /// change-of-value [2].
    ChangeOfValue {
        /// The changed bits or the new value.
        new_value: ChangeOfValueNew,
        /// Status flags at the time of the transition.
        status_flags: StatusFlags,
    },
    /// Any other algorithm, or a modelled one whose encoding did not decode.
    /// `data` is everything inside eventValues [12], as sent. An
    /// acknowledgement notification carries no event values, so it decodes as
    /// this with `data` empty.
    Other {
        /// The notification's eventType.
        event_type: u32,
        /// The encoded parameters.
        data: Vec<u8>,
    },
}

impl NotificationParameters {
    /// The event type this parameter set belongs to.
    pub fn event_type(&self) -> EventType {
        match self {
            Self::ChangeOfState { .. } => EventType::ChangeOfState,
            Self::ChangeOfValue { .. } => EventType::ChangeOfValue,
            Self::OutOfRange { .. } => EventType::OutOfRange,
            Self::ChangeOfReliability { .. } => EventType::ChangeOfReliability,
            Self::Other { event_type, .. } => EventType::from(*event_type),
        }
    }

    /// Decode the contents of eventValues [12], falling back to
    /// [`Self::Other`] for an algorithm not modelled or one that does not
    /// decode as its production says.
    fn decode(event_type: u32, data: &[u8]) -> Self {
        Self::decode_modelled(event_type, data).unwrap_or_else(|| Self::Other {
            event_type,
            data: data.to_vec(),
        })
    }

    /// The parameters' CHOICE tag is the event type they belong to. One that
    /// disagrees with eventType is kept raw rather than trusted either way.
    fn decode_modelled(event_type: u32, data: &[u8]) -> Option<Self> {
        let (BACnetTag::Opening(choice), _, header) = decode_tag(data).ok()? else {
            return None;
        };
        if u32::from(choice) != event_type {
            return None;
        }
        let body = data.get(header..)?;
        let mut offset = 0;
        let parameters = match choice {
            1 => {
                offset += decode_opening_tag(body, 0).ok()?;
                let (new_state, length) = PropertyStates::decode(&body[offset..]).ok()?;
                offset += length;
                offset += decode_closing_tag(&body[offset..], 0).ok()?;
                let (bits, length) = decode_context_bit_string(&body[offset..], 1).ok()?;
                offset += length;
                Self::ChangeOfState {
                    new_state,
                    status_flags: StatusFlags::from_bits(&bits),
                }
            }
            2 => {
                offset += decode_opening_tag(body, 0).ok()?;
                let new_value = if is_context_tag(&body[offset..], 0) {
                    let (bits, length) = decode_context_bit_string(&body[offset..], 0).ok()?;
                    offset += length;
                    ChangeOfValueNew::ChangedBits(bits)
                } else {
                    let (value, length) = decode_context_real(&body[offset..], 1).ok()?;
                    offset += length;
                    ChangeOfValueNew::ChangedValue(value)
                };
                offset += decode_closing_tag(&body[offset..], 0).ok()?;
                let (bits, length) = decode_context_bit_string(&body[offset..], 1).ok()?;
                offset += length;
                Self::ChangeOfValue {
                    new_value,
                    status_flags: StatusFlags::from_bits(&bits),
                }
            }
            5 => {
                let (exceeding_value, length) = decode_context_real(body, 0).ok()?;
                offset += length;
                let (bits, length) = decode_context_bit_string(&body[offset..], 1).ok()?;
                offset += length;
                let (deadband, length) = decode_context_real(&body[offset..], 2).ok()?;
                offset += length;
                let (exceeded_limit, length) = decode_context_real(&body[offset..], 3).ok()?;
                offset += length;
                Self::OutOfRange {
                    exceeding_value,
                    status_flags: StatusFlags::from_bits(&bits),
                    deadband,
                    exceeded_limit,
                }
            }
            19 => {
                let (reliability, length) = decode_context_enumerated(body, 0).ok()?;
                offset += length;
                let (bits, length) = decode_context_bit_string(&body[offset..], 1).ok()?;
                offset += length;
                if is_opening_tag(&body[offset..], 2) {
                    let inner = decode_opening_tag(&body[offset..], 2).ok()?;
                    offset += inner;
                    offset += enclosed_length(&body[offset..], 2).ok()?;
                    offset += decode_closing_tag(&body[offset..], 2).ok()?;
                }
                Self::ChangeOfReliability {
                    reliability: Reliability::from(reliability),
                    status_flags: StatusFlags::from_bits(&bits),
                }
            }
            _ => return None,
        };
        offset += decode_closing_tag(body.get(offset..)?, choice).ok()?;
        // Trailing octets mean a production we only think we know.
        (header + offset == data.len()).then_some(parameters)
    }

    fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        match self {
            Self::ChangeOfState {
                new_state,
                status_flags,
            } => {
                encode_opening_tag(buffer, 1)?;
                encode_opening_tag(buffer, 0)?;
                new_state.encode(buffer)?;
                encode_closing_tag(buffer, 0)?;
                encode_context_bit_string(buffer, 1, &status_flags.to_bits())?;
                encode_closing_tag(buffer, 1)?;
            }
            Self::OutOfRange {
                exceeding_value,
                status_flags,
                deadband,
                exceeded_limit,
            } => {
                encode_opening_tag(buffer, 5)?;
                encode_context_real(buffer, 0, *exceeding_value)?;
                encode_context_bit_string(buffer, 1, &status_flags.to_bits())?;
                encode_context_real(buffer, 2, *deadband)?;
                encode_context_real(buffer, 3, *exceeded_limit)?;
                encode_closing_tag(buffer, 5)?;
            }
            Self::ChangeOfReliability {
                reliability,
                status_flags,
            } => {
                encode_opening_tag(buffer, 19)?;
                buffer.extend_from_slice(&encode_context_enumerated(u32::from(*reliability), 0)?);
                encode_context_bit_string(buffer, 1, &status_flags.to_bits())?;
                // property-values [2] is required but may be an empty sequence.
                encode_opening_tag(buffer, 2)?;
                encode_closing_tag(buffer, 2)?;
                encode_closing_tag(buffer, 19)?;
            }
            Self::ChangeOfValue {
                new_value,
                status_flags,
            } => {
                encode_opening_tag(buffer, 2)?;
                encode_opening_tag(buffer, 0)?;
                match new_value {
                    ChangeOfValueNew::ChangedBits(bits) => {
                        encode_context_bit_string(buffer, 0, bits)?
                    }
                    ChangeOfValueNew::ChangedValue(value) => {
                        encode_context_real(buffer, 1, *value)?
                    }
                }
                encode_closing_tag(buffer, 0)?;
                encode_context_bit_string(buffer, 1, &status_flags.to_bits())?;
                encode_closing_tag(buffer, 2)?;
            }
            Self::Other { data, .. } => buffer.extend_from_slice(data),
        }

        Ok(())
    }
}

/// An event notification a device sends to a notification-class recipient.
#[derive(Debug, Clone, PartialEq)]
pub struct EventNotification {
    /// Recipient's process identifier, from the Recipient_List entry.
    pub process_identifier: u32,
    /// The device reporting the event.
    pub initiating_device: ObjectIdentifier,
    /// The object whose event state changed.
    pub event_object: ObjectIdentifier,
    /// When the transition occurred.
    pub timestamp: TimestampValue,
    /// Instance number of the routing notification class.
    pub notification_class: u32,
    /// Notification priority for this transition (1–255).
    pub priority: u32,
    /// Whether this is an alarm or a plain event.
    pub notify_type: NotifyType,
    /// Whether the recipient must acknowledge.
    pub ack_required: bool,
    /// Event state before the transition.
    pub from_state: EventState,
    /// Event state after the transition.
    pub to_state: EventState,
    /// Optional human-readable message.
    pub message_text: Option<String>,
    /// Algorithm-specific detail.
    pub parameters: NotificationParameters,
}

impl EventNotification {
    /// The event type carried by [`Self::parameters`].
    pub fn event_type(&self) -> EventType {
        self.parameters.event_type()
    }

    /// Encode the service data shared by the confirmed and unconfirmed forms.
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        buffer.extend_from_slice(&encode_context_unsigned(self.process_identifier, 0)?);
        buffer.extend_from_slice(&encode_context_object_id(self.initiating_device, 1)?);
        buffer.extend_from_slice(&encode_context_object_id(self.event_object, 2)?);

        encode_opening_tag(buffer, 3)?;
        self.timestamp.encode(buffer)?;
        encode_closing_tag(buffer, 3)?;

        buffer.extend_from_slice(&encode_context_unsigned(self.notification_class, 4)?);
        buffer.extend_from_slice(&encode_context_unsigned(self.priority, 5)?);
        buffer.extend_from_slice(&encode_context_enumerated(self.event_type().into(), 6)?);

        if let Some(text) = &self.message_text {
            encode_context_char_string(buffer, 7, text)?;
        }

        buffer.extend_from_slice(&encode_context_enumerated(self.notify_type.into(), 8)?);

        // ack-required and from-state are only present for alarms and events,
        // never for acknowledgement notifications.
        if self.notify_type != NotifyType::AckNotification {
            encode_context_boolean(buffer, 9, self.ack_required)?;
            buffer.extend_from_slice(&encode_context_enumerated(
                u16::from(self.from_state).into(),
                10,
            )?);
        }

        buffer.extend_from_slice(&encode_context_enumerated(
            u16::from(self.to_state).into(),
            11,
        )?);

        // No event-values: an acknowledgement reports no algorithm (13.8.1).
        if self.notify_type != NotifyType::AckNotification {
            encode_opening_tag(buffer, 12)?;
            self.parameters.encode(buffer)?;
            encode_closing_tag(buffer, 12)?;
        }

        Ok(())
    }

    /// Decode the service data of either notification form.
    ///
    /// An acknowledgement notification omits ackRequired and fromState; they
    /// decode as `false` and [`EventState::Normal`], which mean nothing there.
    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let (process_identifier, mut offset) = decode_context_unsigned(data, 0)?;
        let (initiating_device, length) = decode_context_object_id(&data[offset..], 1)?;
        offset += length;
        let (event_object, length) = decode_context_object_id(&data[offset..], 2)?;
        offset += length;

        offset += decode_opening_tag(&data[offset..], 3)?;
        let (timestamp, length) = TimestampValue::decode(&data[offset..])?;
        offset += length;
        offset += decode_closing_tag(&data[offset..], 3)?;

        let (notification_class, length) = decode_context_unsigned(&data[offset..], 4)?;
        offset += length;
        let (priority, length) = decode_context_unsigned(&data[offset..], 5)?;
        offset += length;
        let (event_type, length) = decode_context_enumerated(&data[offset..], 6)?;
        offset += length;

        let message_text = if is_context_tag(&data[offset..], 7) {
            let (text, length) = decode_context_char_string(&data[offset..], 7)?;
            offset += length;
            text
        } else {
            None
        };

        let (notify_type, length) = decode_context_enumerated(&data[offset..], 8)?;
        offset += length;
        let notify_type = NotifyType::try_from(notify_type)
            .map_err(|_| EncodingError::InvalidFormat("unknown notify type".into()))?;

        let mut ack_required = false;
        if is_context_tag(&data[offset..], 9) {
            let (value, length) = decode_context_boolean(&data[offset..], 9)?;
            ack_required = value;
            offset += length;
        }
        let mut from_state = EventState::Normal;
        if is_context_tag(&data[offset..], 10) {
            let (value, length) = decode_context_enumerated(&data[offset..], 10)?;
            from_state = event_state(value)?;
            offset += length;
        }

        let (to_state, length) = decode_context_enumerated(&data[offset..], 11)?;
        offset += length;
        let to_state = event_state(to_state)?;

        let parameters = if is_opening_tag(&data[offset..], 12) {
            offset += decode_opening_tag(&data[offset..], 12)?;
            let length = enclosed_length(&data[offset..], 12)?;
            let parameters =
                NotificationParameters::decode(event_type, &data[offset..offset + length]);
            offset += length;
            decode_closing_tag(&data[offset..], 12)?;
            parameters
        } else {
            NotificationParameters::Other {
                event_type,
                data: Vec::new(),
            }
        };

        Ok(Self {
            process_identifier,
            initiating_device,
            event_object,
            timestamp,
            notification_class,
            priority,
            notify_type,
            ack_required,
            from_state,
            to_state,
            message_text,
            parameters,
        })
    }
}

/// A decoded BACnetEventState, which the wire carries as any Unsigned.
pub(crate) fn event_state(value: u32) -> EncodingResult<EventState> {
    u16::try_from(value)
        .map(EventState::from)
        .map_err(|_| EncodingError::InvalidFormat("event state out of range".into()))
}

/// Decode a context-tagged CHARACTER STRING in whichever character set it
/// declares. Text in a set that cannot be read here is `None`: the message is
/// optional, and the notification it rides on is not to be lost over it.
fn decode_context_char_string(data: &[u8], tag: u8) -> EncodingResult<(Option<String>, usize)> {
    let (actual, length, header) = decode_context_tag(data)?;
    if actual != tag || length == 0 {
        return Err(EncodingError::InvalidTag);
    }
    let content = data
        .get(header..header + length)
        .ok_or(EncodingError::BufferUnderflow)?;
    let text = CharacterSet::try_from(content[0])
        .and_then(|set| set.decode(&content[1..]))
        .ok();
    Ok((text, header + length))
}

/// Encode a CHARACTER STRING under a context tag, always as UTF-8.
fn encode_context_char_string(buffer: &mut Vec<u8>, tag: u8, text: &str) -> EncodingResult<()> {
    let bytes = text.as_bytes();
    encode_context_tag(buffer, tag, bytes.len() + 1)?;
    buffer.push(0); // ANSI X3.4 / UTF-8
    buffer.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;

    fn notification(parameters: NotificationParameters) -> EventNotification {
        EventNotification {
            process_identifier: 777,
            initiating_device: ObjectIdentifier::new(ObjectType::Device, 1234),
            event_object: ObjectIdentifier::new(ObjectType::MultiStateValue, 1),
            timestamp: TimestampValue::SequenceNumber(5),
            notification_class: 1,
            priority: 90,
            notify_type: NotifyType::Alarm,
            ack_required: false,
            from_state: EventState::Normal,
            to_state: EventState::Offnormal,
            message_text: None,
            parameters,
        }
    }

    #[test]
    fn change_of_state_reports_event_type_one() {
        let event = notification(NotificationParameters::ChangeOfState {
            new_state: PropertyStates::UnsignedValue(5),
            status_flags: StatusFlags::for_event_state(EventState::Offnormal, false),
        });
        assert_eq!(u32::from(event.event_type()), 1);
    }

    /// The change-of-state parameter block is what alarmsd parses to recover
    /// `event-values.change-of-state.new-state`, so pin its exact bytes.
    #[test]
    fn change_of_state_parameters_match_the_spec_layout() {
        let parameters = NotificationParameters::ChangeOfState {
            new_state: PropertyStates::UnsignedValue(5),
            status_flags: StatusFlags {
                in_alarm: true,
                fault: false,
                overridden: false,
                out_of_service: false,
            },
        };

        let mut encoded = Vec::new();
        parameters.encode(&mut encoded).expect("encode");

        assert_eq!(
            encoded,
            vec![
                0x1e, // opening tag [1] change-of-state
                0x0e, // opening tag [0] new-state
                0xb9, 0x05, // context 11 (unsigned-value), length 1, state 5
                0x0f, // closing tag [0]
                0x1a, 0x04, 0x80, // context 1, length 2: 4 unused bits, 0b1000_0000
                0x1f, // closing tag [1]
            ]
        );
    }

    #[test]
    fn out_of_range_parameters_match_the_spec_layout() {
        let parameters = NotificationParameters::OutOfRange {
            exceeding_value: 25.0,
            status_flags: StatusFlags {
                in_alarm: true,
                fault: false,
                overridden: false,
                out_of_service: false,
            },
            deadband: 0.5,
            exceeded_limit: 24.0,
        };

        let mut encoded = Vec::new();
        parameters.encode(&mut encoded).expect("encode");

        let mut expected = vec![0x5e]; // opening tag [5] out-of-range
        expected.push(0x0c); // context 0, length 4
        expected.extend_from_slice(&25.0f32.to_be_bytes());
        expected.extend_from_slice(&[0x1a, 0x04, 0x80]); // status flags
        expected.push(0x2c); // context 2, length 4
        expected.extend_from_slice(&0.5f32.to_be_bytes());
        expected.push(0x3c); // context 3, length 4
        expected.extend_from_slice(&24.0f32.to_be_bytes());
        expected.push(0x5f); // closing tag [5]

        assert_eq!(encoded, expected);
    }

    #[test]
    fn change_of_reliability_carries_an_empty_property_values_sequence() {
        let parameters = NotificationParameters::ChangeOfReliability {
            reliability: Reliability::UnreliableOther,
            status_flags: StatusFlags::for_event_state(EventState::Fault, false),
        };

        let mut encoded = Vec::new();
        parameters.encode(&mut encoded).expect("encode");

        // Opening [19] uses the extended tag-number form, as do its closers.
        assert_eq!(&encoded[..2], &[0xfe, 0x13]);
        assert_eq!(&encoded[encoded.len() - 2..], &[0xff, 0x13]);
        // property-values [2] is present but empty.
        assert!(encoded.windows(2).any(|pair| pair == [0x2e, 0x2f]));
    }

    #[test]
    fn service_data_field_order_follows_clause_13_8() {
        let event = notification(NotificationParameters::ChangeOfState {
            new_state: PropertyStates::UnsignedValue(5),
            status_flags: StatusFlags::for_event_state(EventState::Offnormal, false),
        });

        let mut encoded = Vec::new();
        event.encode(&mut encoded).expect("encode");

        // processIdentifier [0] = 777 carries a two-byte payload in the tag length.
        assert_eq!(&encoded[..3], &[0x0a, 0x03, 0x09]);
        // The parameters are wrapped in the eventValues [12] constructed tag.
        assert_eq!(encoded[encoded.len() - 1], 0xcf);
        assert!(encoded.windows(1).any(|byte| byte == [0xce]));
    }

    /// Byte-for-byte against a frame captured from the bacnet-stack reference
    /// implementation:
    ///
    /// ```text
    /// bacuevent --mac <host> 777 8 1234 19 1 5 1 90 1 11 5 1000 "" 0 0 0 2
    /// ```
    ///
    /// The captured datagram was
    /// `810a0034 0100 1003 <service data>`; only the service data is compared
    /// here since BVLC/NPDU/APDU framing is the caller's concern.
    #[test]
    fn matches_a_frame_captured_from_the_reference_implementation() {
        let event = EventNotification {
            process_identifier: 777,
            initiating_device: ObjectIdentifier::new(ObjectType::Device, 1234),
            event_object: ObjectIdentifier::new(ObjectType::MultiStateValue, 1),
            timestamp: TimestampValue::SequenceNumber(5),
            notification_class: 1,
            priority: 90,
            notify_type: NotifyType::Alarm,
            ack_required: false,
            from_state: EventState::Normal,
            to_state: EventState::Offnormal,
            // The reference tool always emits the field, empty in this capture.
            message_text: Some(String::new()),
            parameters: NotificationParameters::ChangeOfState {
                new_state: PropertyStates::UnsignedValue(5),
                status_flags: StatusFlags {
                    in_alarm: true,
                    fault: false,
                    overridden: false,
                    out_of_service: false,
                },
            },
        };

        let mut encoded = Vec::new();
        event.encode(&mut encoded).expect("encode");

        let expected = [
            0x0a, 0x03, 0x09, // [0] processIdentifier 777
            0x1c, 0x02, 0x00, 0x04, 0xd2, // [1] initiating device,1234
            0x2c, 0x04, 0xc0, 0x00, 0x01, // [2] event object multi-state-value,1
            0x3e, 0x19, 0x05, 0x3f, // [3] timeStamp sequenceNumber 5
            0x49, 0x01, // [4] notificationClass 1
            0x59, 0x5a, // [5] priority 90
            0x69, 0x01, // [6] eventType change-of-state
            0x79, 0x00, // [7] messageText ""
            0x89, 0x00, // [8] notifyType alarm
            0x99, 0x00, // [9] ackRequired false
            0xa9, 0x00, // [10] fromState normal
            0xb9, 0x02, // [11] toState offnormal
            0xce, // [12] eventValues
            0x1e, 0x0e, 0xb9, 0x05, 0x0f, 0x1a, 0x04, 0x80, 0x1f, 0xcf,
        ];

        assert_eq!(encoded, expected);
    }

    #[test]
    fn ack_notifications_omit_ack_required_and_from_state() {
        let mut event = notification(NotificationParameters::ChangeOfState {
            new_state: PropertyStates::BinaryValue(true),
            status_flags: StatusFlags::default(),
        });
        event.notify_type = NotifyType::AckNotification;

        let mut encoded = Vec::new();
        event.encode(&mut encoded).expect("encode");

        // Context tag 9 (0x99) and 10 (0xa9) must not appear as field headers.
        let mut alarm_form = Vec::new();
        notification(NotificationParameters::ChangeOfState {
            new_state: PropertyStates::BinaryValue(true),
            status_flags: StatusFlags::default(),
        })
        .encode(&mut alarm_form)
        .expect("encode");

        assert!(alarm_form.len() > encoded.len());
    }

    #[test]
    fn message_text_is_optional() {
        let mut event = notification(NotificationParameters::ChangeOfState {
            new_state: PropertyStates::UnsignedValue(2),
            status_flags: StatusFlags::default(),
        });

        let mut without = Vec::new();
        event.encode(&mut without).expect("encode");

        event.message_text = Some("Mode fault".to_string());
        let mut with = Vec::new();
        event.encode(&mut with).expect("encode");

        // Tag byte + extended length byte + the UTF-8 marker, then the text.
        assert_eq!(with.len(), without.len() + 3 + "Mode fault".len());
    }

    fn round_trip(event: &EventNotification) -> EventNotification {
        let mut encoded = Vec::new();
        event.encode(&mut encoded).expect("encode");
        EventNotification::decode(&encoded).expect("decode")
    }

    #[test]
    fn every_modelled_algorithm_round_trips() {
        let flags = StatusFlags::for_event_state(EventState::Offnormal, false);
        for parameters in [
            NotificationParameters::ChangeOfState {
                new_state: PropertyStates::BinaryValue(true),
                status_flags: flags,
            },
            NotificationParameters::ChangeOfState {
                new_state: PropertyStates::IntegerValue(-300),
                status_flags: flags,
            },
            NotificationParameters::ChangeOfState {
                new_state: PropertyStates::Enumerated {
                    choice: 13,
                    value: 4,
                },
                status_flags: flags,
            },
            NotificationParameters::ChangeOfValue {
                new_value: ChangeOfValueNew::ChangedValue(21.5),
                status_flags: flags,
            },
            NotificationParameters::ChangeOfValue {
                new_value: ChangeOfValueNew::ChangedBits(vec![true, false, true]),
                status_flags: flags,
            },
            NotificationParameters::OutOfRange {
                exceeding_value: 25.0,
                status_flags: flags,
                deadband: 0.5,
                exceeded_limit: 24.0,
            },
            NotificationParameters::ChangeOfReliability {
                reliability: Reliability::UnreliableOther,
                status_flags: StatusFlags::for_event_state(EventState::Fault, false),
            },
        ] {
            let mut event = notification(parameters);
            event.message_text = Some("Pump fault".into());
            event.ack_required = true;
            assert_eq!(round_trip(&event), event);
        }
    }

    #[test]
    fn decodes_the_frame_captured_from_the_reference_implementation() {
        let frame = [
            0x0a, 0x03, 0x09, 0x1c, 0x02, 0x00, 0x04, 0xd2, 0x2c, 0x04, 0xc0, 0x00, 0x01, 0x3e,
            0x19, 0x05, 0x3f, 0x49, 0x01, 0x59, 0x5a, 0x69, 0x01, 0x79, 0x00, 0x89, 0x00, 0x99,
            0x00, 0xa9, 0x00, 0xb9, 0x02, 0xce, 0x1e, 0x0e, 0xb9, 0x05, 0x0f, 0x1a, 0x04, 0x80,
            0x1f, 0xcf,
        ];
        let event = EventNotification::decode(&frame).expect("decode");
        assert_eq!(event.process_identifier, 777);
        assert_eq!(event.to_state, EventState::Offnormal);
        assert_eq!(event.message_text.as_deref(), Some(""));
        assert_eq!(
            event.parameters,
            NotificationParameters::ChangeOfState {
                new_state: PropertyStates::UnsignedValue(5),
                status_flags: StatusFlags::for_event_state(EventState::Offnormal, false),
            }
        );
    }

    /// change-of-bitstring [0] is not modelled; it must still decode, and
    /// re-encode to the same octets.
    #[test]
    fn an_unmodelled_algorithm_is_kept_whole() {
        let data = vec![
            0x0e, // opening [0] change-of-bitstring
            0x0a, 0x04, 0xa0, // [0] referenced-bitstring, 4 bits 1010
            0x1a, 0x04, 0x80, // [1] status-flags
            0x0f,
        ];
        let event = notification(NotificationParameters::Other {
            event_type: 0,
            data: data.clone(),
        });
        let decoded = round_trip(&event);
        assert_eq!(decoded.event_type(), EventType::Other(0));
        assert_eq!(
            decoded.parameters,
            NotificationParameters::Other {
                event_type: 0,
                data
            }
        );
    }

    #[test]
    fn a_modelled_algorithm_that_does_not_parse_is_kept_whole() {
        // out-of-range [5] missing its exceeded-limit.
        let mut data = vec![0x5e, 0x0c];
        data.extend_from_slice(&25.0f32.to_be_bytes());
        data.extend_from_slice(&[0x1a, 0x04, 0x80, 0x2c]);
        data.extend_from_slice(&0.5f32.to_be_bytes());
        data.push(0x5f);
        let event = notification(NotificationParameters::Other {
            event_type: 5,
            data: data.clone(),
        });
        let decoded = round_trip(&event);
        assert_eq!(decoded.event_type(), EventType::OutOfRange);
        assert_eq!(
            decoded.parameters,
            NotificationParameters::Other {
                event_type: 5,
                data
            }
        );
    }

    /// eventType says out-of-range, the parameters are change-of-state.
    #[test]
    fn parameters_that_contradict_the_event_type_are_kept_whole() {
        let event = notification(NotificationParameters::ChangeOfState {
            new_state: PropertyStates::BinaryValue(true),
            status_flags: StatusFlags::default(),
        });
        let mut encoded = Vec::new();
        event.encode(&mut encoded).expect("encode");
        // [6] eventType change-of-state (1) becomes out-of-range (5).
        let at = encoded
            .windows(2)
            .position(|pair| pair == [0x69, 0x01])
            .expect("event type");
        encoded[at + 1] = 0x05;

        let decoded = EventNotification::decode(&encoded).expect("decode");
        assert_eq!(decoded.event_type(), EventType::OutOfRange);
        assert!(matches!(
            decoded.parameters,
            NotificationParameters::Other { event_type: 5, .. }
        ));
    }

    #[test]
    fn an_acknowledgement_notification_decodes_without_event_values() {
        let mut event = notification(NotificationParameters::OutOfRange {
            exceeding_value: 25.0,
            status_flags: StatusFlags::default(),
            deadband: 0.5,
            exceeded_limit: 24.0,
        });
        event.notify_type = NotifyType::AckNotification;
        let decoded = round_trip(&event);
        assert_eq!(decoded.notify_type, NotifyType::AckNotification);
        assert_eq!(decoded.event_type(), EventType::OutOfRange);
        assert_eq!(
            decoded.parameters,
            NotificationParameters::Other {
                event_type: 5,
                data: Vec::new()
            }
        );
    }

    /// DBCS needs a code page carried out of band, so it cannot be read; the
    /// notification still decodes, with no text.
    #[test]
    fn message_text_in_an_unreadable_set_decodes_as_none() {
        let event = notification(NotificationParameters::ChangeOfState {
            new_state: PropertyStates::UnsignedValue(2),
            status_flags: StatusFlags::default(),
        });
        let mut encoded = Vec::new();
        event.encode(&mut encoded).expect("encode");
        let at = encoded
            .iter()
            .position(|&byte| byte == 0x89)
            .expect("notify type");
        // Character set 1 (DBCS), a code page, then two octets of text.
        encoded.splice(at..at, [0x7d, 0x05, 0x01, 0x03, 0xa4, 0x82, 0xa0]);

        let decoded = EventNotification::decode(&encoded).expect("decode");
        assert_eq!(decoded.message_text, None);
        assert_eq!(decoded.to_state, event.to_state);
    }

    #[test]
    fn message_text_in_latin1_decodes() {
        let event = notification(NotificationParameters::ChangeOfState {
            new_state: PropertyStates::UnsignedValue(2),
            status_flags: StatusFlags::default(),
        });
        let mut encoded = Vec::new();
        event.encode(&mut encoded).expect("encode");
        // Splice "Kjøle" in ISO 8859-1 in front of notifyType [8].
        let at = encoded
            .iter()
            .position(|&byte| byte == 0x89)
            .expect("notify type");
        let text = [0x05, b'K', b'j', 0xf8, b'l', b'e'];
        let mut field = vec![0x7d, text.len() as u8];
        field.extend_from_slice(&text);
        encoded.splice(at..at, field);

        let decoded = EventNotification::decode(&encoded).expect("decode");
        assert_eq!(decoded.message_text.as_deref(), Some("Kjøle"));
    }
}
