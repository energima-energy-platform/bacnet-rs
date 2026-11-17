//! GetEventInformation (135-2020 13.12) and GetAlarmSummary (13.10): what a
//! device holds outside normal, or awaiting acknowledgement, right now. How a
//! recipient that missed notifications learns the state it missed.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::encoding::{
    advanced::bitstring::{decode_bit_string, encode_bit_string},
    decode_closing_tag, decode_context_bit_string, decode_context_boolean,
    decode_context_enumerated, decode_context_object_id, decode_enumerated,
    decode_object_identifier, decode_opening_tag, decode_unsigned, encode_closing_tag,
    encode_context_bit_string, encode_context_boolean, encode_context_enumerated,
    encode_context_object_id, encode_enumerated, encode_object_identifier, encode_opening_tag,
    encode_unsigned, is_closing_tag, is_context_tag, EncodingError, Result as EncodingResult,
};
use crate::object::{intrinsic::NotifyType, EventState, ObjectIdentifier};
use crate::property::TimestampValue;
use crate::service::event_notification::event_state;

/// GetEventInformation-Request: the first page, or the page after the object
/// the previous one ended on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GetEventInformationRequest {
    pub last_received_object_identifier: Option<ObjectIdentifier>,
}

impl GetEventInformationRequest {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        if let Some(object) = self.last_received_object_identifier {
            buffer.extend_from_slice(&encode_context_object_id(object, 0)?);
        }
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let last_received_object_identifier = if data.is_empty() {
            None
        } else {
            Some(decode_context_object_id(data, 0)?.0)
        };
        Ok(Self {
            last_received_object_identifier,
        })
    }
}

/// One object's entry in a GetEventInformation-ACK. Transition-indexed fields
/// are ordered to-offnormal, to-fault, to-normal.
#[derive(Debug, Clone, PartialEq)]
pub struct EventSummary {
    pub object_identifier: ObjectIdentifier,
    pub event_state: EventState,
    pub acknowledged_transitions: [bool; 3],
    pub event_time_stamps: [TimestampValue; 3],
    pub notify_type: NotifyType,
    pub event_enable: [bool; 3],
    pub event_priorities: [u32; 3],
}

impl EventSummary {
    /// Octets this summary takes in a GetEventInformation-ACK.
    pub fn encoded_len(&self) -> usize {
        let mut buffer = Vec::new();
        self.encode(&mut buffer).map_or(0, |()| buffer.len())
    }

    fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        buffer.extend_from_slice(&encode_context_object_id(self.object_identifier, 0)?);
        buffer.extend_from_slice(&encode_context_enumerated(
            u16::from(self.event_state).into(),
            1,
        )?);
        encode_context_bit_string(buffer, 2, &self.acknowledged_transitions)?;
        encode_opening_tag(buffer, 3)?;
        for stamp in &self.event_time_stamps {
            stamp.encode(buffer)?;
        }
        encode_closing_tag(buffer, 3)?;
        buffer.extend_from_slice(&encode_context_enumerated(self.notify_type.into(), 4)?);
        encode_context_bit_string(buffer, 5, &self.event_enable)?;
        encode_opening_tag(buffer, 6)?;
        for priority in self.event_priorities {
            encode_unsigned(buffer, priority)?;
        }
        encode_closing_tag(buffer, 6)
    }

    fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let (object_identifier, mut offset) = decode_context_object_id(data, 0)?;
        let (state, length) = decode_context_enumerated(&data[offset..], 1)?;
        offset += length;
        let (acknowledged, length) = decode_context_bit_string(&data[offset..], 2)?;
        offset += length;

        offset += decode_opening_tag(&data[offset..], 3)?;
        let mut stamps = Vec::with_capacity(3);
        for _ in 0..3 {
            let (stamp, length) = TimestampValue::decode(&data[offset..])?;
            offset += length;
            stamps.push(stamp);
        }
        offset += decode_closing_tag(&data[offset..], 3)?;

        let (notify_type, length) = decode_context_enumerated(&data[offset..], 4)?;
        offset += length;
        let (enable, length) = decode_context_bit_string(&data[offset..], 5)?;
        offset += length;

        offset += decode_opening_tag(&data[offset..], 6)?;
        let mut event_priorities = [0; 3];
        for priority in &mut event_priorities {
            let (value, length) = decode_unsigned(&data[offset..])?;
            offset += length;
            *priority = value;
        }
        offset += decode_closing_tag(&data[offset..], 6)?;

        Ok((
            Self {
                object_identifier,
                event_state: event_state(state)?,
                acknowledged_transitions: transitions(&acknowledged),
                event_time_stamps: stamps
                    .try_into()
                    .map_err(|_| EncodingError::InvalidLength)?,
                notify_type: NotifyType::try_from(notify_type)
                    .map_err(|_| EncodingError::InvalidFormat("unknown notify type".into()))?,
                event_enable: transitions(&enable),
                event_priorities,
            },
            offset,
        ))
    }
}

/// GetEventInformation-ACK: one page of summaries, and whether another follows.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetEventInformationAck {
    pub list_of_event_summaries: Vec<EventSummary>,
    pub more_events: bool,
}

impl GetEventInformationAck {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        encode_opening_tag(buffer, 0)?;
        for summary in &self.list_of_event_summaries {
            summary.encode(buffer)?;
        }
        encode_closing_tag(buffer, 0)?;
        encode_context_boolean(buffer, 1, self.more_events)
    }

    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let mut offset = decode_opening_tag(data, 0)?;
        let mut list_of_event_summaries = Vec::new();
        while !is_closing_tag(&data[offset..], 0) {
            let (summary, length) = EventSummary::decode(&data[offset..])?;
            offset += length;
            list_of_event_summaries.push(summary);
        }
        offset += decode_closing_tag(&data[offset..], 0)?;
        let more_events = if is_context_tag(&data[offset..], 1) {
            decode_context_boolean(&data[offset..], 1)?.0
        } else {
            false
        };
        Ok(Self {
            list_of_event_summaries,
            more_events,
        })
    }
}

/// One entry of a GetAlarmSummary-ACK: an object in alarm.
#[derive(Debug, Clone, PartialEq)]
pub struct AlarmSummary {
    pub object_identifier: ObjectIdentifier,
    pub alarm_state: EventState,
    pub acknowledged_transitions: [bool; 3],
}

/// GetAlarmSummary-ACK. The request carries no parameters.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetAlarmSummaryAck {
    pub alarms: Vec<AlarmSummary>,
}

impl GetAlarmSummaryAck {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        for alarm in &self.alarms {
            encode_object_identifier(buffer, alarm.object_identifier)?;
            encode_enumerated(buffer, u16::from(alarm.alarm_state).into());
            encode_bit_string(buffer, &alarm.acknowledged_transitions)?;
        }
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let mut offset = 0;
        let mut alarms = Vec::new();
        while offset < data.len() {
            let (object_identifier, length) = decode_object_identifier(&data[offset..])?;
            offset += length;
            let (state, length) = decode_enumerated(&data[offset..])?;
            offset += length;
            let (acknowledged, length) = decode_bit_string(&data[offset..])?;
            offset += length;
            alarms.push(AlarmSummary {
                object_identifier,
                alarm_state: event_state(state)?,
                acknowledged_transitions: transitions(&acknowledged),
            });
        }
        Ok(Self { alarms })
    }
}

/// The three transition bits, reading a short bit string's missing bits as
/// clear.
fn transitions(bits: &[bool]) -> [bool; 3] {
    let bit = |index: usize| bits.get(index).copied().unwrap_or(false);
    [bit(0), bit(1), bit(2)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;

    fn summary(instance: u32) -> EventSummary {
        EventSummary {
            object_identifier: ObjectIdentifier::new(ObjectType::AnalogInput, instance),
            event_state: EventState::HighLimit,
            acknowledged_transitions: [false, true, true],
            event_time_stamps: [
                TimestampValue::DateTime {
                    date: (2026, 11, 17, 2),
                    time: (10, 15, 0, 0),
                },
                TimestampValue::SequenceNumber(0),
                TimestampValue::Time(255, 255, 255, 255),
            ],
            notify_type: NotifyType::Alarm,
            event_enable: [true, true, true],
            event_priorities: [100, 50, 200],
        }
    }

    #[test]
    fn an_event_information_ack_round_trips() {
        let ack = GetEventInformationAck {
            list_of_event_summaries: vec![summary(1), summary(2)],
            more_events: true,
        };
        let mut encoded = Vec::new();
        ack.encode(&mut encoded).unwrap();
        assert_eq!(GetEventInformationAck::decode(&encoded).unwrap(), ack);
    }

    #[test]
    fn a_request_names_where_the_last_page_ended() {
        for request in [
            GetEventInformationRequest::default(),
            GetEventInformationRequest {
                last_received_object_identifier: Some(ObjectIdentifier::new(
                    ObjectType::BinaryInput,
                    7,
                )),
            },
        ] {
            let mut encoded = Vec::new();
            request.encode(&mut encoded).unwrap();
            assert_eq!(
                GetEventInformationRequest::decode(&encoded).unwrap(),
                request
            );
        }
    }

    #[test]
    fn an_alarm_summary_round_trips() {
        let ack = GetAlarmSummaryAck {
            alarms: vec![AlarmSummary {
                object_identifier: ObjectIdentifier::new(ObjectType::BinaryInput, 1),
                alarm_state: EventState::Offnormal,
                acknowledged_transitions: [false, true, true],
            }],
        };
        let mut encoded = Vec::new();
        ack.encode(&mut encoded).unwrap();
        assert_eq!(GetAlarmSummaryAck::decode(&encoded).unwrap(), ack);
    }
}
