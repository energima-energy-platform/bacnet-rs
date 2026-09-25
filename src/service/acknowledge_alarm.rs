//! AcknowledgeAlarm (135-2020 13.5): an operator saying an alarm has been seen.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::encoding::{
    decode_closing_tag, decode_context_enumerated, decode_context_object_id, decode_context_tag,
    decode_context_unsigned, decode_opening_tag, encode_closing_tag, encode_context_enumerated,
    encode_context_object_id, encode_context_tag, encode_context_unsigned, encode_opening_tag,
    EncodingError, Result as EncodingResult,
};
use crate::object::{EventState, ObjectIdentifier};
use crate::property::TimestampValue;

#[derive(Debug, Clone, PartialEq)]
pub struct AcknowledgeAlarmRequest {
    pub acknowledging_process_identifier: u32,
    pub event_object_identifier: ObjectIdentifier,
    /// The state whose transition is acknowledged.
    pub event_state_acknowledged: EventState,
    /// The time stamp of that transition, as the acknowledger was told it.
    pub time_stamp: TimestampValue,
    pub acknowledgment_source: String,
    pub time_of_acknowledgment: TimestampValue,
}

impl AcknowledgeAlarmRequest {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        buffer.extend_from_slice(&encode_context_unsigned(
            self.acknowledging_process_identifier,
            0,
        )?);
        buffer.extend_from_slice(&encode_context_object_id(self.event_object_identifier, 1)?);
        buffer.extend_from_slice(&encode_context_enumerated(
            u16::from(self.event_state_acknowledged).into(),
            2,
        )?);
        encode_opening_tag(buffer, 3)?;
        self.time_stamp.encode(buffer)?;
        encode_closing_tag(buffer, 3)?;
        let source = self.acknowledgment_source.as_bytes();
        encode_context_tag(buffer, 4, source.len() + 1)?;
        buffer.push(0); // ANSI X3.4 / UTF-8
        buffer.extend_from_slice(source);
        encode_opening_tag(buffer, 5)?;
        self.time_of_acknowledgment.encode(buffer)?;
        encode_closing_tag(buffer, 5)
    }

    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let (acknowledging_process_identifier, mut consumed) = decode_context_unsigned(data, 0)?;
        let (event_object_identifier, length) = decode_context_object_id(&data[consumed..], 1)?;
        consumed += length;
        let (state, length) = decode_context_enumerated(&data[consumed..], 2)?;
        consumed += length;
        let event_state_acknowledged =
            EventState::from(u16::try_from(state).map_err(|_| EncodingError::InvalidTag)?);

        let (time_stamp, length) = constructed_timestamp(&data[consumed..], 3)?;
        consumed += length;

        let (tag, length, header) = decode_context_tag(&data[consumed..])?;
        if tag != 4 || length == 0 {
            return Err(EncodingError::InvalidTag);
        }
        let text = data
            .get(consumed + header + 1..consumed + header + length)
            .ok_or(EncodingError::BufferUnderflow)?;
        let acknowledgment_source =
            String::from_utf8(text.to_vec()).map_err(|_| EncodingError::InvalidTag)?;
        consumed += header + length;

        let (time_of_acknowledgment, _) = constructed_timestamp(&data[consumed..], 5)?;

        Ok(Self {
            acknowledging_process_identifier,
            event_object_identifier,
            event_state_acknowledged,
            time_stamp,
            acknowledgment_source,
            time_of_acknowledgment,
        })
    }
}

/// A BACnetTimeStamp inside the opening and closing tags `tag`.
fn constructed_timestamp(data: &[u8], tag: u8) -> EncodingResult<(TimestampValue, usize)> {
    let mut consumed = decode_opening_tag(data, tag)?;
    let (timestamp, length) = TimestampValue::decode(&data[consumed..])?;
    consumed += length;
    consumed += decode_closing_tag(&data[consumed..], tag)?;
    Ok((timestamp, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;

    #[test]
    fn a_request_round_trips() {
        let request = AcknowledgeAlarmRequest {
            acknowledging_process_identifier: 777,
            event_object_identifier: ObjectIdentifier::new(ObjectType::AnalogValue, 1),
            event_state_acknowledged: EventState::HighLimit,
            time_stamp: TimestampValue::SequenceNumber(3),
            acknowledgment_source: "operator".to_string(),
            time_of_acknowledgment: TimestampValue::SequenceNumber(4),
        };
        let mut encoded = Vec::new();
        request.encode(&mut encoded).unwrap();

        assert_eq!(AcknowledgeAlarmRequest::decode(&encoded).unwrap(), request);
    }
}
