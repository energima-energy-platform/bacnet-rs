//! Regression tests for service decoders that used to accept malformed input.
//!
//! These cover the cases where a truncated or corrupt optional field was
//! previously indistinguishable from an absent one, and the character sets a
//! CharacterString may declare but that were all read as UTF-8.

use bacnet_rs::encoding::{
    decode_character_string, encode_character_string, encode_context_unsigned, encode_real,
    CharacterSet, EncodingError,
};
use bacnet_rs::object::{ObjectIdentifier, ObjectType};
use bacnet_rs::service::{SubscribeCovPropertyRequest, SubscribeCovRequest, WritePropertyRequest};

fn analog_value(instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::AnalogValue, instance)
}

/// A CharacterString carrying `payload` after the character-set octet.
fn character_string(character_set: u8, payload: &[u8]) -> Vec<u8> {
    let length = payload.len() + 1;
    let mut data = if length < 5 {
        vec![(7u8 << 4) | length as u8]
    } else {
        vec![(7u8 << 4) | 5, length as u8]
    };
    data.push(character_set);
    data.extend_from_slice(payload);
    data
}

// ---------------------------------------------------------------- WriteProperty

#[test]
fn a_write_property_request_round_trips() {
    let mut value = Vec::new();
    encode_real(&mut value, 21.5).unwrap();

    let original = WritePropertyRequest {
        object_identifier: analog_value(7),
        property_identifier: 85,
        property_array_index: Some(3),
        property_value: value,
        priority: Some(8),
    };

    let mut encoded = Vec::new();
    original.encode(&mut encoded).unwrap();
    let decoded = WritePropertyRequest::decode(&encoded).unwrap();

    assert_eq!(decoded.object_identifier, original.object_identifier);
    assert_eq!(decoded.property_identifier, original.property_identifier);
    assert_eq!(decoded.property_array_index, original.property_array_index);
    assert_eq!(decoded.property_value, original.property_value);
    assert_eq!(decoded.priority, original.priority);
}

#[test]
fn a_write_property_request_round_trips_without_its_optional_fields() {
    let mut value = Vec::new();
    encode_real(&mut value, 0.0).unwrap();

    let original = WritePropertyRequest::new(analog_value(1), 85, value);

    let mut encoded = Vec::new();
    original.encode(&mut encoded).unwrap();
    let decoded = WritePropertyRequest::decode(&encoded).unwrap();

    assert_eq!(decoded.property_array_index, None);
    assert_eq!(decoded.priority, None);
}

#[test]
fn a_truncated_priority_fails_the_write_rather_than_reading_as_absent() {
    let mut value = Vec::new();
    encode_real(&mut value, 21.5).unwrap();
    let request = WritePropertyRequest {
        priority: Some(8),
        ..WritePropertyRequest::new(analog_value(7), 85, value)
    };

    let mut encoded = Vec::new();
    request.encode(&mut encoded).unwrap();

    // Drop the priority's value octet, leaving its tag behind. This used to
    // decode as a valid write at no priority at all.
    encoded.pop();
    assert!(
        WritePropertyRequest::decode(&encoded).is_err(),
        "a priority tag with no value must not decode as an absent priority"
    );
}

#[test]
fn a_malformed_array_index_fails_the_write_rather_than_reading_as_absent() {
    let mut value = Vec::new();
    encode_real(&mut value, 21.5).unwrap();
    let request = WritePropertyRequest {
        property_array_index: Some(300),
        ..WritePropertyRequest::new(analog_value(7), 85, value)
    };

    let mut encoded = Vec::new();
    request.encode(&mut encoded).unwrap();

    // The array index is context tag 2 with a two-octet value. Claim a length
    // that runs past the end of the field. The decoder used to swallow every
    // error here into `None`; the misalignment then happened to trip the next
    // check, so this guards the intent rather than pinning a past failure.
    let tag_position = encoded
        .iter()
        .position(|&byte| byte == 0x2A)
        .expect("context tag 2, length 2");
    encoded[tag_position] = 0x2C;

    assert!(
        WritePropertyRequest::decode(&encoded).is_err(),
        "a corrupt array index must not decode as an absent one"
    );
}

// ------------------------------------------------------------------ SubscribeCOV

#[test]
fn subscribe_cov_round_trips_through_the_shared_header() {
    for (confirmed, lifetime) in [
        (Some(true), Some(600u32)),
        (Some(false), None),
        (None, Some(0)),
        (None, None),
    ] {
        let original = SubscribeCovRequest {
            subscriber_process_identifier: 42,
            monitored_object_identifier: analog_value(9),
            issue_confirmed_notifications: confirmed,
            lifetime,
        };

        let mut encoded = Vec::new();
        original.encode(&mut encoded).unwrap();
        let decoded = SubscribeCovRequest::decode(&encoded).unwrap();

        assert_eq!(decoded.subscriber_process_identifier, 42);
        assert_eq!(decoded.monitored_object_identifier, analog_value(9));
        assert_eq!(decoded.issue_confirmed_notifications, confirmed);
        assert_eq!(decoded.lifetime, lifetime);
        assert_eq!(
            decoded.is_cancellation(),
            confirmed.is_none() && lifetime.is_none()
        );
    }
}

#[test]
fn an_application_tag_is_not_mistaken_for_a_subscribe_option() {
    // Application UnsignedInt (tag 2) where the optional context tag 2 would
    // sit. Matching on the tag nibble alone used to read this as the confirmed
    // -notifications flag.
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&encode_context_unsigned(42, 0).unwrap());
    encoded.extend_from_slice(&[0x1C]); // context tag 1, length 4
    encoded.extend_from_slice(&u32::try_from(analog_value(9)).unwrap().to_be_bytes());
    encoded.extend_from_slice(&[0x21, 0x01]); // application UnsignedInt 1

    let decoded = SubscribeCovRequest::decode(&encoded).unwrap();
    assert_eq!(
        decoded.issue_confirmed_notifications, None,
        "an application tag is not context tag 2"
    );
}

#[test]
fn subscribe_cov_property_round_trips_with_the_same_header() {
    use bacnet_rs::service::PropertyReference;

    let original = SubscribeCovPropertyRequest {
        subscriber_process_identifier: 7,
        monitored_object_identifier: analog_value(4),
        issue_confirmed_notifications: Some(true),
        lifetime: Some(120),
        monitored_property: PropertyReference {
            property_identifier: 85u32.into(),
            property_array_index: None,
        },
        cov_increment: Some(0.5),
    };

    let mut encoded = Vec::new();
    original.encode(&mut encoded).unwrap();
    let decoded = SubscribeCovPropertyRequest::decode(&encoded).unwrap();

    assert_eq!(decoded.subscriber_process_identifier, 7);
    assert_eq!(decoded.monitored_object_identifier, analog_value(4));
    assert_eq!(decoded.issue_confirmed_notifications, Some(true));
    assert_eq!(decoded.lifetime, Some(120));
    assert_eq!(decoded.cov_increment, Some(0.5));
}

// --------------------------------------------------------------- Character sets

#[test]
fn a_utf8_character_string_round_trips() {
    let mut encoded = Vec::new();
    encode_character_string(&mut encoded, "Zone 3 Setpoint").unwrap();
    let (value, consumed) = decode_character_string(&encoded).unwrap();
    assert_eq!(value, "Zone 3 Setpoint");
    assert_eq!(consumed, encoded.len());
}

#[test]
fn a_ucs2_character_string_is_not_read_as_utf8() {
    // "Kjøl" in UCS-2 big-endian. Read as UTF-8 this is either an error or
    // mojibake; it used to be handed to String::from_utf8 regardless.
    let payload: Vec<u8> = "Kjøl".encode_utf16().flat_map(u16::to_be_bytes).collect();
    let encoded = character_string(CharacterSet::Ucs2 as u8, &payload);

    let (value, consumed) = decode_character_string(&encoded).unwrap();
    assert_eq!(value, "Kjøl");
    assert_eq!(consumed, encoded.len());
}

#[test]
fn a_latin1_character_string_is_not_read_as_utf8() {
    // 0xF8 is o-slash in Latin-1 and an invalid UTF-8 lead byte.
    let encoded = character_string(CharacterSet::Latin1 as u8, &[b'K', b'j', 0xF8, b'l']);

    let (value, _) = decode_character_string(&encoded).unwrap();
    assert_eq!(value, "Kjøl");
}

#[test]
fn a_ucs4_character_string_decodes() {
    let payload: Vec<u8> = "Ok✓"
        .chars()
        .flat_map(|c| (c as u32).to_be_bytes())
        .collect();
    let encoded = character_string(CharacterSet::Ucs4 as u8, &payload);

    let (value, _) = decode_character_string(&encoded).unwrap();
    assert_eq!(value, "Ok✓");
}

#[test]
fn character_sets_that_need_a_code_page_are_reported_not_guessed() {
    for character_set in [CharacterSet::Dbcs as u8, CharacterSet::JisX0208 as u8] {
        let encoded = character_string(character_set, &[0x82, 0xA0]);
        assert!(
            matches!(
                decode_character_string(&encoded),
                Err(EncodingError::InvalidFormat(_))
            ),
            "character set {character_set} cannot be interpreted here"
        );
    }
}

#[test]
fn an_unknown_character_set_is_rejected() {
    let encoded = character_string(99, b"whatever");
    assert!(matches!(
        decode_character_string(&encoded),
        Err(EncodingError::InvalidFormat(_))
    ));
}

#[test]
fn a_ucs2_string_with_an_odd_octet_count_is_rejected() {
    let encoded = character_string(CharacterSet::Ucs2 as u8, &[0x00, 0x4B, 0x00]);
    assert!(matches!(
        decode_character_string(&encoded),
        Err(EncodingError::InvalidFormat(_))
    ));
}
