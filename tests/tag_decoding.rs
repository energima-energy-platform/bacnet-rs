//! Regression tests for the BACnet tag layer.
//!
//! Each test here pins down a decoder defect that was reachable from the wire:
//! a panic on an over-long integer, a context tag accepted as an application
//! tag, and tag numbers above 14 that this library could encode but not decode.

use bacnet_rs::encoding::{
    decode_application_tag, decode_closing_tag, decode_context_tag, decode_opening_tag,
    decode_signed64, decode_tag, decode_unsigned64, encode_closing_tag, encode_context_tag,
    encode_opening_tag, is_closing_tag, is_context_tag, is_opening_tag, ApplicationTag, BACnetTag,
    EncodingError,
};

/// An application UnsignedInt whose extended length says `length` octets follow,
/// with that many octets of payload.
fn application_integer(tag: u8, length: u8) -> Vec<u8> {
    let mut data = vec![tag << 4 | 5, length];
    data.extend(std::iter::repeat_n(0x01, length as usize));
    data
}

#[test]
fn an_unsigned_longer_than_eight_octets_is_rejected_not_fatal() {
    // Nine octets leaves no room in a u64. The decoder used to compute `8 -
    // length` on a usize and panic before it ever looked at the value.
    for length in 9..=32u8 {
        let data = application_integer(ApplicationTag::UnsignedInt as u8, length);
        assert!(
            matches!(decode_unsigned64(&data), Err(EncodingError::InvalidLength)),
            "unsigned of {length} octets should be rejected, not panic"
        );
    }
}

#[test]
fn a_signed_longer_than_eight_octets_is_rejected_not_fatal() {
    for length in 9..=32u8 {
        let data = application_integer(ApplicationTag::SignedInt as u8, length);
        assert!(
            matches!(decode_signed64(&data), Err(EncodingError::InvalidLength)),
            "signed of {length} octets should be rejected, not panic"
        );
    }
}

#[test]
fn integers_of_every_legal_width_still_round_trip() {
    for length in 1..=8u8 {
        let data = application_integer(ApplicationTag::UnsignedInt as u8, length);
        let (value, consumed) = decode_unsigned64(&data).expect("legal width");
        assert_eq!(consumed, data.len());
        // Payload is 0x01 repeated, so the value is that pattern in the low octets.
        let expected = (0..length).fold(0u64, |acc, _| (acc << 8) | 1);
        assert_eq!(value, expected, "width {length}");

        let data = application_integer(ApplicationTag::SignedInt as u8, length);
        let (value, consumed) = decode_signed64(&data).expect("legal width");
        assert_eq!(consumed, data.len());
        assert_eq!(value, expected as i64, "width {length}");
    }
}

#[test]
fn a_negative_signed_sign_extends_at_every_width() {
    // All-ones at any width is -1, which only holds if the leading octets are
    // filled from the sign bit rather than with zeroes.
    for length in 1..=8u8 {
        let mut data = vec![(ApplicationTag::SignedInt as u8) << 4 | 5, length];
        data.extend(std::iter::repeat_n(0xFF, length as usize));

        let (value, consumed) = decode_signed64(&data).expect("legal width");
        assert_eq!(value, -1, "width {length}");
        assert_eq!(consumed, data.len());
    }

    // A leading octet below 0x80 stays positive at every width.
    for length in 1..=8u8 {
        let mut data = vec![(ApplicationTag::SignedInt as u8) << 4 | 5, length];
        data.push(0x7F);
        data.extend(std::iter::repeat_n(0x00, length as usize - 1));

        let (value, _) = decode_signed64(&data).expect("legal width");
        assert!(
            value > 0,
            "width {length} should stay positive, got {value}"
        );
    }
}

#[test]
fn a_context_tag_is_not_read_as_an_application_tag() {
    // Context tag 2, length 1. The class bit used to be folded into the length,
    // yielding a bogus application UnsignedInt of length 9.
    let data = [0x29u8, 0x05];

    assert!(matches!(
        decode_application_tag(&data),
        Err(EncodingError::InvalidTag)
    ));

    let (tag, length, consumed) = decode_tag(&data).expect("a valid context tag");
    assert_eq!(tag, BACnetTag::Context(2));
    assert_eq!(length, 1);
    assert_eq!(consumed, 1);
}

#[test]
fn an_application_tag_is_not_read_as_a_context_tag() {
    // Application UnsignedInt (tag 2) carrying one octet. Tests that matched on
    // the tag nibble alone used to accept this as context tag 2.
    let data = [0x21u8, 0x05];

    assert!(!is_context_tag(&data, 2));
    assert!(matches!(
        decode_context_tag(&data),
        Err(EncodingError::InvalidTag)
    ));
    assert_eq!(
        decode_application_tag(&data).expect("an application tag").0,
        ApplicationTag::UnsignedInt
    );
}

#[test]
fn opening_and_closing_tags_report_themselves_as_such() {
    let opening = [0x3Eu8];
    let closing = [0x3Fu8];

    assert_eq!(decode_tag(&opening).unwrap().0, BACnetTag::Opening(3));
    assert_eq!(decode_tag(&closing).unwrap().0, BACnetTag::Closing(3));

    // They carry no value of their own, so they report no length rather than the
    // 6 and 7 their nibble happens to hold.
    assert_eq!(decode_tag(&opening).unwrap().1, 0);
    assert_eq!(decode_tag(&closing).unwrap().1, 0);

    // And they are not primitive context tags.
    assert!(matches!(
        decode_context_tag(&opening),
        Err(EncodingError::InvalidTag)
    ));
    assert!(matches!(
        decode_context_tag(&closing),
        Err(EncodingError::InvalidTag)
    ));
}

#[test]
fn an_application_tag_may_not_use_the_opening_or_closing_nibble() {
    // Nibble 6 and 7 on the application class: lengths above 4 must use the
    // extended form, so these are malformed rather than 6- and 7-octet values.
    for tag_byte in [0x26u8, 0x27] {
        assert!(matches!(
            decode_tag(&[tag_byte, 0, 0, 0, 0, 0, 0, 0]),
            Err(EncodingError::InvalidTag)
        ));
    }
}

#[test]
fn context_tags_above_fourteen_round_trip() {
    // Change-of-reliability notification parameters are context 19, which needs
    // the extended tag-number form of clause 20.2.1.2. The encoder emitted it;
    // the decoder used to return tag 15 and consume one octet too few.
    for tag_number in [15u8, 19, 100, 254] {
        let mut buffer = Vec::new();
        encode_context_tag(&mut buffer, tag_number, 1).unwrap();
        buffer.push(0x42);

        let (tag, length, consumed) = decode_tag(&buffer).expect("an extended context tag");
        assert_eq!(tag, BACnetTag::Context(tag_number));
        assert_eq!(length, 1);
        assert_eq!(consumed, 2, "the tag number occupies a second octet");
        assert_eq!(buffer[consumed], 0x42, "the value follows the whole tag");

        assert_eq!(
            decode_context_tag(&buffer).unwrap(),
            (tag_number, 1, 2),
            "tag {tag_number}"
        );
    }
}

#[test]
fn opening_and_closing_tags_above_fourteen_round_trip() {
    for tag_number in [15u8, 19, 100, 254] {
        let mut buffer = Vec::new();
        encode_opening_tag(&mut buffer, tag_number).unwrap();
        encode_closing_tag(&mut buffer, tag_number).unwrap();

        assert_eq!(buffer.len(), 4, "two octets each in the extended form");

        assert!(is_opening_tag(&buffer, tag_number));
        let consumed = decode_opening_tag(&buffer, tag_number).expect("an opening tag");
        assert_eq!(consumed, 2);

        assert!(is_closing_tag(&buffer[consumed..], tag_number));
        assert_eq!(
            decode_closing_tag(&buffer[consumed..], tag_number).expect("a closing tag"),
            2
        );
    }
}

#[test]
fn an_extended_tag_number_does_not_alias_a_small_one() {
    // 19 << 4 truncates to 0x30, so a predicate built by shifting the tag number
    // into the nibble would match opening tag 3 here.
    let mut extended = Vec::new();
    encode_opening_tag(&mut extended, 19).unwrap();

    assert!(is_opening_tag(&extended, 19));
    assert!(!is_opening_tag(&extended, 3));

    let mut small = Vec::new();
    encode_opening_tag(&mut small, 3).unwrap();

    assert!(is_opening_tag(&small, 3));
    assert!(!is_opening_tag(&small, 19));
}

#[test]
fn a_truncated_extended_tag_number_is_rejected() {
    // The initial octet promises a tag number that never arrives.
    assert!(matches!(
        decode_tag(&[0xF9u8]),
        Err(EncodingError::BufferUnderflow)
    ));
}

#[test]
fn truncated_extended_lengths_are_rejected() {
    // Length nibble 5 promises length octets that never arrive, at each width.
    assert!(decode_tag(&[0x25u8]).is_err());
    assert!(decode_tag(&[0x25u8, 254]).is_err());
    assert!(decode_tag(&[0x25u8, 254, 0x01]).is_err());
    assert!(decode_tag(&[0x25u8, 255]).is_err());
    assert!(decode_tag(&[0x25u8, 255, 0x01, 0x02, 0x03]).is_err());

    // The same, behind an extended tag number, where the length octets start one
    // position later than usual.
    assert!(decode_tag(&[0xFDu8, 19, 254]).is_err());
}

#[test]
fn extended_lengths_decode_at_each_width() {
    let (_, length, consumed) = decode_tag(&[0x25u8, 200]).unwrap();
    assert_eq!((length, consumed), (200, 2));

    let (_, length, consumed) = decode_tag(&[0x25u8, 254, 0x01, 0x00]).unwrap();
    assert_eq!((length, consumed), (256, 4));

    let (_, length, consumed) = decode_tag(&[0x25u8, 255, 0x00, 0x01, 0x00, 0x00]).unwrap();
    assert_eq!((length, consumed), (65536, 6));

    // Behind an extended tag number the length octets shift by one.
    let (tag, length, consumed) = decode_tag(&[0xFDu8, 19, 254, 0x01, 0x00]).unwrap();
    assert_eq!(tag, BACnetTag::Context(19));
    assert_eq!((length, consumed), (256, 5));
}

#[test]
fn an_empty_buffer_decodes_to_an_error_not_a_panic() {
    assert!(decode_tag(&[]).is_err());
    assert!(decode_application_tag(&[]).is_err());
    assert!(decode_context_tag(&[]).is_err());
    assert!(!is_opening_tag(&[], 0));
    assert!(!is_closing_tag(&[], 0));
    assert!(!is_context_tag(&[], 0));
}
