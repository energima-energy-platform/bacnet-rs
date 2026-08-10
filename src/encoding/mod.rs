//! BACnet Encoding and Decoding Utilities
//!
//! This module provides comprehensive functionality for encoding and decoding BACnet protocol data
//! according to ASHRAE Standard 135. It handles the serialization and deserialization of all
//! BACnet data types, application tags, and protocol structures.
//!
//! # Overview
//!
//! The BACnet encoding system uses a tag-length-value (TLV) format where each data element
//! consists of:
//!
//! - **Tag**: Identifies the data type and context
//! - **Length**: Specifies the length of the value (for variable-length types)
//! - **Value**: The actual data content
//!
//! This module provides functionality for:
//!
//! - **Primitive Types**: Boolean, Unsigned/Signed integers, Real numbers, Double precision, etc.
//! - **String Types**: Character strings, Bit strings, Octet strings
//! - **Time Types**: Date, Time, DateTime values
//! - **Object Types**: Object identifiers, Property identifiers
//! - **Constructed Types**: Arrays, Lists, Sequences
//! - **Context Tags**: Application-specific encoding contexts
//!
//! # Application Tags
//!
//! BACnet defines standard application tags for common data types:
//!
//! | Tag | Type | Description |
//! |-----|------|-------------|
//! | 0 | Null | No value |
//! | 1 | Boolean | True/False |
//! | 2 | Unsigned Integer | 8, 16, 24, or 32-bit unsigned |
//! | 3 | Signed Integer | 8, 16, 24, or 32-bit signed |
//! | 4 | Real | 32-bit IEEE 754 float |
//! | 5 | Double | 64-bit IEEE 754 double |
//! | 6 | Octet String | Arbitrary byte sequence |
//! | 7 | Character String | Text with encoding indicator |
//! | 8 | Bit String | Bit field with unused bits count |
//! | 9 | Enumerated | Unsigned integer representing enumeration |
//! | 10 | Date | Year, month, day, day-of-week |
//! | 11 | Time | Hour, minute, second, hundredths |
//! | 12 | Object Identifier | Object type and instance |
//!
//! # Examples
//!
//! ## Encoding Basic Types
//!
//! ```rust
//! use bacnet_rs::encoding::{encode_unsigned, encode_real, ApplicationTag};
//!
//! let mut buffer = Vec::new();
//!
//! // Encode an unsigned integer with application tag
//! encode_unsigned(&mut buffer, 42).unwrap();
//!
//! // Encode a real number with application tag
//! encode_real(&mut buffer, 23.5).unwrap();
//!
//! println!("Encoded {} bytes", buffer.len());
//! ```
//!
//! ## Decoding Basic Types
//!
//! ```rust
//! use bacnet_rs::encoding::{decode_unsigned, ApplicationTag};
//!
//! // Sample encoded data (tag + value)
//! let data = vec![0x21, 0x2A]; // Unsigned integer 42
//!
//! // Decode the value
//! let (value, consumed) = decode_unsigned(&data).unwrap();
//! assert_eq!(value, 42);
//! assert_eq!(consumed, 2);
//! ```
//!
//! ## Working with Application Tags
//!
//! ```rust
//! use bacnet_rs::encoding::{ApplicationTag, decode_application_tag};
//!
//! let data = vec![0x21, 0x2A]; // Unsigned integer
//! let (tag, length, consumed) = decode_application_tag(&data).unwrap();
//! assert_eq!(tag, ApplicationTag::UnsignedInt);
//! ```
//!
//! ## Context-Specific Encoding
//!
//! ```rust
//! use bacnet_rs::encoding::{encode_context_unsigned, decode_context_unsigned};
//!
//! // Encode with context tag 3
//! let buffer = encode_context_unsigned(1000, 3).unwrap();
//!
//! // Decode with expected context tag 3
//! let (value, consumed) = decode_context_unsigned(&buffer, 3).unwrap();
//! assert_eq!(value, 1000);
//! ```
//!
//! # Error Handling
//!
//! Encoding operations can fail for several reasons:
//!
//! - **Buffer Overflow**: Output buffer is too small
//! - **Invalid Data**: Input data is malformed or invalid
//! - **Type Mismatch**: Data doesn't match expected type
//! - **Length Error**: Incorrect length fields
//!
//! ```rust
//! use bacnet_rs::encoding::{EncodingError, decode_unsigned};
//!
//! let invalid_data = vec![0x21]; // Missing value byte
//! match decode_unsigned(&invalid_data) {
//!     Ok((value, _)) => println!("Value: {}", value),
//!     Err(EncodingError::BufferUnderflow) => println!("Not enough data"),
//!     Err(e) => println!("Other error: {:?}", e),
//! }
//! ```
//!
//! # Performance Notes
//!
//! - Encoding functions write directly to provided buffers for efficiency
//! - Decoding functions return both the decoded value and bytes consumed
//! - No dynamic allocation is required for basic encoding/decoding operations
//! - Context tag validation is performed during decoding for safety

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::object::ObjectIdentifier;

/// Result type for encoding operations
#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, EncodingError>;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, EncodingError>;

/// Errors that can occur during encoding/decoding operations
#[derive(Debug, Clone)]
pub enum EncodingError {
    /// Buffer overflow during encoding
    BufferOverflow,
    /// Buffer underflow during decoding
    BufferUnderflow,
    /// Invalid tag number encountered
    InvalidTag,
    /// Invalid length value
    InvalidLength,
    /// Unexpected end of data during decoding
    UnexpectedEndOfData,
    /// Invalid encoding format
    InvalidFormat(String),
    /// Value out of valid range
    ValueOutOfRange,
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodingError::BufferOverflow => write!(f, "Buffer overflow during encoding"),
            EncodingError::BufferUnderflow => write!(f, "Buffer underflow during decoding"),
            EncodingError::InvalidTag => write!(f, "Invalid tag number encountered"),
            EncodingError::InvalidLength => write!(f, "Invalid length value"),
            EncodingError::UnexpectedEndOfData => write!(f, "Unexpected end of data"),
            EncodingError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            EncodingError::ValueOutOfRange => write!(f, "Value out of valid range"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for EncodingError {}

/// BACnet application tag numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApplicationTag {
    Null = 0,
    Boolean = 1,
    UnsignedInt = 2,
    SignedInt = 3,
    Real = 4,
    Double = 5,
    OctetString = 6,
    CharacterString = 7,
    BitString = 8,
    Enumerated = 9,
    Date = 10,
    Time = 11,
    ObjectIdentifier = 12,
    Reserved13 = 13,
    Reserved14 = 14,
    Reserved15 = 15,
}

/// A decoded BACnet tag.
///
/// Context-specific tags come in three forms that share an encoding but mean
/// different things: a primitive tag introducing a value, and the opening and
/// closing markers that bracket constructed data. Keeping them as separate
/// variants means callers never have to re-read the length-value-type nibble out
/// of the buffer to tell which one they are holding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BACnetTag {
    /// An application tag introducing a primitive value.
    Application(ApplicationTag),
    /// A context-specific tag introducing a primitive value.
    Context(u8),
    /// The opening marker of constructed context-specific data.
    Opening(u8),
    /// The closing marker of constructed context-specific data.
    Closing(u8),
}

impl BACnetTag {
    /// The context tag number, for any of the three context-specific forms.
    pub fn context_number(&self) -> Option<u8> {
        match self {
            BACnetTag::Context(tag) | BACnetTag::Opening(tag) | BACnetTag::Closing(tag) => {
                Some(*tag)
            }
            BACnetTag::Application(_) => None,
        }
    }
}

/// Class bit of the initial octet: set for context-specific tags.
const CONTEXT_CLASS_BIT: u8 = 0x08;

/// Length-value-type nibble meaning "the length follows in extended form".
const LVT_EXTENDED_LENGTH: u8 = 5;

/// Length-value-type nibble marking an opening tag.
const LVT_OPENING_TAG: u8 = 6;

/// Length-value-type nibble marking a closing tag.
const LVT_CLOSING_TAG: u8 = 7;

/// Tag-number nibble B'1111', meaning the real tag number follows the initial
/// octet (clause 20.2.1.2).
const EXTENDED_TAG_NUMBER: u8 = 15;

/// Read the extended length octets that follow an initial octet whose
/// length-value-type nibble is 5.
///
/// `offset` is the index of the first length octet, which is not always 1: an
/// extended tag number is encoded ahead of the length. Returns the length and
/// how many octets it occupied.
fn read_extended_length(data: &[u8], offset: usize) -> Result<(usize, usize)> {
    match *data.get(offset).ok_or(EncodingError::BufferUnderflow)? {
        length @ 0..=253 => Ok((length as usize, 1)),
        254 => {
            let bytes = data
                .get(offset + 1..offset + 3)
                .ok_or(EncodingError::BufferUnderflow)?;
            Ok((u16::from_be_bytes([bytes[0], bytes[1]]) as usize, 3))
        }
        _ => {
            let bytes = data
                .get(offset + 1..offset + 5)
                .ok_or(EncodingError::BufferUnderflow)?;
            Ok((
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize,
                5,
            ))
        }
    }
}

/// Decode any BACnet tag from the front of `data`.
///
/// Returns the tag, the length of the value that follows it, and how many octets
/// the tag itself occupied. Opening and closing tags introduce no value of their
/// own and so report a length of zero.
pub fn decode_tag(data: &[u8]) -> Result<(BACnetTag, usize, usize)> {
    let tag_byte = *data.first().ok_or(EncodingError::InvalidTag)?;
    let is_context = tag_byte & CONTEXT_CLASS_BIT != 0;
    let lvt = tag_byte & 0x07;

    let mut tag_number = tag_byte >> 4;
    let mut consumed = 1;

    if tag_number == EXTENDED_TAG_NUMBER {
        // Application tag numbers only run to 12, so the extended form is
        // context-specific by construction.
        if !is_context {
            return Err(EncodingError::InvalidTag);
        }
        tag_number = *data.get(1).ok_or(EncodingError::BufferUnderflow)?;
        consumed = 2;
    }

    if is_context {
        match lvt {
            LVT_OPENING_TAG => return Ok((BACnetTag::Opening(tag_number), 0, consumed)),
            LVT_CLOSING_TAG => return Ok((BACnetTag::Closing(tag_number), 0, consumed)),
            _ => {}
        }
    } else if lvt >= LVT_OPENING_TAG {
        // Clause 20.2.1.3.1: an application tag's nibble is a length, and lengths
        // above 4 use the extended form. 6 and 7 are opening and closing markers,
        // which exist only for context-specific tags.
        return Err(EncodingError::InvalidTag);
    }

    let length = if lvt == LVT_EXTENDED_LENGTH {
        let (length, extra) = read_extended_length(data, consumed)?;
        consumed += extra;
        length
    } else {
        lvt as usize
    };

    let tag = if is_context {
        BACnetTag::Context(tag_number)
    } else {
        BACnetTag::Application(ApplicationTag::try_from(tag_number)?)
    };

    Ok((tag, length, consumed))
}

/// Write the extended length octets for a value of `length` octets.
///
/// Only called once the initial octet's length-value-type nibble has been set to
/// 5 to say they are coming.
fn write_extended_length(buffer: &mut Vec<u8>, length: usize) {
    if length < 254 {
        buffer.push(length as u8);
    } else if length < 65536 {
        buffer.push(254);
        buffer.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        buffer.push(255);
        buffer.extend_from_slice(&(length as u32).to_be_bytes());
    }
}

/// Encode a BACnet application tag
pub fn encode_application_tag(buffer: &mut Vec<u8>, tag: ApplicationTag, length: usize) {
    let tag_byte = if length < LVT_EXTENDED_LENGTH as usize {
        (tag as u8) << 4 | (length as u8)
    } else {
        (tag as u8) << 4 | LVT_EXTENDED_LENGTH
    };

    buffer.push(tag_byte);

    if length >= LVT_EXTENDED_LENGTH as usize {
        write_extended_length(buffer, length);
    }
}

/// Decode a BACnet application tag.
///
/// Rejects context-specific tags rather than reading their class bit as part of
/// the length, which would silently inflate it by eight.
pub fn decode_application_tag(data: &[u8]) -> Result<(ApplicationTag, usize, usize)> {
    match decode_tag(data)? {
        (BACnetTag::Application(tag), length, consumed) => Ok((tag, length, consumed)),
        _ => Err(EncodingError::InvalidTag),
    }
}

/// Encode a BACnet boolean value
pub fn encode_boolean(buffer: &mut Vec<u8>, value: bool) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Boolean, if value { 1 } else { 0 });
    Ok(())
}

/// Decode a BACnet boolean value
pub fn decode_boolean(data: &[u8]) -> Result<(bool, usize)> {
    let (tag, length, consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::Boolean {
        return Err(EncodingError::InvalidTag);
    }

    let value = match length {
        0 => false,
        1 => true,
        _ => return Err(EncodingError::InvalidLength),
    };

    Ok((value, consumed))
}

/// Encode a BACnet unsigned integer
pub fn encode_unsigned(buffer: &mut Vec<u8>, value: u32) -> Result<()> {
    let bytes = if value == 0 {
        vec![0]
    } else if value <= 0xFF {
        vec![value as u8]
    } else if value <= 0xFFFF {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= 0xFFFFFF {
        let bytes = value.to_be_bytes();
        bytes[1..].to_vec()
    } else {
        value.to_be_bytes().to_vec()
    };

    encode_application_tag(buffer, ApplicationTag::UnsignedInt, bytes.len());
    buffer.extend_from_slice(&bytes);
    Ok(())
}

pub fn encode_unsigned64(buffer: &mut Vec<u8>, value: u64) {
    let bytes = if value == 0 {
        vec![0]
    } else if value <= 0xFF {
        vec![value as u8]
    } else if value <= 0xFFFF {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= 0xFFFFFF {
        let bytes = value.to_be_bytes();
        bytes[1..].to_vec()
    } else if value <= 0xFFFFFFFF {
        (value as u32).to_be_bytes().to_vec()
    } else {
        value.to_be_bytes().to_vec()
    };

    encode_application_tag(buffer, ApplicationTag::UnsignedInt, bytes.len());
    buffer.extend_from_slice(&bytes);
}

/// Decode a BACnet unsigned integer
pub fn decode_unsigned(data: &[u8]) -> Result<(u32, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::UnsignedInt {
        return Err(EncodingError::InvalidTag);
    }

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    let value = match length {
        1 => data[consumed] as u32,
        2 => u16::from_be_bytes([data[consumed], data[consumed + 1]]) as u32,
        3 => {
            let bytes = [0, data[consumed], data[consumed + 1], data[consumed + 2]];
            u32::from_be_bytes(bytes)
        }
        4 => u32::from_be_bytes([
            data[consumed],
            data[consumed + 1],
            data[consumed + 2],
            data[consumed + 3],
        ]),
        _ => return Err(EncodingError::InvalidLength),
    };

    consumed += length;
    Ok((value, consumed))
}

/// Decode a BACnet unsigned integer into a u64
pub fn decode_unsigned64(data: &[u8]) -> Result<(u64, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::UnsignedInt {
        return Err(EncodingError::InvalidTag);
    }

    if length > 8 {
        return Err(EncodingError::InvalidLength);
    }

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    let unused = 8 - length;
    let mut value = [0; 8];
    value[unused..].copy_from_slice(&data[consumed..consumed + length]);

    let value = u64::from_be_bytes(value);

    consumed += length;
    Ok((value, consumed))
}

/// Encode a BACnet signed integer
pub fn encode_signed(buffer: &mut Vec<u8>, value: i32) -> Result<()> {
    let bytes = if (-128..=127).contains(&value) {
        vec![value as u8]
    } else if (-32768..=32767).contains(&value) {
        (value as i16).to_be_bytes().to_vec()
    } else if (-8388608..=8388607).contains(&value) {
        let bytes = value.to_be_bytes();
        bytes[1..].to_vec()
    } else {
        value.to_be_bytes().to_vec()
    };

    encode_application_tag(buffer, ApplicationTag::SignedInt, bytes.len());
    buffer.extend_from_slice(&bytes);
    Ok(())
}

pub fn encode_signed64(buffer: &mut Vec<u8>, value: i64) {
    let bytes = if (-128..=127).contains(&value) {
        vec![value as u8]
    } else if (-32768..=32767).contains(&value) {
        (value as i16).to_be_bytes().to_vec()
    } else if (-8388608..=8388607).contains(&value) {
        let bytes = value.to_be_bytes();
        bytes[1..].to_vec()
    } else if (i32::MIN as i64..=i32::MAX as i64).contains(&value) {
        (value as i32).to_be_bytes().to_vec()
    } else {
        value.to_be_bytes().to_vec()
    };

    encode_application_tag(buffer, ApplicationTag::SignedInt, bytes.len());
    buffer.extend_from_slice(&bytes);
}

/// Decode a BACnet signed integer
pub fn decode_signed(data: &[u8]) -> Result<(i32, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::SignedInt {
        return Err(EncodingError::InvalidTag);
    }

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    let value = match length {
        1 => data[consumed] as i8 as i32,
        2 => i16::from_be_bytes([data[consumed], data[consumed + 1]]) as i32,
        3 => {
            let sign_extend = if data[consumed] & 0x80 != 0 {
                0xFF
            } else {
                0x00
            };
            let bytes = [
                sign_extend,
                data[consumed],
                data[consumed + 1],
                data[consumed + 2],
            ];
            i32::from_be_bytes(bytes)
        }
        4 => i32::from_be_bytes([
            data[consumed],
            data[consumed + 1],
            data[consumed + 2],
            data[consumed + 3],
        ]),
        _ => return Err(EncodingError::InvalidLength),
    };

    consumed += length;
    Ok((value, consumed))
}

/// Decode a BACnet signed integer into a i64
pub fn decode_signed64(data: &[u8]) -> Result<(i64, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::SignedInt {
        return Err(EncodingError::InvalidTag);
    }

    if length == 0 || length > 8 {
        return Err(EncodingError::InvalidLength);
    }

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    // Sign-extend into the unused leading octets so any width from one to eight
    // reconstructs the same way.
    let sign_extend = if data[consumed] & 0x80 != 0 { 0xFF } else { 0x00 };
    let mut bytes = [sign_extend; 8];
    bytes[8 - length..].copy_from_slice(&data[consumed..consumed + length]);
    let value = i64::from_be_bytes(bytes);

    consumed += length;
    Ok((value, consumed))
}

/// Encode a BACnet real (float) value
pub fn encode_real(buffer: &mut Vec<u8>, value: f32) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Real, 4);
    buffer.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Decode a BACnet real (float) value
pub fn decode_real(data: &[u8]) -> Result<(f32, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::Real {
        return Err(EncodingError::InvalidTag);
    }

    if length != 4 {
        return Err(EncodingError::InvalidLength);
    }

    if data.len() < consumed + 4 {
        return Err(EncodingError::BufferUnderflow);
    }

    let value = f32::from_be_bytes([
        data[consumed],
        data[consumed + 1],
        data[consumed + 2],
        data[consumed + 3],
    ]);

    consumed += 4;
    Ok((value, consumed))
}

/// Encode a BACnet octet string
pub fn encode_octet_string(buffer: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::OctetString, value.len());
    buffer.extend_from_slice(value);
    Ok(())
}

/// Decode a BACnet octet string
pub fn decode_octet_string(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::OctetString {
        return Err(EncodingError::InvalidTag);
    }

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    let value = data[consumed..consumed + length].to_vec();
    consumed += length;

    Ok((value, consumed))
}

/// Encode a BACnet character string
pub fn encode_character_string(buffer: &mut Vec<u8>, value: &str) -> Result<()> {
    let string_bytes = value.as_bytes();
    encode_application_tag(
        buffer,
        ApplicationTag::CharacterString,
        string_bytes.len() + 1,
    );
    buffer.push(0); // Character set encoding (0 = ANSI X3.4)
    buffer.extend_from_slice(string_bytes);
    Ok(())
}

/// Decode a BACnet character string
pub fn decode_character_string(data: &[u8]) -> Result<(String, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::CharacterString {
        return Err(EncodingError::InvalidTag);
    }

    if data.len() < consumed + length || length == 0 {
        return Err(EncodingError::BufferUnderflow);
    }

    // Skip character set encoding byte
    let _encoding = data[consumed];
    consumed += 1;

    let string_data = &data[consumed..consumed + length - 1];
    let value = String::from_utf8(string_data.to_vec())
        .map_err(|_| EncodingError::InvalidFormat("Invalid UTF-8 string".to_string()))?;

    consumed += length - 1;

    Ok((value, consumed))
}

/// Encode a BACnet enumerated value
pub fn encode_enumerated(buffer: &mut Vec<u8>, value: u32) {
    let bytes = if value <= 0xFF {
        vec![value as u8]
    } else if value <= 0xFFFF {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= 0xFFFFFF {
        let bytes = value.to_be_bytes();
        bytes[1..].to_vec()
    } else {
        value.to_be_bytes().to_vec()
    };

    encode_application_tag(buffer, ApplicationTag::Enumerated, bytes.len());
    buffer.extend_from_slice(&bytes);
}

/// Decode a BACnet enumerated value
pub fn decode_enumerated(data: &[u8]) -> Result<(u32, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::Enumerated {
        return Err(EncodingError::InvalidTag);
    }

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    let value = match length {
        1 => data[consumed] as u32,
        2 => u16::from_be_bytes([data[consumed], data[consumed + 1]]) as u32,
        3 => {
            let bytes = [0, data[consumed], data[consumed + 1], data[consumed + 2]];
            u32::from_be_bytes(bytes)
        }
        4 => u32::from_be_bytes([
            data[consumed],
            data[consumed + 1],
            data[consumed + 2],
            data[consumed + 3],
        ]),
        _ => return Err(EncodingError::InvalidLength),
    };

    consumed += length;
    Ok((value, consumed))
}

/// Encode a BACnet date
pub fn encode_date(buffer: &mut Vec<u8>, year: u16, month: u8, day: u8, weekday: u8) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Date, 4);
    if year == 255 {
        buffer.push(255);
    } else if (1900..=2154).contains(&year) {
        buffer.push((year - 1900) as u8);
    } else {
        return Err(EncodingError::ValueOutOfRange);
    }
    buffer.push(month);
    buffer.push(day);
    buffer.push(weekday);
    Ok(())
}

/// Decode a BACnet date
pub fn decode_date(data: &[u8]) -> Result<((u16, u8, u8, u8), usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::Date {
        return Err(EncodingError::InvalidTag);
    }

    if length != 4 || data.len() < consumed + 4 {
        return Err(EncodingError::InvalidLength);
    }

    let year = if data[consumed] == 255 {
        255
    } else {
        1900 + data[consumed] as u16
    };
    let month = data[consumed + 1];
    let day = data[consumed + 2];
    let weekday = data[consumed + 3];

    consumed += 4;
    Ok(((year, month, day, weekday), consumed))
}

/// Encode a BACnet time
pub fn encode_time(
    buffer: &mut Vec<u8>,
    hour: u8,
    minute: u8,
    second: u8,
    hundredths: u8,
) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Time, 4);
    buffer.push(hour);
    buffer.push(minute);
    buffer.push(second);
    buffer.push(hundredths);
    Ok(())
}

/// Decode a BACnet time
pub fn decode_time(data: &[u8]) -> Result<((u8, u8, u8, u8), usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::Time {
        return Err(EncodingError::InvalidTag);
    }

    if length != 4 || data.len() < consumed + 4 {
        return Err(EncodingError::InvalidLength);
    }

    let hour = data[consumed];
    let minute = data[consumed + 1];
    let second = data[consumed + 2];
    let hundredths = data[consumed + 3];

    consumed += 4;
    Ok(((hour, minute, second, hundredths), consumed))
}

/// Encode a BACnet object identifier
pub fn encode_object_identifier(buffer: &mut Vec<u8>, object_id: ObjectIdentifier) -> Result<()> {
    let object_id: u32 = object_id
        .try_into()
        .map_err(|_| EncodingError::ValueOutOfRange)?;
    encode_application_tag(buffer, ApplicationTag::ObjectIdentifier, 4);
    buffer.extend_from_slice(&object_id.to_be_bytes());
    Ok(())
}

/// Decode a BACnet object identifier
pub fn decode_object_identifier(data: &[u8]) -> Result<(ObjectIdentifier, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::ObjectIdentifier {
        return Err(EncodingError::InvalidTag);
    }

    if length != 4 || data.len() < consumed + 4 {
        return Err(EncodingError::InvalidLength);
    }

    let object_id = u32::from_be_bytes([
        data[consumed],
        data[consumed + 1],
        data[consumed + 2],
        data[consumed + 3],
    ]);

    let object_type = object_id >> 22;
    let instance = object_id & 0x3FFFFF;
    let object_id = ObjectIdentifier::new(object_type.into(), instance);

    consumed += 4;
    Ok((object_id, consumed))
}

/// Encode a BACnet double (64-bit float)
pub fn encode_double(buffer: &mut Vec<u8>, value: f64) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Double, 8);
    buffer.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Decode a BACnet double (64-bit float)
pub fn decode_double(data: &[u8]) -> Result<(f64, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::Double {
        return Err(EncodingError::InvalidTag);
    }

    if length != 8 || data.len() < consumed + 8 {
        return Err(EncodingError::InvalidLength);
    }

    let value = f64::from_be_bytes([
        data[consumed],
        data[consumed + 1],
        data[consumed + 2],
        data[consumed + 3],
        data[consumed + 4],
        data[consumed + 5],
        data[consumed + 6],
        data[consumed + 7],
    ]);

    consumed += 8;
    Ok((value, consumed))
}

/// Encode a context-specific tag
pub fn encode_context_tag(buffer: &mut Vec<u8>, tag_number: u8, length: usize) -> Result<()> {
    // Tag numbers above 14 use the extended form of clause 20.2.1.2: the tag
    // nibble becomes B'1111' and the real tag number follows the initial octet,
    // ahead of any extended length octets.
    let extended = tag_number > 14;
    let tag_nibble = if extended {
        EXTENDED_TAG_NUMBER << 4
    } else {
        tag_number << 4
    };

    let tag_byte = if length < LVT_EXTENDED_LENGTH as usize {
        CONTEXT_CLASS_BIT | tag_nibble | (length as u8)
    } else {
        CONTEXT_CLASS_BIT | tag_nibble | LVT_EXTENDED_LENGTH
    };

    buffer.push(tag_byte);

    if extended {
        buffer.push(tag_number);
    }

    if length >= LVT_EXTENDED_LENGTH as usize {
        write_extended_length(buffer, length);
    }

    Ok(())
}

/// Encode the opening tag of constructed context-specific data.
///
/// Tag numbers above 14 use the extended form of clause 20.2.1.2: the tag nibble
/// is set to B'1111' and the real tag number follows in the next octet.
/// `BACnetNotificationParameters` needs this for change-of-reliability (19).
pub fn encode_opening_tag(buffer: &mut Vec<u8>, tag_number: u8) -> Result<()> {
    if tag_number > 14 {
        buffer.push(EXTENDED_TAG_NUMBER << 4 | CONTEXT_CLASS_BIT | LVT_OPENING_TAG);
        buffer.push(tag_number);
    } else {
        buffer.push(tag_number << 4 | CONTEXT_CLASS_BIT | LVT_OPENING_TAG);
    }
    Ok(())
}

/// Encode the closing tag of constructed context-specific data.
///
/// Uses the same extended form as [`encode_opening_tag`] above tag 14.
pub fn encode_closing_tag(buffer: &mut Vec<u8>, tag_number: u8) -> Result<()> {
    if tag_number > 14 {
        buffer.push(EXTENDED_TAG_NUMBER << 4 | CONTEXT_CLASS_BIT | LVT_CLOSING_TAG);
        buffer.push(tag_number);
    } else {
        buffer.push(tag_number << 4 | CONTEXT_CLASS_BIT | LVT_CLOSING_TAG);
    }
    Ok(())
}

/// Encode a context-specific unsigned integer
pub fn encode_context_unsigned(value: u32, tag_number: u8) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    // Determine the number of bytes needed for the unsigned value
    let bytes = if value == 0 {
        vec![0]
    } else if value <= 0xFF {
        vec![value as u8]
    } else if value <= 0xFFFF {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= 0xFFFFFF {
        let bytes = value.to_be_bytes();
        bytes[1..].to_vec()
    } else {
        value.to_be_bytes().to_vec()
    };

    // Encode the context tag
    encode_context_tag(&mut buffer, tag_number, bytes.len())?;

    // Add the value bytes
    buffer.extend_from_slice(&bytes);

    Ok(buffer)
}

/// Decode a primitive context-specific tag.
///
/// Opening and closing tags are rejected: they introduce no value, so the length
/// this returns would be meaningless for them. Use [`decode_tag`],
/// [`decode_opening_tag`] or [`decode_closing_tag`] for those.
pub fn decode_context_tag(data: &[u8]) -> Result<(u8, usize, usize)> {
    match decode_tag(data)? {
        (BACnetTag::Context(tag_number), length, consumed) => Ok((tag_number, length, consumed)),
        _ => Err(EncodingError::InvalidTag),
    }
}

/// Decode an opening tag, checking it opens context `expected`.
///
/// Returns how many octets the tag occupied, which is two for tag numbers above
/// 14.
pub fn decode_opening_tag(data: &[u8], expected: u8) -> Result<usize> {
    match decode_tag(data)? {
        (BACnetTag::Opening(tag_number), _, consumed) if tag_number == expected => Ok(consumed),
        _ => Err(EncodingError::InvalidTag),
    }
}

/// Decode a closing tag, checking it closes context `expected`.
///
/// Returns how many octets the tag occupied.
pub fn decode_closing_tag(data: &[u8], expected: u8) -> Result<usize> {
    match decode_tag(data)? {
        (BACnetTag::Closing(tag_number), _, consumed) if tag_number == expected => Ok(consumed),
        _ => Err(EncodingError::InvalidTag),
    }
}

/// Whether the next tag opens constructed context `tag`.
pub fn is_opening_tag(data: &[u8], tag: u8) -> bool {
    matches!(decode_tag(data), Ok((BACnetTag::Opening(actual), _, _)) if actual == tag)
}

/// Whether the next tag closes constructed context `tag`.
pub fn is_closing_tag(data: &[u8], tag: u8) -> bool {
    matches!(decode_tag(data), Ok((BACnetTag::Closing(actual), _, _)) if actual == tag)
}

/// Whether the next tag is context `tag` carrying a primitive value.
pub fn is_context_tag(data: &[u8], tag: u8) -> bool {
    matches!(decode_tag(data), Ok((BACnetTag::Context(actual), _, _)) if actual == tag)
}

/// Decode a context-specific unsigned integer
pub fn decode_context_unsigned(data: &[u8], expected_tag: u8) -> Result<(u32, usize)> {
    let (tag_number, length, tag_consumed) = decode_context_tag(data)?;

    if tag_number != expected_tag {
        return Err(EncodingError::InvalidTag);
    }

    if data.len() < tag_consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    let value = match length {
        0 => 0,
        1 => data[tag_consumed] as u32,
        2 => u16::from_be_bytes([data[tag_consumed], data[tag_consumed + 1]]) as u32,
        3 => {
            let bytes = [
                0,
                data[tag_consumed],
                data[tag_consumed + 1],
                data[tag_consumed + 2],
            ];
            u32::from_be_bytes(bytes)
        }
        4 => u32::from_be_bytes([
            data[tag_consumed],
            data[tag_consumed + 1],
            data[tag_consumed + 2],
            data[tag_consumed + 3],
        ]),
        _ => return Err(EncodingError::InvalidLength),
    };

    Ok((value, tag_consumed + length))
}

/// Encode a context-specific boolean.
///
/// Unlike the application form, which carries the value in its length nibble, a
/// context-tagged boolean carries it in a one-octet payload.
pub fn encode_context_boolean(buffer: &mut Vec<u8>, tag_number: u8, value: bool) -> Result<()> {
    encode_context_tag(buffer, tag_number, 1)?;
    buffer.push(u8::from(value));
    Ok(())
}

/// Decode a context-specific boolean.
pub fn decode_context_boolean(data: &[u8], expected_tag: u8) -> Result<(bool, usize)> {
    let (tag_number, length, consumed) = decode_context_tag(data)?;
    if tag_number != expected_tag || length != 1 {
        return Err(EncodingError::InvalidTag);
    }
    match *data.get(consumed).ok_or(EncodingError::BufferUnderflow)? {
        0 => Ok((false, consumed + 1)),
        1 => Ok((true, consumed + 1)),
        _ => Err(EncodingError::InvalidFormat(
            "context Boolean is not zero or one".into(),
        )),
    }
}

/// Encode a context-specific real.
pub fn encode_context_real(buffer: &mut Vec<u8>, tag_number: u8, value: f32) -> Result<()> {
    encode_context_tag(buffer, tag_number, 4)?;
    buffer.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Decode a context-specific real.
pub fn decode_context_real(data: &[u8], expected_tag: u8) -> Result<(f32, usize)> {
    let (tag_number, length, consumed) = decode_context_tag(data)?;
    if tag_number != expected_tag {
        return Err(EncodingError::InvalidTag);
    }
    if length != 4 {
        return Err(EncodingError::InvalidLength);
    }
    let bytes = data
        .get(consumed..consumed + 4)
        .ok_or(EncodingError::BufferUnderflow)?;
    Ok((
        f32::from_be_bytes(bytes.try_into().map_err(|_| EncodingError::InvalidLength)?),
        consumed + 4,
    ))
}

/// Encode a context-specific enumerated value
pub fn encode_context_enumerated(value: u32, tag_number: u8) -> Result<Vec<u8>> {
    // Enumerated values use the same encoding as unsigned integers
    encode_context_unsigned(value, tag_number)
}

/// Decode a context-specific enumerated value
pub fn decode_context_enumerated(data: &[u8], expected_tag: u8) -> Result<(u32, usize)> {
    // Enumerated values use the same decoding as unsigned integers
    decode_context_unsigned(data, expected_tag)
}

/// Encode a context-specific object identifier
pub fn encode_context_object_id(object_id: ObjectIdentifier, tag_number: u8) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    // Combine object type and instance into 4-byte object identifier
    let object_id: u32 = object_id.try_into()?;

    // Encode context tag with length 4
    encode_context_tag(&mut buffer, tag_number, 4)?;

    // Add the object identifier bytes
    buffer.extend_from_slice(&object_id.to_be_bytes());

    Ok(buffer)
}

/// Decode a context-specific object identifier
pub fn decode_context_object_id(
    data: &[u8],
    expected_tag: u8,
) -> Result<(ObjectIdentifier, usize)> {
    let (tag_number, length, tag_consumed) = decode_context_tag(data)?;

    if tag_number != expected_tag {
        return Err(EncodingError::InvalidTag);
    }

    if length != 4 {
        return Err(EncodingError::InvalidLength);
    }

    if data.len() < tag_consumed + 4 {
        return Err(EncodingError::BufferUnderflow);
    }

    let object_id = u32::from_be_bytes([
        data[tag_consumed],
        data[tag_consumed + 1],
        data[tag_consumed + 2],
        data[tag_consumed + 3],
    ]);

    Ok((object_id.into(), tag_consumed + 4))
}

impl TryFrom<u8> for ApplicationTag {
    type Error = EncodingError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(ApplicationTag::Null),
            1 => Ok(ApplicationTag::Boolean),
            2 => Ok(ApplicationTag::UnsignedInt),
            3 => Ok(ApplicationTag::SignedInt),
            4 => Ok(ApplicationTag::Real),
            5 => Ok(ApplicationTag::Double),
            6 => Ok(ApplicationTag::OctetString),
            7 => Ok(ApplicationTag::CharacterString),
            8 => Ok(ApplicationTag::BitString),
            9 => Ok(ApplicationTag::Enumerated),
            10 => Ok(ApplicationTag::Date),
            11 => Ok(ApplicationTag::Time),
            12 => Ok(ApplicationTag::ObjectIdentifier),
            13 => Ok(ApplicationTag::Reserved13),
            14 => Ok(ApplicationTag::Reserved14),
            _ => Err(EncodingError::InvalidTag),
        }
    }
}

/// Advanced encoding features and optimizations
pub mod advanced {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::{collections::BTreeMap, vec::Vec};

    /// Buffer manager for efficient encoding/decoding operations
    #[derive(Debug)]
    pub struct BufferManager {
        /// Reusable buffers for encoding operations
        #[cfg(feature = "std")]
        encode_buffers: Vec<Vec<u8>>,
        #[cfg(not(feature = "std"))]
        encode_buffers: alloc::vec::Vec<alloc::vec::Vec<u8>>,
        /// Maximum buffer size to cache
        max_buffer_size: usize,
        /// Statistics for buffer usage
        pub stats: BufferStats,
    }

    /// Buffer usage statistics
    #[derive(Debug, Default)]
    pub struct BufferStats {
        pub total_allocations: u64,
        pub buffer_reuses: u64,
        pub max_buffer_size_used: usize,
        pub total_bytes_encoded: u64,
        pub total_bytes_decoded: u64,
    }

    impl BufferManager {
        /// Create a new buffer manager
        pub fn new(max_buffer_size: usize) -> Self {
            Self {
                encode_buffers: Vec::with_capacity(8),
                max_buffer_size,
                stats: BufferStats::default(),
            }
        }

        /// Get a buffer for encoding, reusing if possible
        pub fn get_encode_buffer(&mut self) -> Vec<u8> {
            if let Some(mut buffer) = self.encode_buffers.pop() {
                buffer.clear();
                self.stats.buffer_reuses += 1;
                buffer
            } else {
                self.stats.total_allocations += 1;
                Vec::with_capacity(256)
            }
        }

        /// Return a buffer for reuse
        pub fn return_buffer(&mut self, buffer: Vec<u8>) {
            self.stats.total_bytes_encoded += buffer.len() as u64;
            if buffer.capacity() <= self.max_buffer_size && self.encode_buffers.len() < 16 {
                self.encode_buffers.push(buffer);
            }
        }

        /// Update decoding statistics
        pub fn update_decode_stats(&mut self, bytes_decoded: usize) {
            self.stats.total_bytes_decoded += bytes_decoded as u64;
        }
    }

    /// Context-specific tag encoding/decoding.
    ///
    /// Re-exported from the crate root so there is a single implementation of
    /// each; this module used to carry its own copies, which diverged.
    pub mod context {
        pub use super::super::{
            decode_closing_tag, decode_context_tag, decode_opening_tag, encode_closing_tag,
            encode_context_tag, encode_opening_tag,
        };
    }

    /// Bit string encoding/decoding utilities
    pub mod bitstring {
        use super::*;

        /// Encode a bit string
        #[allow(clippy::manual_is_multiple_of)]
        pub fn encode_bit_string(buffer: &mut Vec<u8>, bits: &[bool]) -> Result<()> {
            let byte_count = bits.len().div_ceil(8);
            let unused_bits = if bits.len() % 8 == 0 {
                0
            } else {
                8 - (bits.len() % 8)
            };

            encode_application_tag(buffer, ApplicationTag::BitString, byte_count + 1);
            buffer.push(unused_bits as u8);

            let mut current_byte = 0u8;
            let mut bit_pos = 0;

            for &bit in bits {
                if bit {
                    current_byte |= 1 << (7 - bit_pos);
                }
                bit_pos += 1;

                if bit_pos == 8 {
                    buffer.push(current_byte);
                    current_byte = 0;
                    bit_pos = 0;
                }
            }

            if bit_pos > 0 {
                buffer.push(current_byte);
            }

            Ok(())
        }

        /// Decode a bit string
        pub fn decode_bit_string(data: &[u8]) -> Result<(Vec<bool>, usize)> {
            let (tag, length, mut consumed) = decode_application_tag(data)?;

            if tag != ApplicationTag::BitString {
                return Err(EncodingError::InvalidTag);
            }

            if length == 0 || data.len() < consumed + length {
                return Err(EncodingError::BufferUnderflow);
            }

            let unused_bits = data[consumed] as usize;
            consumed += 1;

            if unused_bits > 7 {
                return Err(EncodingError::InvalidFormat(
                    "Invalid unused bits count".to_string(),
                ));
            }

            let mut bits = Vec::new();
            let byte_count = length - 1;

            for i in 0..byte_count {
                let byte_val = data[consumed + i];
                let bits_in_byte = if i == byte_count - 1 {
                    8 - unused_bits
                } else {
                    8
                };

                for bit_pos in 0..bits_in_byte {
                    bits.push((byte_val & (1 << (7 - bit_pos))) != 0);
                }
            }

            consumed += byte_count;
            Ok((bits, consumed))
        }
    }
}

/// Encoding stream for efficient multi-value encoding
pub struct EncodingStream {
    buffer: Vec<u8>,
    position: usize,
    max_size: usize,
}

impl EncodingStream {
    /// Create a new encoding stream
    pub fn new(max_size: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(max_size),
            position: 0,
            max_size,
        }
    }

    /// Encode an application tagged value
    pub fn encode_tagged<T: EncodableValue>(
        &mut self,
        tag: ApplicationTag,
        value: T,
    ) -> Result<()> {
        if self.buffer.len() >= self.max_size {
            return Err(EncodingError::BufferOverflow);
        }
        value.encode_to(tag, &mut self.buffer)
    }

    /// Encode a context tagged value
    pub fn encode_context<T: EncodableValue>(&mut self, tag_number: u8, value: T) -> Result<()> {
        if self.buffer.len() >= self.max_size {
            return Err(EncodingError::BufferOverflow);
        }
        value.encode_context_to(tag_number, &mut self.buffer)
    }

    /// Get the encoded data
    pub fn data(&self) -> &[u8] {
        &self.buffer
    }

    /// Take the buffer
    pub fn into_buffer(self) -> Vec<u8> {
        self.buffer
    }

    /// Clear the stream
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.position = 0;
    }
}

/// Trait for values that can be encoded
pub trait EncodableValue {
    /// Encode with application tag
    fn encode_to(&self, tag: ApplicationTag, buffer: &mut Vec<u8>) -> Result<()>;

    /// Encode with context tag
    fn encode_context_to(&self, tag_number: u8, buffer: &mut Vec<u8>) -> Result<()>;
}

impl EncodableValue for bool {
    fn encode_to(&self, _tag: ApplicationTag, buffer: &mut Vec<u8>) -> Result<()> {
        encode_boolean(buffer, *self)
    }

    fn encode_context_to(&self, tag_number: u8, buffer: &mut Vec<u8>) -> Result<()> {
        advanced::context::encode_context_tag(buffer, tag_number, if *self { 1 } else { 0 })
    }
}

impl EncodableValue for u32 {
    fn encode_to(&self, _tag: ApplicationTag, buffer: &mut Vec<u8>) -> Result<()> {
        encode_unsigned(buffer, *self)
    }

    fn encode_context_to(&self, tag_number: u8, buffer: &mut Vec<u8>) -> Result<()> {
        let temp_buffer = Vec::new();
        let mut temp = temp_buffer;
        encode_unsigned(&mut temp, *self)?;
        advanced::context::encode_context_tag(buffer, tag_number, temp.len() - 1)?;
        buffer.extend_from_slice(&temp[1..]);
        Ok(())
    }
}

impl EncodableValue for i32 {
    fn encode_to(&self, _tag: ApplicationTag, buffer: &mut Vec<u8>) -> Result<()> {
        encode_signed(buffer, *self)
    }

    fn encode_context_to(&self, tag_number: u8, buffer: &mut Vec<u8>) -> Result<()> {
        let temp_buffer = Vec::new();
        let mut temp = temp_buffer;
        encode_signed(&mut temp, *self)?;
        advanced::context::encode_context_tag(buffer, tag_number, temp.len() - 1)?;
        buffer.extend_from_slice(&temp[1..]);
        Ok(())
    }
}

impl EncodableValue for f32 {
    fn encode_to(&self, _tag: ApplicationTag, buffer: &mut Vec<u8>) -> Result<()> {
        encode_real(buffer, *self)
    }

    fn encode_context_to(&self, tag_number: u8, buffer: &mut Vec<u8>) -> Result<()> {
        advanced::context::encode_context_tag(buffer, tag_number, 4)?;
        buffer.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl EncodableValue for f64 {
    fn encode_to(&self, _tag: ApplicationTag, buffer: &mut Vec<u8>) -> Result<()> {
        encode_double(buffer, *self)
    }

    fn encode_context_to(&self, tag_number: u8, buffer: &mut Vec<u8>) -> Result<()> {
        advanced::context::encode_context_tag(buffer, tag_number, 8)?;
        buffer.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl EncodableValue for &str {
    fn encode_to(&self, _tag: ApplicationTag, buffer: &mut Vec<u8>) -> Result<()> {
        encode_character_string(buffer, self)
    }

    fn encode_context_to(&self, tag_number: u8, buffer: &mut Vec<u8>) -> Result<()> {
        advanced::context::encode_context_tag(buffer, tag_number, self.len() + 1)?;
        buffer.push(0); // Character set
        buffer.extend_from_slice(self.as_bytes());
        Ok(())
    }
}

/// Decoding stream for efficient multi-value decoding
pub struct DecodingStream<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> DecodingStream<'a> {
    /// Create a new decoding stream
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    /// Check if stream has more data
    pub fn has_data(&self) -> bool {
        self.position < self.data.len()
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    /// Peek at the next tag without consuming
    pub fn peek_tag(&self) -> Result<ApplicationTag> {
        if self.position >= self.data.len() {
            return Err(EncodingError::UnexpectedEndOfData);
        }

        let tag_byte = self.data[self.position];
        let tag = ApplicationTag::try_from(tag_byte >> 4)?;
        Ok(tag)
    }

    /// Decode a boolean
    pub fn decode_boolean(&mut self) -> Result<bool> {
        let (value, consumed) = decode_boolean(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode an unsigned integer
    pub fn decode_unsigned(&mut self) -> Result<u32> {
        let (value, consumed) = decode_unsigned(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode a signed integer
    pub fn decode_signed(&mut self) -> Result<i32> {
        let (value, consumed) = decode_signed(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode a real number
    pub fn decode_real(&mut self) -> Result<f32> {
        let (value, consumed) = decode_real(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode a double
    pub fn decode_double(&mut self) -> Result<f64> {
        let (value, consumed) = decode_double(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode a character string
    pub fn decode_character_string(&mut self) -> Result<String> {
        let (value, consumed) = decode_character_string(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode an octet string
    pub fn decode_octet_string(&mut self) -> Result<Vec<u8>> {
        let (value, consumed) = decode_octet_string(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode an enumerated value
    pub fn decode_enumerated(&mut self) -> Result<u32> {
        let (value, consumed) = decode_enumerated(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode a date
    pub fn decode_date(&mut self) -> Result<(u16, u8, u8, u8)> {
        let (value, consumed) = decode_date(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode a time
    pub fn decode_time(&mut self) -> Result<(u8, u8, u8, u8)> {
        let (value, consumed) = decode_time(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode an object identifier
    pub fn decode_object_identifier(&mut self) -> Result<ObjectIdentifier> {
        let (identifier, consumed) = decode_object_identifier(&self.data[self.position..])?;
        self.position += consumed;
        Ok(identifier)
    }

    /// Skip a value
    pub fn skip_value(&mut self) -> Result<()> {
        let (_tag, length, consumed) = decode_application_tag(&self.data[self.position..])?;
        self.position += consumed + length;
        Ok(())
    }

    /// Get current position
    pub fn position(&self) -> usize {
        self.position
    }

    /// Set position
    pub fn set_position(&mut self, position: usize) -> Result<()> {
        if position > self.data.len() {
            return Err(EncodingError::ValueOutOfRange);
        }
        self.position = position;
        Ok(())
    }
}

/// Property array encoder
#[derive(Default)]
pub struct PropertyArrayEncoder {
    buffer: Vec<u8>,
    count: usize,
}

impl PropertyArrayEncoder {
    /// Create a new property array encoder
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a property value
    pub fn add_property<T: EncodableValue>(&mut self, property_id: u32, value: T) -> Result<()> {
        // Encode property identifier with context tag 0
        advanced::context::encode_context_tag(&mut self.buffer, 0, 4)?;
        self.buffer.extend_from_slice(&property_id.to_be_bytes());

        // Open context tag 1 for value
        advanced::context::encode_opening_tag(&mut self.buffer, 1)?;

        // Encode the value
        value.encode_to(ApplicationTag::Null, &mut self.buffer)?;

        // Close context tag 1
        advanced::context::encode_closing_tag(&mut self.buffer, 1)?;

        self.count += 1;
        Ok(())
    }

    /// Get the encoded data
    pub fn data(&self) -> &[u8] {
        &self.buffer
    }

    /// Get the property count
    pub fn count(&self) -> usize {
        self.count
    }

    /// Clear the encoder
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.count = 0;
    }
}

/// Error encoder for BACnet error PDUs
#[derive(Default)]
pub struct ErrorEncoder {
    buffer: Vec<u8>,
}

impl ErrorEncoder {
    /// Create a new error encoder
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode an error class and code
    pub fn encode_error(&mut self, error_class: u32, error_code: u32) -> Result<()> {
        // Error class with context tag 0
        advanced::context::encode_context_tag(
            &mut self.buffer,
            0,
            if error_class <= 0xFF {
                1
            } else if error_class <= 0xFFFF {
                2
            } else {
                4
            },
        )?;
        encode_enumerated(&mut self.buffer, error_class);

        // Error code with context tag 1
        advanced::context::encode_context_tag(
            &mut self.buffer,
            1,
            if error_code <= 0xFF {
                1
            } else if error_code <= 0xFFFF {
                2
            } else {
                4
            },
        )?;
        encode_enumerated(&mut self.buffer, error_code);

        Ok(())
    }

    /// Get the encoded data
    pub fn data(&self) -> &[u8] {
        &self.buffer
    }

    /// Clear the encoder
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// Encoding performance analyzer
#[derive(Debug, Default)]
pub struct EncodingAnalyzer {
    /// Encoding operation statistics
    pub stats: EncodingStatistics,
    /// Performance benchmarks
    benchmarks: Vec<EncodingBenchmark>,
    /// Error patterns
    error_patterns: Vec<ErrorPattern>,
}

/// Encoding operation statistics
#[derive(Debug, Default)]
pub struct EncodingStatistics {
    /// Total encoding operations
    pub total_encodings: u64,
    /// Total decoding operations
    pub total_decodings: u64,
    /// Total bytes encoded
    pub bytes_encoded: u64,
    /// Total bytes decoded
    pub bytes_decoded: u64,
    /// Encoding errors
    pub encoding_errors: u64,
    /// Decoding errors
    pub decoding_errors: u64,
    /// Average encoding time (microseconds)
    pub avg_encode_time_us: f64,
    /// Average decoding time (microseconds)
    pub avg_decode_time_us: f64,
}

/// Performance benchmark data
#[derive(Debug, Clone)]
struct EncodingBenchmark {
    /// Data type being benchmarked
    _data_type: &'static str,
    /// Data size in bytes
    _size: usize,
    /// Encoding time in microseconds
    _encode_time_us: u64,
    /// Decoding time in microseconds
    _decode_time_us: u64,
    /// Timestamp
    #[cfg(feature = "std")]
    _timestamp: std::time::Instant,
}

/// Error pattern tracking
#[derive(Debug, Clone)]
struct ErrorPattern {
    /// Error type
    error_type: EncodingError,
    /// Frequency count
    count: u32,
    /// Last occurrence
    #[cfg(feature = "std")]
    last_seen: std::time::Instant,
}

impl EncodingAnalyzer {
    /// Create a new encoding analyzer
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an encoding operation
    pub fn record_encoding(&mut self, data_type: &'static str, bytes: usize, duration_us: u64) {
        self.stats.total_encodings += 1;
        self.stats.bytes_encoded += bytes as u64;

        // Update average encoding time
        let total_time = self.stats.avg_encode_time_us * (self.stats.total_encodings - 1) as f64;
        self.stats.avg_encode_time_us =
            (total_time + duration_us as f64) / self.stats.total_encodings as f64;

        // Store benchmark data
        self.benchmarks.push(EncodingBenchmark {
            _data_type: data_type,
            _size: bytes,
            _encode_time_us: duration_us,
            _decode_time_us: 0,
            #[cfg(feature = "std")]
            _timestamp: std::time::Instant::now(),
        });

        // Keep only recent benchmarks (last 1000)
        if self.benchmarks.len() > 1000 {
            self.benchmarks.remove(0);
        }
    }

    /// Record a decoding operation
    pub fn record_decoding(&mut self, _data_type: &'static str, bytes: usize, duration_us: u64) {
        self.stats.total_decodings += 1;
        self.stats.bytes_decoded += bytes as u64;

        // Update average decoding time
        let total_time = self.stats.avg_decode_time_us * (self.stats.total_decodings - 1) as f64;
        self.stats.avg_decode_time_us =
            (total_time + duration_us as f64) / self.stats.total_decodings as f64;
    }

    /// Record an encoding error
    pub fn record_error(&mut self, error: EncodingError) {
        self.stats.encoding_errors += 1;

        // Update error pattern
        if let Some(pattern) = self
            .error_patterns
            .iter_mut()
            .find(|p| std::mem::discriminant(&p.error_type) == std::mem::discriminant(&error))
        {
            pattern.count += 1;
            #[cfg(feature = "std")]
            {
                pattern.last_seen = std::time::Instant::now();
            }
        } else {
            self.error_patterns.push(ErrorPattern {
                error_type: error,
                count: 1,
                #[cfg(feature = "std")]
                last_seen: std::time::Instant::now(),
            });
        }
    }

    /// Get encoding throughput (bytes per second)
    pub fn get_encoding_throughput(&self) -> f64 {
        if self.stats.avg_encode_time_us > 0.0 {
            (self.stats.bytes_encoded as f64 / self.stats.total_encodings as f64)
                / (self.stats.avg_encode_time_us / 1_000_000.0)
        } else {
            0.0
        }
    }

    /// Get decoding throughput (bytes per second)
    pub fn get_decoding_throughput(&self) -> f64 {
        if self.stats.avg_decode_time_us > 0.0 {
            (self.stats.bytes_decoded as f64 / self.stats.total_decodings as f64)
                / (self.stats.avg_decode_time_us / 1_000_000.0)
        } else {
            0.0
        }
    }

    /// Get most common errors
    pub fn get_top_errors(&self, limit: usize) -> Vec<(&EncodingError, u32)> {
        let mut errors: Vec<_> = self
            .error_patterns
            .iter()
            .map(|p| (&p.error_type, p.count))
            .collect();
        errors.sort_by_key(|b| std::cmp::Reverse(b.1));
        errors.truncate(limit);
        errors
    }

    /// Reset statistics
    pub fn reset(&mut self) {
        self.stats = EncodingStatistics::default();
        self.benchmarks.clear();
        self.error_patterns.clear();
    }
}

/// Encoding cache for frequently used values
#[derive(Debug)]
pub struct EncodingCache {
    /// Cached encoded values
    cache: Vec<CacheEntry>,
    /// Maximum cache size
    max_size: usize,
    /// Cache hit statistics
    pub hits: u64,
    /// Cache miss statistics
    pub misses: u64,
}

/// Cache entry
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Hash of the original value
    hash: u64,
    /// Encoded data
    encoded: Vec<u8>,
    /// Access count
    access_count: u32,
    /// Last access time
    #[cfg(feature = "std")]
    last_access: std::time::Instant,
}

impl EncodingCache {
    /// Create a new encoding cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Vec::with_capacity(max_size),
            max_size,
            hits: 0,
            misses: 0,
        }
    }

    /// Get cached encoding if available
    pub fn get(&mut self, hash: u64) -> Option<Vec<u8>> {
        if let Some(entry) = self.cache.iter_mut().find(|e| e.hash == hash) {
            entry.access_count += 1;
            #[cfg(feature = "std")]
            {
                entry.last_access = std::time::Instant::now();
            }
            self.hits += 1;
            Some(entry.encoded.clone())
        } else {
            self.misses += 1;
            None
        }
    }

    /// Store encoded value in cache
    pub fn put(&mut self, hash: u64, encoded: Vec<u8>) {
        // Check if already exists
        if self.cache.iter().any(|e| e.hash == hash) {
            return;
        }

        // Remove least recently used if cache is full
        if self.cache.len() >= self.max_size {
            self.cache.sort_by_key(|e| e.access_count);
            self.cache.remove(0);
        }

        self.cache.push(CacheEntry {
            hash,
            encoded,
            access_count: 1,
            #[cfg(feature = "std")]
            last_access: std::time::Instant::now(),
        });
    }

    /// Clear the cache
    pub fn clear(&mut self) {
        self.cache.clear();
        self.hits = 0;
        self.misses = 0;
    }

    /// Get cache hit ratio
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total > 0 {
            self.hits as f64 / total as f64
        } else {
            0.0
        }
    }
}

/// Encoding configuration manager
#[derive(Debug, Clone)]
pub struct EncodingConfig {
    /// Use compression for large data
    pub use_compression: bool,
    /// Compression threshold (bytes)
    pub compression_threshold: usize,
    /// Enable caching
    pub enable_caching: bool,
    /// Cache size
    pub cache_size: usize,
    /// Enable performance tracking
    pub enable_performance_tracking: bool,
    /// Validation level
    pub validation_level: ValidationLevel,
    /// Maximum string length
    pub max_string_length: usize,
    /// Maximum array size
    pub max_array_size: usize,
}

/// Validation levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationLevel {
    /// No validation
    None,
    /// Basic validation
    Basic,
    /// Strict validation
    Strict,
    /// Paranoid validation (slowest)
    Paranoid,
}

impl Default for EncodingConfig {
    fn default() -> Self {
        Self {
            use_compression: false,
            compression_threshold: 1024,
            enable_caching: true,
            cache_size: 1000,
            enable_performance_tracking: true,
            validation_level: ValidationLevel::Basic,
            max_string_length: 4096,
            max_array_size: 1000,
        }
    }
}

/// High-level encoding manager
#[derive(Debug)]
pub struct EncodingManager {
    /// Configuration
    _config: EncodingConfig,
    /// Performance analyzer
    analyzer: Option<EncodingAnalyzer>,
    /// Encoding cache
    cache: Option<EncodingCache>,
    /// Buffer manager
    buffer_manager: advanced::BufferManager,
}

impl EncodingManager {
    /// Create a new encoding manager
    pub fn new(config: EncodingConfig) -> Self {
        let analyzer = if config.enable_performance_tracking {
            Some(EncodingAnalyzer::new())
        } else {
            None
        };

        let cache = if config.enable_caching {
            Some(EncodingCache::new(config.cache_size))
        } else {
            None
        };

        Self {
            _config: config,
            analyzer,
            cache,
            buffer_manager: advanced::BufferManager::new(8192),
        }
    }

    /// Encode a value with full management features
    pub fn encode<T: EncodableValue>(&mut self, value: T, tag: ApplicationTag) -> Result<Vec<u8>> {
        #[cfg(feature = "std")]
        let start_time = std::time::Instant::now();

        let mut buffer = self.buffer_manager.get_encode_buffer();
        let result = value.encode_to(tag, &mut buffer);

        #[cfg(feature = "std")]
        let duration = start_time.elapsed();

        match result {
            Ok(_) => {
                if let Some(ref mut analyzer) = self.analyzer {
                    #[cfg(feature = "std")]
                    analyzer.record_encoding("generic", buffer.len(), duration.as_micros() as u64);
                    #[cfg(not(feature = "std"))]
                    analyzer.record_encoding("generic", buffer.len(), 0);
                }

                let result_buffer = buffer.clone();
                self.buffer_manager.return_buffer(buffer);
                Ok(result_buffer)
            }
            Err(e) => {
                if let Some(ref mut analyzer) = self.analyzer {
                    analyzer.record_error(e.clone());
                }
                self.buffer_manager.return_buffer(buffer);
                Err(e)
            }
        }
    }

    /// Decode a value with full management features
    pub fn decode<T>(
        &mut self,
        data: &[u8],
        decoder: impl Fn(&[u8]) -> Result<(T, usize)>,
    ) -> Result<T> {
        #[cfg(feature = "std")]
        let start_time = std::time::Instant::now();

        let result = decoder(data);

        #[cfg(feature = "std")]
        let duration = start_time.elapsed();

        match result {
            Ok((value, consumed)) => {
                if let Some(ref mut analyzer) = self.analyzer {
                    #[cfg(feature = "std")]
                    analyzer.record_decoding("generic", consumed, duration.as_micros() as u64);
                    #[cfg(not(feature = "std"))]
                    analyzer.record_decoding("generic", consumed, 0);
                }
                Ok(value)
            }
            Err(e) => {
                if let Some(ref mut analyzer) = self.analyzer {
                    analyzer.record_error(e.clone());
                }
                Err(e)
            }
        }
    }

    /// Get performance statistics
    pub fn get_stats(&self) -> Option<&EncodingStatistics> {
        self.analyzer.as_ref().map(|a| &a.stats)
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> Option<(u64, u64, f64)> {
        self.cache
            .as_ref()
            .map(|c| (c.hits, c.misses, c.hit_ratio()))
    }

    /// Reset all statistics
    pub fn reset_stats(&mut self) {
        if let Some(ref mut analyzer) = self.analyzer {
            analyzer.reset();
        }
        if let Some(ref mut cache) = self.cache {
            cache.clear();
        }
    }
}

impl Default for EncodingManager {
    fn default() -> Self {
        Self::new(EncodingConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use crate::ObjectType;

    use super::*;

    #[test]
    fn test_encode_decode_boolean() {
        let mut buffer = Vec::new();

        // Test true
        encode_boolean(&mut buffer, true).unwrap();
        let (value, consumed) = decode_boolean(&buffer).unwrap();
        assert!(value);
        assert_eq!(consumed, 1);

        // Test false
        buffer.clear();
        encode_boolean(&mut buffer, false).unwrap();
        let (value, consumed) = decode_boolean(&buffer).unwrap();
        assert!(!value);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_encode_decode_unsigned() {
        let mut buffer = Vec::new();
        let test_values = [0, 255, 65535, 16777215, 4294967295];

        for &test_value in &test_values {
            buffer.clear();
            encode_unsigned(&mut buffer, test_value).unwrap();
            let (value, _) = decode_unsigned(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_encode_decode_signed() {
        let mut buffer = Vec::new();
        let test_values = [-128, -1, 0, 1, 127, -32768, 32767, -8388608, 8388607];

        for &test_value in &test_values {
            buffer.clear();
            encode_signed(&mut buffer, test_value).unwrap();
            let (value, _) = decode_signed(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_encode_decode_real() {
        let mut buffer = Vec::new();
        let test_values = [
            0.0,
            1.0,
            -1.0,
            std::f32::consts::PI,
            -273.15,
            f32::MAX,
            f32::MIN,
        ];

        for &test_value in &test_values {
            buffer.clear();
            encode_real(&mut buffer, test_value).unwrap();
            let (value, _) = decode_real(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_encode_decode_character_string() {
        let mut buffer = Vec::new();
        let test_strings = ["Hello", "BACnet", "Temperature Sensor", ""];

        for &test_string in &test_strings {
            buffer.clear();
            encode_character_string(&mut buffer, test_string).unwrap();
            let (value, _) = decode_character_string(&buffer).unwrap();
            assert_eq!(value, test_string);
        }
    }

    #[test]
    fn test_encode_decode_octet_string() {
        let mut buffer = Vec::new();
        let test_data = vec![0x01, 0x02, 0x03, 0xFF, 0x00];

        encode_octet_string(&mut buffer, &test_data).unwrap();
        let (decoded, _) = decode_octet_string(&buffer).unwrap();
        assert_eq!(decoded, test_data);
    }

    #[test]
    fn test_encode_decode_enumerated() {
        let mut buffer = Vec::new();
        let test_values = [0, 1, 255, 256, 65535, 65536, 16777215];

        for &test_value in &test_values {
            buffer.clear();
            encode_enumerated(&mut buffer, test_value);
            let (value, _) = decode_enumerated(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_encode_decode_date() {
        let mut buffer = Vec::new();

        encode_date(&mut buffer, 2024, 3, 15, 5).unwrap(); // Friday, March 15, 2024
        let ((year, month, day, weekday), _) = decode_date(&buffer).unwrap();
        assert_eq!(year, 2024);
        assert_eq!(month, 3);
        assert_eq!(day, 15);
        assert_eq!(weekday, 5);
    }

    #[test]
    fn test_encode_decode_time() {
        let mut buffer = Vec::new();

        encode_time(&mut buffer, 14, 30, 45, 50).unwrap(); // 14:30:45.50
        let ((hour, minute, second, hundredths), _) = decode_time(&buffer).unwrap();
        assert_eq!(hour, 14);
        assert_eq!(minute, 30);
        assert_eq!(second, 45);
        assert_eq!(hundredths, 50);
    }

    #[test]
    fn test_encode_decode_object_identifier() {
        let mut buffer = Vec::new();

        let object_id = ObjectIdentifier::new(ObjectType::AnalogValue, 12345);
        encode_object_identifier(&mut buffer, object_id).unwrap(); // Analog Value 12345
        let (object_id, _) = decode_object_identifier(&buffer).unwrap();
        assert_eq!(object_id.object_type, ObjectType::AnalogValue);
        assert_eq!(object_id.instance, 12345);
    }

    #[test]
    fn test_encode_decode_double() {
        let mut buffer = Vec::new();
        let test_values = [
            0.0,
            1.0,
            -1.0,
            std::f64::consts::PI,
            -273.15,
            f64::MAX,
            f64::MIN,
        ];

        for &test_value in &test_values {
            buffer.clear();
            encode_double(&mut buffer, test_value).unwrap();
            let (value, _) = decode_double(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_buffer_manager() {
        use advanced::BufferManager;

        let mut manager = BufferManager::new(1024);

        // Test getting and returning buffers
        let buffer1 = manager.get_encode_buffer();
        let buffer2 = manager.get_encode_buffer();

        assert_eq!(manager.stats.total_allocations, 2);
        assert_eq!(manager.stats.buffer_reuses, 0);

        manager.return_buffer(buffer1);
        let buffer3 = manager.get_encode_buffer();

        assert_eq!(manager.stats.total_allocations, 2);
        assert_eq!(manager.stats.buffer_reuses, 1);

        manager.return_buffer(buffer2);
        manager.return_buffer(buffer3);
    }

    #[test]
    fn test_context_specific_encoding() {
        use advanced::context::*;

        let mut buffer = Vec::new();

        // Test context-specific tag encoding
        encode_context_tag(&mut buffer, 5, 10).unwrap();
        let (tag_number, length, consumed) = decode_context_tag(&buffer).unwrap();

        assert_eq!(tag_number, 5);
        assert_eq!(length, 10);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_opening_closing_tags() {
        use advanced::context::*;

        let mut buffer = Vec::new();

        // Test opening and closing tags
        encode_opening_tag(&mut buffer, 3).unwrap();
        encode_closing_tag(&mut buffer, 3).unwrap();

        assert_eq!(buffer, vec![0x3E, 0x3F]);
    }

    #[test]
    fn test_bit_string_encoding() {
        use advanced::bitstring::*;

        let mut buffer = Vec::new();
        let bits = vec![true, false, true, true, false, false, true, false, true];

        encode_bit_string(&mut buffer, &bits).unwrap();
        let (decoded_bits, _) = decode_bit_string(&buffer).unwrap();

        assert_eq!(decoded_bits, bits);
    }

    #[test]
    fn test_encode_decode_performance() {
        let mut buffer = Vec::new();
        let iterations = 1000;

        // Performance test for encoding/decoding
        for i in 0..iterations {
            buffer.clear();
            encode_unsigned(&mut buffer, i).unwrap();
            let (value, _) = decode_unsigned(&buffer).unwrap();
            assert_eq!(value, i);
        }
    }

    #[test]
    fn test_encode_decode_i64() {
        let mut buffer = Vec::new();
        let test_values = [
            0,
            1,
            -1,
            -330,
            i32::MAX as i64,
            i32::MIN as i64,
            i32::MAX as i64 + 10,
            i32::MIN as i64 - 10,
            i64::MAX,
            i64::MIN,
            i64::MAX as i32 as i64,
            i64::MIN as i32 as i64,
        ];

        for &test_value in &test_values {
            buffer.clear();
            encode_signed64(&mut buffer, test_value);
            let (value, _) = decode_signed64(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_encode_decode_u64() {
        let mut buffer = Vec::new();
        let test_values = [
            0,
            1,
            255,
            330,
            u32::MAX as u64,
            u32::MIN as u64,
            u32::MAX as u64 + 10,
            u64::MAX,
            u64::MIN,
            u64::MAX as u32 as u64,
            u64::MIN as u32 as u64,
        ];

        for &test_value in &test_values {
            buffer.clear();
            encode_unsigned64(&mut buffer, test_value);
            let (value, _) = decode_unsigned64(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_decode_bacnet_tag() {
        let data = [0x21];
        let (tag, length, consumed) = decode_tag(&data).unwrap();
        assert_eq!(tag, BACnetTag::Application(ApplicationTag::UnsignedInt));
        assert_eq!(length, 1);
        assert_eq!(consumed, 1);

        // An opening tag reports itself as one, not as a context tag carrying six
        // octets of value.
        let data = [0x1E];
        let (tag, length, consumed) = decode_tag(&data).unwrap();
        assert_eq!(tag, BACnetTag::Opening(1));
        assert_eq!(length, 0);
        assert_eq!(consumed, 1);

        let data = [0x0C];
        let (tag, length, consumed) = decode_tag(&data).unwrap();
        assert_eq!(tag, BACnetTag::Context(0));
        assert_eq!(length, 4);
        assert_eq!(consumed, 1);

        let data = [0x35, 0x08];
        let (tag, length, consumed) = decode_tag(&data).unwrap();
        assert_eq!(tag, BACnetTag::Application(ApplicationTag::SignedInt));
        assert_eq!(length, 8);
        assert_eq!(consumed, 2);
    }
}
