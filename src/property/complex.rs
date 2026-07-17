//! Constructed BACnet property value types.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    encoding::{
        advanced::context::{encode_closing_tag, encode_opening_tag},
        decode_context_object_id, decode_context_tag, decode_context_unsigned,
        encode_context_enumerated, encode_context_object_id, encode_context_tag,
        encode_context_unsigned, encode_object_identifier, encode_octet_string, encode_unsigned,
        EncodingError, Result as EncodingResult,
    },
    object::{ObjectIdentifier, PropertyIdentifier},
    property::{decode_property_value, PropertyValue},
};

/// BACnet address used by constructed application values.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BacnetAddress {
    pub network: u16,
    pub mac_address: Vec<u8>,
}

/// One BACnetAddressBinding entry from Device_Address_Binding.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressBindingValue {
    pub device_identifier: ObjectIdentifier,
    pub address: BacnetAddress,
}

impl AddressBindingValue {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        encode_object_identifier(buffer, self.device_identifier)?;
        encode_unsigned(buffer, self.address.network.into())?;
        encode_octet_string(buffer, &self.address.mac_address)?;
        Ok(())
    }
}

/// Recipient choice used by BACnetRecipientProcess.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    Device(ObjectIdentifier),
    Address(BacnetAddress),
}

/// Destination and process identifier for notifications.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientProcess {
    pub recipient: Recipient,
    pub process_identifier: u32,
}

/// Reference to a property on a BACnet object.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPropertyReference {
    pub object_identifier: ObjectIdentifier,
    pub property_identifier: PropertyIdentifier,
    pub array_index: Option<u32>,
}

/// One entry in the Device object's Active_COV_Subscriptions property.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct CovSubscriptionValue {
    pub recipient: RecipientProcess,
    pub monitored_property: ObjectPropertyReference,
    pub issue_confirmed_notifications: bool,
    pub time_remaining: u32,
    pub cov_increment: Option<f32>,
}

impl CovSubscriptionValue {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        encode_recipient_process(buffer, 0, &self.recipient)?;
        encode_object_property_reference(buffer, 1, &self.monitored_property)?;
        encode_context_boolean(buffer, 2, self.issue_confirmed_notifications)?;
        buffer.extend_from_slice(&encode_context_unsigned(self.time_remaining, 3)?);
        if let Some(increment) = self.cov_increment {
            encode_context_real(buffer, 4, increment)?;
        }
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let (recipient, mut consumed) = decode_recipient_process(data, 0)?;
        let (monitored_property, length) = decode_object_property_reference(&data[consumed..], 1)?;
        consumed += length;
        let (issue_confirmed_notifications, length) = decode_context_boolean(&data[consumed..], 2)?;
        consumed += length;
        let (time_remaining, length) = decode_context_unsigned(&data[consumed..], 3)?;
        consumed += length;

        let cov_increment = if context_tag_matches(&data[consumed..], 4, Some(4)) {
            let (increment, length) = decode_context_real(&data[consumed..], 4)?;
            consumed += length;
            Some(increment)
        } else {
            None
        };

        Ok((
            Self {
                recipient,
                monitored_property,
                issue_confirmed_notifications,
                time_remaining,
                cov_increment,
            },
            consumed,
        ))
    }
}

pub(crate) fn decode_cov_subscriptions(data: &[u8]) -> EncodingResult<Vec<PropertyValue>> {
    let mut subscriptions = Vec::new();
    let mut consumed = 0;
    while consumed < data.len() {
        let (subscription, length) = CovSubscriptionValue::decode(&data[consumed..])?;
        if length == 0 {
            return Err(EncodingError::InvalidLength);
        }
        consumed += length;
        subscriptions.push(PropertyValue::CovSubscription(subscription));
    }
    Ok(subscriptions)
}

pub(crate) fn decode_address_bindings(data: &[u8]) -> EncodingResult<Vec<PropertyValue>> {
    let mut bindings = Vec::new();
    let mut consumed = 0;
    while consumed < data.len() {
        let (device_identifier, length) = decode_property_value(&data[consumed..])?;
        consumed += length;
        let PropertyValue::ObjectIdentifier(device_identifier) = device_identifier else {
            return Err(EncodingError::InvalidFormat(
                "address binding device is not an object identifier".into(),
            ));
        };
        let (network, length) = decode_property_value(&data[consumed..])?;
        consumed += length;
        let PropertyValue::Unsigned(network) = network else {
            return Err(EncodingError::InvalidFormat(
                "address binding network is not unsigned".into(),
            ));
        };
        let network = u16::try_from(network).map_err(|_| EncodingError::ValueOutOfRange)?;
        let (mac_address, length) = decode_property_value(&data[consumed..])?;
        consumed += length;
        let PropertyValue::OctetString(mac_address) = mac_address else {
            return Err(EncodingError::InvalidFormat(
                "address binding MAC is not an octet string".into(),
            ));
        };
        bindings.push(PropertyValue::AddressBinding(AddressBindingValue {
            device_identifier,
            address: BacnetAddress {
                network,
                mac_address,
            },
        }));
    }
    Ok(bindings)
}

fn encode_recipient_process(
    buffer: &mut Vec<u8>,
    tag: u8,
    value: &RecipientProcess,
) -> EncodingResult<()> {
    encode_opening_tag(buffer, tag)?;
    encode_opening_tag(buffer, 0)?;
    match &value.recipient {
        Recipient::Device(device) => {
            buffer.extend_from_slice(&encode_context_object_id(*device, 0)?)
        }
        Recipient::Address(address) => {
            encode_opening_tag(buffer, 1)?;
            encode_unsigned(buffer, address.network.into())?;
            encode_octet_string(buffer, &address.mac_address)?;
            encode_closing_tag(buffer, 1)?;
        }
    }
    encode_closing_tag(buffer, 0)?;
    buffer.extend_from_slice(&encode_context_unsigned(value.process_identifier, 1)?);
    encode_closing_tag(buffer, tag)?;
    Ok(())
}

fn decode_recipient_process(data: &[u8], tag: u8) -> EncodingResult<(RecipientProcess, usize)> {
    let mut consumed = expect_constructed_tag(data, tag, 6)?;
    consumed += expect_constructed_tag(&data[consumed..], 0, 6)?;

    let recipient = if context_tag_matches(&data[consumed..], 0, Some(4)) {
        let (device, length) = decode_context_object_id(&data[consumed..], 0)?;
        consumed += length;
        Recipient::Device(device)
    } else {
        consumed += expect_constructed_tag(&data[consumed..], 1, 6)?;
        let (network, length) = decode_property_value(&data[consumed..])?;
        consumed += length;
        let PropertyValue::Unsigned(network) = network else {
            return Err(EncodingError::InvalidFormat(
                "BACnetAddress network is not unsigned".into(),
            ));
        };
        let network = u16::try_from(network).map_err(|_| EncodingError::ValueOutOfRange)?;
        let (mac_address, length) = decode_property_value(&data[consumed..])?;
        consumed += length;
        let PropertyValue::OctetString(mac_address) = mac_address else {
            return Err(EncodingError::InvalidFormat(
                "BACnetAddress MAC is not an octet string".into(),
            ));
        };
        consumed += expect_constructed_tag(&data[consumed..], 1, 7)?;
        Recipient::Address(BacnetAddress {
            network,
            mac_address,
        })
    };

    consumed += expect_constructed_tag(&data[consumed..], 0, 7)?;
    let (process_identifier, length) = decode_context_unsigned(&data[consumed..], 1)?;
    consumed += length;
    consumed += expect_constructed_tag(&data[consumed..], tag, 7)?;

    Ok((
        RecipientProcess {
            recipient,
            process_identifier,
        },
        consumed,
    ))
}

fn encode_object_property_reference(
    buffer: &mut Vec<u8>,
    tag: u8,
    value: &ObjectPropertyReference,
) -> EncodingResult<()> {
    encode_opening_tag(buffer, tag)?;
    buffer.extend_from_slice(&encode_context_object_id(value.object_identifier, 0)?);
    buffer.extend_from_slice(&encode_context_enumerated(
        value.property_identifier.into(),
        1,
    )?);
    if let Some(index) = value.array_index {
        buffer.extend_from_slice(&encode_context_unsigned(index, 2)?);
    }
    encode_closing_tag(buffer, tag)?;
    Ok(())
}

fn decode_object_property_reference(
    data: &[u8],
    tag: u8,
) -> EncodingResult<(ObjectPropertyReference, usize)> {
    let mut consumed = expect_constructed_tag(data, tag, 6)?;
    let (object_identifier, length) = decode_context_object_id(&data[consumed..], 0)?;
    consumed += length;
    let (property_identifier, length) = decode_context_unsigned(&data[consumed..], 1)?;
    consumed += length;
    let array_index = if context_tag_matches(&data[consumed..], 2, None) {
        let (index, length) = decode_context_unsigned(&data[consumed..], 2)?;
        consumed += length;
        Some(index)
    } else {
        None
    };
    consumed += expect_constructed_tag(&data[consumed..], tag, 7)?;

    Ok((
        ObjectPropertyReference {
            object_identifier,
            property_identifier: property_identifier.into(),
            array_index,
        },
        consumed,
    ))
}

fn encode_context_boolean(buffer: &mut Vec<u8>, tag: u8, value: bool) -> EncodingResult<()> {
    encode_context_tag(buffer, tag, 1)?;
    buffer.push(u8::from(value));
    Ok(())
}

fn decode_context_boolean(data: &[u8], tag: u8) -> EncodingResult<(bool, usize)> {
    let (actual_tag, length, header) = decode_context_tag(data)?;
    if actual_tag != tag || length != 1 || data.len() < header + 1 {
        return Err(EncodingError::InvalidTag);
    }
    match data[header] {
        0 => Ok((false, header + 1)),
        1 => Ok((true, header + 1)),
        _ => Err(EncodingError::InvalidFormat(
            "context Boolean is not zero or one".into(),
        )),
    }
}

fn encode_context_real(buffer: &mut Vec<u8>, tag: u8, value: f32) -> EncodingResult<()> {
    encode_context_tag(buffer, tag, 4)?;
    buffer.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn decode_context_real(data: &[u8], tag: u8) -> EncodingResult<(f32, usize)> {
    let (actual_tag, length, header) = decode_context_tag(data)?;
    if actual_tag != tag || length != 4 || data.len() < header + 4 {
        return Err(EncodingError::InvalidTag);
    }
    Ok((
        f32::from_be_bytes(data[header..header + 4].try_into().unwrap()),
        header + 4,
    ))
}

fn expect_constructed_tag(data: &[u8], tag: u8, kind: usize) -> EncodingResult<usize> {
    let (actual_tag, actual_kind, consumed) = decode_context_tag(data)?;
    if actual_tag == tag && actual_kind == kind {
        Ok(consumed)
    } else {
        Err(EncodingError::InvalidTag)
    }
}

fn context_tag_matches(data: &[u8], tag: u8, length: Option<usize>) -> bool {
    decode_context_tag(data).is_ok_and(|(actual_tag, actual_length, _)| {
        actual_tag == tag && length.is_none_or(|length| actual_length == length)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;

    #[test]
    fn decodes_and_reencodes_real_active_cov_subscription() {
        let encoded = vec![
            0x0E, 0x0E, 0x1E, 0x21, 0x00, 0x65, 0x06, 192, 168, 34, 7, 186, 192, 0x1F, 0x0F, 0x1A,
            0x27, 0x27, 0x0F, 0x1E, 0x0C, 0, 0, 0, 2, 0x19, 85, 0x1F, 0x29, 0, 0x3B, 0x01, 0x50,
            0xEB,
        ];

        let (decoded, consumed) = CovSubscriptionValue::decode(&encoded).unwrap();

        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded.recipient,
            RecipientProcess {
                recipient: Recipient::Address(BacnetAddress {
                    network: 0,
                    mac_address: vec![192, 168, 34, 7, 186, 192],
                }),
                process_identifier: 10_023,
            }
        );
        assert_eq!(
            decoded.monitored_property,
            ObjectPropertyReference {
                object_identifier: ObjectIdentifier::new(ObjectType::AnalogInput, 2),
                property_identifier: PropertyIdentifier::PresentValue,
                array_index: None,
            }
        );
        assert!(!decoded.issue_confirmed_notifications);
        assert_eq!(decoded.time_remaining, 86_251);
        assert_eq!(decoded.cov_increment, None);

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded).unwrap();
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn roundtrips_device_recipient_array_index_and_cov_increment() {
        let value = CovSubscriptionValue {
            recipient: RecipientProcess {
                recipient: Recipient::Device(ObjectIdentifier::new(ObjectType::Device, 42)),
                process_identifier: 300,
            },
            monitored_property: ObjectPropertyReference {
                object_identifier: ObjectIdentifier::new(ObjectType::AnalogValue, 7),
                property_identifier: PropertyIdentifier::PriorityArray,
                array_index: Some(8),
            },
            issue_confirmed_notifications: true,
            time_remaining: 60,
            cov_increment: Some(0.5),
        };
        let mut encoded = Vec::new();
        value.encode(&mut encoded).unwrap();

        let (decoded, consumed) = CovSubscriptionValue::decode(&encoded).unwrap();

        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, value);
    }

    #[test]
    fn decodes_address_binding_list_and_reencodes_entries() {
        let bindings = vec![
            AddressBindingValue {
                device_identifier: ObjectIdentifier::new(ObjectType::Device, 904),
                address: BacnetAddress {
                    network: 412,
                    mac_address: vec![7, 34, 168, 3, 186, 192],
                },
            },
            AddressBindingValue {
                device_identifier: ObjectIdentifier::new(ObjectType::Device, 5780),
                address: BacnetAddress {
                    network: 0,
                    mac_address: vec![192, 168, 34, 7, 186, 192],
                },
            },
        ];
        let mut encoded = Vec::new();
        for binding in &bindings {
            binding.encode(&mut encoded).unwrap();
        }

        let decoded = decode_address_bindings(&encoded).unwrap();

        assert_eq!(
            decoded,
            bindings
                .into_iter()
                .map(PropertyValue::AddressBinding)
                .collect::<Vec<_>>()
        );
    }
}
