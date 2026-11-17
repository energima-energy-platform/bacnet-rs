//! AddListElement and RemoveListElement (135-2020 15.1, 15.2): change a list
//! property by the elements named, leaving every other element alone. The two
//! share one parameter list.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::encoding::{
    decode_closing_tag, decode_context_enumerated, decode_context_object_id,
    decode_context_unsigned, decode_opening_tag, enclosed_length, encode_closing_tag,
    encode_context_enumerated, encode_context_object_id, encode_context_unsigned,
    encode_opening_tag, is_context_tag, EncodingError, Result as EncodingResult,
};
use crate::object::{ObjectIdentifier, PropertyIdentifier};
use crate::property::{
    datatype::{datatype, Element},
    encode_property_value, PropertyValue,
};

#[derive(Debug, Clone, PartialEq)]
pub struct ListElementRequest {
    pub object_identifier: ObjectIdentifier,
    pub property_identifier: PropertyIdentifier,
    /// For a list held in one element of an array.
    pub property_array_index: Option<u32>,
    pub list_of_elements: Vec<PropertyValue>,
}

impl ListElementRequest {
    pub fn new(
        object_identifier: ObjectIdentifier,
        property_identifier: PropertyIdentifier,
        list_of_elements: Vec<PropertyValue>,
    ) -> Self {
        Self {
            object_identifier,
            property_identifier,
            property_array_index: None,
            list_of_elements,
        }
    }

    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        buffer.extend_from_slice(&encode_context_object_id(self.object_identifier, 0)?);
        buffer.extend_from_slice(&encode_context_enumerated(
            self.property_identifier.into(),
            1,
        )?);
        if let Some(index) = self.property_array_index {
            buffer.extend_from_slice(&encode_context_unsigned(index, 2)?);
        }
        encode_opening_tag(buffer, 3)?;
        for element in &self.list_of_elements {
            encode_property_value(element, buffer)?;
        }
        encode_closing_tag(buffer, 3)
    }

    /// Decode, reading the elements as the property's datatype says they are.
    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let (object_identifier, mut offset) = decode_context_object_id(data, 0)?;
        let (property, length) = decode_context_enumerated(&data[offset..], 1)?;
        offset += length;
        let property_identifier = PropertyIdentifier::from(property);
        let property_array_index = if is_context_tag(&data[offset..], 2) {
            let (index, length) = decode_context_unsigned(&data[offset..], 2)?;
            offset += length;
            Some(index)
        } else {
            None
        };

        offset += decode_opening_tag(&data[offset..], 3)?;
        let length = enclosed_length(&data[offset..], 3)?;
        let element =
            datatype(property_identifier).map_or(Element::Any, |datatype| datatype.element());
        let list_of_elements = element.decode_all(&data[offset..offset + length])?;
        offset += length;
        offset += decode_closing_tag(&data[offset..], 3)?;
        if offset != data.len() {
            return Err(EncodingError::InvalidLength);
        }

        Ok(Self {
            object_identifier,
            property_identifier,
            property_array_index,
            list_of_elements,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;
    use crate::property::{BacnetAddress, DestinationValue, Recipient};

    #[test]
    fn a_recipient_list_element_round_trips() {
        let request = ListElementRequest::new(
            ObjectIdentifier::new(ObjectType::NotificationClass, 1),
            PropertyIdentifier::RecipientList,
            vec![PropertyValue::Destination(DestinationValue {
                valid_days: vec![true; 7],
                from_time: (0, 0, 0, 0),
                to_time: (23, 59, 59, 99),
                recipient: Recipient::Address(BacnetAddress {
                    network: 0,
                    mac_address: vec![10, 0, 0, 5, 0xba, 0xc0],
                }),
                process_identifier: 0xbac8,
                issue_confirmed_notifications: true,
                transitions: vec![true; 3],
            })],
        );
        let mut encoded = Vec::new();
        request.encode(&mut encoded).unwrap();
        assert_eq!(ListElementRequest::decode(&encoded).unwrap(), request);
    }
}
