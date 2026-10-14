//! Which datatype a property holds.
//!
//! The encoding of a constructed value does not say what it is: a
//! `BACnetDailySchedule` and a `BACnetSpecialEvent` are both runs of
//! context-tagged fields. Clause 12 does, per property, and this is that table
//! for the constructed datatypes the stack models. A property that is absent
//! holds application-tagged values, which describe themselves.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::{
    encoding::{EncodingError, Result as EncodingResult},
    object::PropertyIdentifier,
};

use super::{
    complex::{
        AddressBindingValue, CalendarEntryValue, CovSubscriptionValue, DailyScheduleValue,
        DateRangeValue, DestinationValue, ObjectPropertyReference, SpecialEventValue,
        TimestampValue, ValueSourceValue,
    },
    decode_property_value, PropertyValue,
};

/// What one value of a property is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Element {
    /// Application-tagged, whichever primitive it is: ABSTRACT-SYNTAX.&Type, or
    /// a primitive the property's definition fixes.
    Any,
    CovSubscription,
    AddressBinding,
    Timestamp,
    ObjectPropertyReference,
    Destination,
    DailySchedule,
    CalendarEntry,
    SpecialEvent,
    DateRange,
    ValueSource,
}

/// How a property holds its values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datatype {
    Single(Element),
    /// BACnetARRAY: indexable from 1, element 0 is the length.
    Array(Element),
    /// BACnetLIST: written and read whole.
    List(Element),
}

/// The datatype of `property`, or `None` for one whose values are
/// application-tagged.
///
/// Keyed by property alone: no property the stack models changes datatype with
/// its object type, except Present_Value and its kin, which are application
/// tagged wherever they appear.
pub fn datatype(property: PropertyIdentifier) -> Option<Datatype> {
    use Datatype::*;
    use PropertyIdentifier as P;
    Some(match property {
        P::ActiveCovSubscriptions => List(Element::CovSubscription),
        P::DeviceAddressBinding => List(Element::AddressBinding),
        P::EventTimeStamps | P::CommandTimeArray => Array(Element::Timestamp),
        P::LastCommandTime => Single(Element::Timestamp),
        P::ListOfObjectPropertyReferences => List(Element::ObjectPropertyReference),
        P::EventAlgorithmInhibitRef | P::ObjectPropertyReference => {
            Single(Element::ObjectPropertyReference)
        }
        P::RecipientList => List(Element::Destination),
        P::WeeklySchedule => Array(Element::DailySchedule),
        P::DateList => List(Element::CalendarEntry),
        P::ExceptionSchedule => Array(Element::SpecialEvent),
        P::EffectivePeriod => Single(Element::DateRange),
        P::ValueSource => Single(Element::ValueSource),
        P::ValueSourceArray => Array(Element::ValueSource),
        P::PriorityArray => Array(Element::Any),
        _ => return None,
    })
}

impl Datatype {
    pub fn element(self) -> Element {
        match self {
            Datatype::Single(element) | Datatype::Array(element) | Datatype::List(element) => {
                element
            }
        }
    }

    /// Wrap a property's values as this datatype holds them.
    pub fn collect(self, values: Vec<PropertyValue>) -> Option<PropertyValue> {
        match self {
            Datatype::Single(_) => match <[PropertyValue; 1]>::try_from(values) {
                Ok([value]) => Some(value),
                Err(_) => None,
            },
            Datatype::Array(_) => Some(PropertyValue::Array(values)),
            Datatype::List(_) => Some(PropertyValue::List(values)),
        }
    }
}

impl Element {
    /// Decode one value of this element, returning it and the bytes it took.
    pub fn decode(self, data: &[u8]) -> EncodingResult<(PropertyValue, usize)> {
        fn wrap<T>(
            decoded: EncodingResult<(T, usize)>,
            variant: fn(T) -> PropertyValue,
        ) -> EncodingResult<(PropertyValue, usize)> {
            decoded.map(|(value, length)| (variant(value), length))
        }
        match self {
            Element::Any => decode_property_value(data),
            Element::CovSubscription => wrap(
                CovSubscriptionValue::decode(data),
                PropertyValue::CovSubscription,
            ),
            Element::AddressBinding => wrap(
                AddressBindingValue::decode(data),
                PropertyValue::AddressBinding,
            ),
            Element::Timestamp => wrap(TimestampValue::decode(data), PropertyValue::Timestamp),
            Element::ObjectPropertyReference => wrap(
                ObjectPropertyReference::decode(data),
                PropertyValue::ObjectPropertyReference,
            ),
            Element::Destination => {
                wrap(DestinationValue::decode(data), PropertyValue::Destination)
            }
            Element::DailySchedule => wrap(
                DailyScheduleValue::decode(data),
                PropertyValue::DailySchedule,
            ),
            Element::CalendarEntry => wrap(
                CalendarEntryValue::decode(data),
                PropertyValue::CalendarEntry,
            ),
            Element::SpecialEvent => {
                wrap(SpecialEventValue::decode(data), PropertyValue::SpecialEvent)
            }
            Element::DateRange => wrap(DateRangeValue::decode(data), PropertyValue::DateRange),
            Element::ValueSource => {
                wrap(ValueSourceValue::decode(data), PropertyValue::ValueSource)
            }
        }
    }

    /// Decode a run of these elements that fills `data` exactly.
    pub fn decode_all(self, data: &[u8]) -> EncodingResult<Vec<PropertyValue>> {
        let mut values = Vec::new();
        let mut position = 0;
        while position < data.len() {
            let (value, length) = self.decode(&data[position..])?;
            if length == 0 {
                return Err(EncodingError::InvalidLength);
            }
            position += length;
            values.push(value);
        }
        Ok(values)
    }

    /// Whether `value` is one of these.
    pub fn holds(self, value: &PropertyValue) -> bool {
        use PropertyValue as V;
        match self {
            Element::Any => !matches!(
                value,
                V::Array(_)
                    | V::List(_)
                    | V::CovSubscription(_)
                    | V::AddressBinding(_)
                    | V::Timestamp(_)
                    | V::ObjectPropertyReference(_)
                    | V::Destination(_)
                    | V::DailySchedule(_)
                    | V::CalendarEntry(_)
                    | V::SpecialEvent(_)
                    | V::DateRange(_)
                    | V::ValueSource(_)
                    | V::Unknown(_)
            ),
            Element::CovSubscription => matches!(value, V::CovSubscription(_)),
            Element::AddressBinding => matches!(value, V::AddressBinding(_)),
            Element::Timestamp => matches!(value, V::Timestamp(_)),
            Element::ObjectPropertyReference => matches!(value, V::ObjectPropertyReference(_)),
            Element::Destination => matches!(value, V::Destination(_)),
            Element::DailySchedule => matches!(value, V::DailySchedule(_)),
            Element::CalendarEntry => matches!(value, V::CalendarEntry(_)),
            Element::SpecialEvent => matches!(value, V::SpecialEvent(_)),
            Element::DateRange => matches!(value, V::DateRange(_)),
            Element::ValueSource => matches!(value, V::ValueSource(_)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::property::{encode_property_value, TimeValueValue};

    fn encoded(values: &[PropertyValue]) -> Vec<u8> {
        let mut buffer = Vec::new();
        for value in values {
            encode_property_value(value, &mut buffer).unwrap();
        }
        buffer
    }

    #[test]
    fn a_weekly_schedule_is_an_array_of_daily_schedules() {
        let day = PropertyValue::DailySchedule(DailyScheduleValue {
            time_values: vec![TimeValueValue {
                time: (8, 0, 0, 0),
                value: Box::new(PropertyValue::Enumerated(1)),
            }],
        });
        let days = vec![day; 7];
        let datatype = datatype(PropertyIdentifier::WeeklySchedule).unwrap();

        let decoded = datatype.element().decode_all(&encoded(&days)).unwrap();

        assert_eq!(datatype.collect(decoded), Some(PropertyValue::Array(days)));
    }

    #[test]
    fn a_single_value_is_not_collected_from_two() {
        let range = PropertyValue::DateRange(DateRangeValue {
            start: (2026, 1, 1, 255),
            end: (2026, 12, 31, 255),
        });
        let datatype = datatype(PropertyIdentifier::EffectivePeriod).unwrap();

        assert_eq!(datatype.collect(vec![range.clone()]), Some(range.clone()));
        assert_eq!(datatype.collect(vec![range.clone(), range]), None);
    }

    #[test]
    fn an_element_holds_only_its_own_kind() {
        let entry = PropertyValue::CalendarEntry(CalendarEntryValue::Date(2026, 5, 17, 255));
        assert!(Element::CalendarEntry.holds(&entry));
        assert!(!Element::SpecialEvent.holds(&entry));
        assert!(!Element::Any.holds(&entry));
        assert!(Element::Any.holds(&PropertyValue::Real(1.0)));
    }
}
