//! Binary Object Types Implementation
//!
//! This module implements the Binary Input, Binary Output, and Binary Value object types
//! as defined in ASHRAE 135. These objects represent binary (two-state) values in BACnet.

use crate::object::{
    common_get, common_set, effective_priority,
    event_state::EventState,
    intrinsic::{
        intrinsic_get, intrinsic_property_list, intrinsic_set, status_flags_bits, AlarmEvaluation,
        AlarmTrigger, IntrinsicReporting,
    },
    reliability::Reliability,
    write_priority_slot, BacnetObject, CommonView, CommonWritable, CommonWrite, ObjectError,
    ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue, Result,
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Binary values enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BinaryPV {
    Inactive = 0,
    Active = 1,
}

impl From<bool> for BinaryPV {
    fn from(value: bool) -> Self {
        if value {
            BinaryPV::Active
        } else {
            BinaryPV::Inactive
        }
    }
}

impl From<BinaryPV> for bool {
    fn from(value: BinaryPV) -> Self {
        value == BinaryPV::Active
    }
}

fn commandable_binary(value: PropertyValue) -> Result<Option<BinaryPV>> {
    match value {
        PropertyValue::Enumerated(0) => Ok(Some(BinaryPV::Inactive)),
        PropertyValue::Enumerated(1) => Ok(Some(BinaryPV::Active)),
        PropertyValue::Enumerated(_) => Err(ObjectError::InvalidValue(
            "Binary value must be 0 or 1".to_string(),
        )),
        PropertyValue::Null => Ok(None),
        _ => Err(ObjectError::InvalidPropertyType),
    }
}

/// Polarity enumeration
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Polarity {
    Normal = 0,
    Reverse = 1,
}

impl TryFrom<u32> for Polarity {
    type Error = ObjectError;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Polarity::Normal),
            1 => Ok(Polarity::Reverse),
            _ => Err(ObjectError::InvalidValue(
                "Polarity must be 0 or 1".to_string(),
            )),
        }
    }
}

/// Read an alarm property from a binary object.
///
/// Returns `None` when the object has no intrinsic reporting configured, or when
/// `property` is not an alarm property.
fn binary_alarm_get(
    alarm_value: BinaryPV,
    alarm: Option<&IntrinsicReporting>,
    property: PropertyIdentifier,
) -> Option<Result<PropertyValue>> {
    let alarm = alarm?;

    match property {
        PropertyIdentifier::AlarmValue => Some(Ok(PropertyValue::Enumerated(alarm_value as u32))),
        _ => intrinsic_get(alarm, property),
    }
}

/// Write an alarm property on a binary object. `None` follows the same
/// convention as [`binary_alarm_get`].
fn binary_alarm_set(
    alarm_value: &mut BinaryPV,
    alarm: Option<&mut IntrinsicReporting>,
    property: PropertyIdentifier,
    value: PropertyValue,
) -> Option<Result<()>> {
    let alarm = alarm?;

    match property {
        PropertyIdentifier::AlarmValue => Some(match value {
            PropertyValue::Enumerated(0) => {
                *alarm_value = BinaryPV::Inactive;
                Ok(())
            }
            PropertyValue::Enumerated(1) => {
                *alarm_value = BinaryPV::Active;
                Ok(())
            }
            PropertyValue::Boolean(active) => {
                *alarm_value = BinaryPV::from(active);
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        }),
        _ => intrinsic_set(alarm, property, value),
    }
}

/// Alarm properties a binary object exposes, given its configuration.
fn binary_alarm_property_list(alarm: Option<&IntrinsicReporting>) -> Vec<PropertyIdentifier> {
    if alarm.is_none() {
        return Vec::new();
    }

    let mut properties = vec![PropertyIdentifier::AlarmValue];
    properties.extend(intrinsic_property_list());
    properties
}

/// Whether a binary alarm property accepts writes.
fn binary_alarm_writable(property: PropertyIdentifier, alarm_configured: bool) -> bool {
    alarm_configured
        && matches!(
            property,
            PropertyIdentifier::AlarmValue
                | PropertyIdentifier::NotificationClass
                | PropertyIdentifier::TimeDelay
                | PropertyIdentifier::TimeDelayNormal
                | PropertyIdentifier::EventEnable
                | PropertyIdentifier::NotifyType
                | PropertyIdentifier::EventDetectionEnable
        )
}

/// Run CHANGE_OF_STATE for a binary object.
///
/// The object is off-normal while Present_Value equals Alarm_Value; an
/// unreliable object goes to fault, which takes precedence.
fn evaluate_binary(
    present_value: BinaryPV,
    alarm_value: BinaryPV,
    reliability: Reliability,
    alarm: Option<&IntrinsicReporting>,
) -> Option<AlarmEvaluation> {
    let alarm = alarm?;
    if !alarm.event_detection_enable {
        return None;
    }

    if reliability != Reliability::NoFaultDetected {
        return Some(AlarmEvaluation {
            desired_state: EventState::Fault,
            trigger: AlarmTrigger::ReliabilityChange { reliability },
        });
    }

    let desired_state = if present_value == alarm_value {
        EventState::Offnormal
    } else {
        EventState::Normal
    };

    Some(AlarmEvaluation {
        desired_state,
        trigger: AlarmTrigger::BinaryChange {
            active: present_value == BinaryPV::Active,
        },
    })
}

/// The intrinsic reporting trait methods shared by all binary object types.
/// The state every binary object type answers from, borrowed from whichever
/// object is answering.
struct BinaryView<'a> {
    identifier: ObjectIdentifier,
    object_type: ObjectType,
    object_name: &'a str,
    description: &'a str,
    present_value: BinaryPV,
    overridden: bool,
    event_state: EventState,
    reliability: Reliability,
    out_of_service: bool,
    inactive_text: &'a str,
    active_text: &'a str,
    alarm_value: BinaryPV,
    alarm: Option<&'a IntrinsicReporting>,
}

/// Read a property common to every binary object type.
///
/// Returns `None` for properties belonging to a single type (device type,
/// priority array) so callers fall through to their own arms.
fn shared_get(view: BinaryView<'_>, property: PropertyIdentifier) -> Option<Result<PropertyValue>> {
    if let Some(result) = common_get(
        &CommonView {
            identifier: view.identifier,
            object_type: view.object_type,
            object_name: view.object_name,
            description: view.description,
            event_state: view.event_state,
            reliability: view.reliability,
            out_of_service: view.out_of_service,
            overridden: view.overridden,
        },
        property,
    ) {
        return Some(result);
    }

    let value = match property {
        PropertyIdentifier::PresentValue => PropertyValue::Enumerated(view.present_value as u32),
        PropertyIdentifier::InactiveText => {
            PropertyValue::CharacterString(view.inactive_text.to_owned())
        }
        PropertyIdentifier::ActiveText => {
            PropertyValue::CharacterString(view.active_text.to_owned())
        }
        _ => return binary_alarm_get(view.alarm_value, view.alarm, property),
    };

    Some(Ok(value))
}

/// The writable fields shared by every binary object type.
struct BinaryWritable<'a> {
    object_name: &'a mut String,
    description: &'a mut String,
    reliability: &'a mut Reliability,
    out_of_service: &'a mut bool,
    alarm_value: &'a mut BinaryPV,
    alarm: Option<&'a mut IntrinsicReporting>,
}

/// Write a property common to every binary object type. `None` means the
/// property is not one this helper owns.
fn shared_set(
    fields: BinaryWritable<'_>,
    property: PropertyIdentifier,
    value: PropertyValue,
) -> Option<Result<()>> {
    let BinaryWritable {
        object_name,
        description,
        reliability,
        out_of_service,
        alarm_value,
        alarm,
    } = fields;

    let value = match common_set(
        CommonWritable {
            object_name,
            description,
            reliability,
            out_of_service,
        },
        property,
        value,
    ) {
        CommonWrite::Handled(result) => return Some(result),
        CommonWrite::Unclaimed(value) => value,
    };

    binary_alarm_set(alarm_value, alarm, property, value)
}

/// Whether a property shared by every binary object type accepts writes.
fn shared_writable(property: PropertyIdentifier, alarm_configured: bool) -> bool {
    matches!(
        property,
        PropertyIdentifier::ObjectName
            | PropertyIdentifier::Description
            | PropertyIdentifier::OutOfService
            | PropertyIdentifier::Reliability
    ) || binary_alarm_writable(property, alarm_configured)
}

/// Properties every binary object exposes, in the order they are reported.
///
/// `trailing` carries the per-type additions, which sit inside the shared order
/// rather than after it: Priority_Array follows Out_Of_Service.
fn shared_property_list(
    trailing: &[PropertyIdentifier],
    alarm: Option<&IntrinsicReporting>,
) -> Vec<PropertyIdentifier> {
    let mut properties = vec![
        PropertyIdentifier::ObjectIdentifier,
        PropertyIdentifier::ObjectName,
        PropertyIdentifier::ObjectType,
        PropertyIdentifier::PresentValue,
        PropertyIdentifier::OutOfService,
    ];
    properties.extend_from_slice(trailing);
    properties.extend([
        PropertyIdentifier::Description,
        PropertyIdentifier::StatusFlags,
        PropertyIdentifier::EventState,
        PropertyIdentifier::Reliability,
        PropertyIdentifier::InactiveText,
        PropertyIdentifier::ActiveText,
    ]);
    properties.extend(binary_alarm_property_list(alarm));
    properties
}

/// The Priority_Array property of a commandable binary object.
fn priority_array_value(priority_array: &[Option<BinaryPV>; 16]) -> PropertyValue {
    PropertyValue::Array(
        priority_array
            .iter()
            .map(|slot| match slot {
                Some(state) => PropertyValue::Enumerated(*state as u32),
                None => PropertyValue::Null,
            })
            .collect(),
    )
}

/// Generate the borrowed views the shared binary handlers take.
///
/// All three binary types hold this state under the same field names, but on
/// three separate structs, so only the object type differs between them.
macro_rules! binary_views {
    ($object_type:expr) => {
        fn view(&self) -> BinaryView<'_> {
            BinaryView {
                identifier: self.identifier,
                object_type: $object_type,
                object_name: &self.object_name,
                description: &self.description,
                present_value: self.present_value,
                overridden: self.overridden,
                event_state: self.event_state,
                reliability: self.reliability,
                out_of_service: self.out_of_service,
                inactive_text: &self.inactive_text,
                active_text: &self.active_text,
                alarm_value: self.alarm_value,
                alarm: self.alarm.as_ref(),
            }
        }

        fn writable(&mut self) -> BinaryWritable<'_> {
            BinaryWritable {
                object_name: &mut self.object_name,
                description: &mut self.description,
                reliability: &mut self.reliability,
                out_of_service: &mut self.out_of_service,
                alarm_value: &mut self.alarm_value,
                alarm: self.alarm.as_mut(),
            }
        }
    };
}

macro_rules! binary_intrinsic_methods {
    () => {
        fn intrinsic(&self) -> Option<&IntrinsicReporting> {
            self.alarm.as_ref()
        }

        fn intrinsic_mut(&mut self) -> Option<&mut IntrinsicReporting> {
            self.alarm.as_mut()
        }

        fn evaluate_alarm(&self) -> Option<AlarmEvaluation> {
            evaluate_binary(
                self.present_value,
                self.alarm_value,
                self.reliability,
                self.alarm.as_ref(),
            )
        }

        fn apply_event_state(&mut self, state: EventState) {
            self.event_state = state;
        }

        fn is_out_of_service(&self) -> bool {
            self.out_of_service
        }
    };
}

/// Binary Input object
#[derive(Debug, Clone)]
pub struct BinaryInput {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value
    pub present_value: BinaryPV,
    /// Description
    pub description: String,
    /// Device type
    pub device_type: String,
    /// Whether an operator has overridden the point. The other Status_Flags
    /// bits are derived from Event_State, Reliability and Out_Of_Service.
    pub overridden: bool,
    /// Event state
    pub event_state: EventState,
    /// Reliability
    pub reliability: Reliability,
    /// Out of service
    pub out_of_service: bool,
    /// Polarity
    pub polarity: Polarity,
    /// Inactive text
    pub inactive_text: String,
    /// Active text
    pub active_text: String,
    /// Change of value time
    pub change_of_state_time: Option<crate::object::Time>,
    /// Change of state count
    pub change_of_state_count: u32,
    /// Time of state count reset
    pub time_of_state_count_reset: Option<crate::object::Time>,
    /// Present value that puts the object into an off-normal event state.
    pub alarm_value: BinaryPV,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

/// Binary Output object
#[derive(Debug, Clone)]
pub struct BinaryOutput {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value
    pub present_value: BinaryPV,
    /// Description
    pub description: String,
    /// Device type
    pub device_type: String,
    /// Whether an operator has overridden the point. The other Status_Flags
    /// bits are derived from Event_State, Reliability and Out_Of_Service.
    pub overridden: bool,
    /// Event state
    pub event_state: EventState,
    /// Reliability
    pub reliability: Reliability,
    /// Out of service
    pub out_of_service: bool,
    /// Polarity
    pub polarity: Polarity,
    /// Inactive text
    pub inactive_text: String,
    /// Active text
    pub active_text: String,
    /// Priority array (16 levels)
    pub priority_array: [Option<BinaryPV>; 16],
    /// Relinquish default
    pub relinquish_default: BinaryPV,
    /// Minimum off time
    pub minimum_off_time: u32,
    /// Minimum on time
    pub minimum_on_time: u32,
    /// Present value that puts the object into an off-normal event state.
    pub alarm_value: BinaryPV,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

/// Binary Value object
#[derive(Debug, Clone)]
pub struct BinaryValue {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value
    pub present_value: BinaryPV,
    /// Description
    pub description: String,
    /// Whether an operator has overridden the point. The other Status_Flags
    /// bits are derived from Event_State, Reliability and Out_Of_Service.
    pub overridden: bool,
    /// Event state
    pub event_state: EventState,
    /// Reliability
    pub reliability: Reliability,
    /// Out of service
    pub out_of_service: bool,
    /// Inactive text
    pub inactive_text: String,
    /// Active text
    pub active_text: String,
    /// Priority array (16 levels)
    pub priority_array: [Option<BinaryPV>; 16],
    /// Relinquish default
    pub relinquish_default: BinaryPV,
    /// Present value that puts the object into an off-normal event state.
    pub alarm_value: BinaryPV,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

impl BinaryInput {
    /// Create a new Binary Input object
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::BinaryInput, instance),
            object_name,
            present_value: BinaryPV::Inactive,
            description: String::new(),
            device_type: String::new(),
            overridden: false,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            polarity: Polarity::Normal,
            inactive_text: "INACTIVE".to_string(),
            active_text: "ACTIVE".to_string(),
            change_of_state_time: None,
            change_of_state_count: 0,
            time_of_state_count_reset: None,
            alarm_value: BinaryPV::Active,
            alarm: None,
        }
    }

    /// Enable CHANGE_OF_STATE reporting through `notification_class`, alarming
    /// when Present_Value equals `alarm_value`.
    pub fn with_intrinsic_reporting(
        mut self,
        notification_class: u32,
        alarm_value: BinaryPV,
    ) -> Self {
        self.alarm_value = alarm_value;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Set the present value and update change of state
    pub fn set_present_value(&mut self, value: BinaryPV) {
        if value != self.present_value {
            self.present_value = value;
            self.change_of_state_count += 1;
            // In a real implementation, would set change_of_state_time to current time
        }
    }

    /// Status flags as individual booleans, in the in-alarm / fault /
    /// overridden / out-of-service order.
    ///
    /// Derived from Event_State, Reliability, Out_Of_Service and
    /// [`overridden`](Self::overridden); set those to change what this reports.
    pub fn get_status_flags(&self) -> (bool, bool, bool, bool) {
        let bits = status_flags_bits(
            self.event_state,
            self.reliability,
            self.out_of_service,
            self.overridden,
        );
        (bits[0], bits[1], bits[2], bits[3])
    }

    binary_views!(ObjectType::BinaryInput);
}

impl BinaryOutput {
    /// Create a new Binary Output object
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::BinaryOutput, instance),
            object_name,
            present_value: BinaryPV::Inactive,
            description: String::new(),
            device_type: String::new(),
            overridden: false,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            polarity: Polarity::Normal,
            inactive_text: "INACTIVE".to_string(),
            active_text: "ACTIVE".to_string(),
            priority_array: [None; 16],
            relinquish_default: BinaryPV::Inactive,
            minimum_off_time: 0,
            minimum_on_time: 0,
            alarm_value: BinaryPV::Active,
            alarm: None,
        }
    }

    /// Enable CHANGE_OF_STATE reporting through `notification_class`, alarming
    /// when Present_Value equals `alarm_value`.
    pub fn with_intrinsic_reporting(
        mut self,
        notification_class: u32,
        alarm_value: BinaryPV,
    ) -> Self {
        self.alarm_value = alarm_value;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<BinaryPV>) -> Result<()> {
        self.present_value = write_priority_slot(
            &mut self.priority_array,
            priority,
            value,
            self.relinquish_default,
        )?;
        Ok(())
    }

    /// Get the effective priority level for current present value
    pub fn get_effective_priority(&self) -> Option<u8> {
        effective_priority(&self.priority_array)
    }

    binary_views!(ObjectType::BinaryOutput);
}

impl BinaryValue {
    /// Create a new Binary Value object
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::BinaryValue, instance),
            object_name,
            present_value: BinaryPV::Inactive,
            description: String::new(),
            overridden: false,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            inactive_text: "INACTIVE".to_string(),
            active_text: "ACTIVE".to_string(),
            priority_array: [None; 16],
            relinquish_default: BinaryPV::Inactive,
            alarm_value: BinaryPV::Active,
            alarm: None,
        }
    }

    /// Enable CHANGE_OF_STATE reporting through `notification_class`, alarming
    /// when Present_Value equals `alarm_value`.
    pub fn with_intrinsic_reporting(
        mut self,
        notification_class: u32,
        alarm_value: BinaryPV,
    ) -> Self {
        self.alarm_value = alarm_value;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<BinaryPV>) -> Result<()> {
        self.present_value = write_priority_slot(
            &mut self.priority_array,
            priority,
            value,
            self.relinquish_default,
        )?;
        Ok(())
    }

    binary_views!(ObjectType::BinaryValue);
}

impl BacnetObject for BinaryInput {
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        shared_get(self.view(), property).unwrap_or(Err(ObjectError::UnknownProperty))
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        shared_set(self.writable(), property, value)
            .unwrap_or(Err(ObjectError::PropertyNotWritable))
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        shared_writable(property, self.alarm.is_some())
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        shared_property_list(&[], self.alarm.as_ref())
    }

    /// An input reflects a physical contact, so its Present_Value has no
    /// priority array and is simply what the source last read.
    fn set_sourced_value(&mut self, value: PropertyValue) -> Result<()> {
        // Null relinquishes a commandable object; an input has nothing to
        // relinquish to, so it is not a value a source can supply.
        match commandable_binary(value)? {
            Some(state) => {
                self.present_value = state;
                Ok(())
            }
            None => Err(ObjectError::InvalidPropertyType),
        }
    }

    binary_intrinsic_methods!();
}

/// The whole `BacnetObject` impl for a commandable binary object.
///
/// Binary Output and Binary Value answer every property identically — both are a
/// commanded state with a priority array behind it, and neither exposes anything
/// the other does not — so the impl is written once here rather than twice.
macro_rules! commandable_binary_object {
    ($object:ty) => {
        impl BacnetObject for $object {
            fn identifier(&self) -> ObjectIdentifier {
                self.identifier
            }

            fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
                if property == PropertyIdentifier::PriorityArray {
                    return Ok(priority_array_value(&self.priority_array));
                }

                shared_get(self.view(), property).unwrap_or(Err(ObjectError::UnknownProperty))
            }

            fn set_property(
                &mut self,
                property: PropertyIdentifier,
                value: PropertyValue,
            ) -> Result<()> {
                if property == PropertyIdentifier::PresentValue {
                    return self.set_property_with_priority(property, value, None);
                }

                shared_set(self.writable(), property, value)
                    .unwrap_or(Err(ObjectError::PropertyNotWritable))
            }

            fn set_property_with_priority(
                &mut self,
                property: PropertyIdentifier,
                value: PropertyValue,
                priority: Option<u8>,
            ) -> Result<()> {
                if property != PropertyIdentifier::PresentValue {
                    return self.set_property(property, value);
                }

                self.write_priority(priority.unwrap_or(16), commandable_binary(value)?)
            }

            fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
                property == PropertyIdentifier::PresentValue
                    || shared_writable(property, self.alarm.is_some())
            }

            fn property_list(&self) -> Vec<PropertyIdentifier> {
                shared_property_list(&[PropertyIdentifier::PriorityArray], self.alarm.as_ref())
            }

            binary_intrinsic_methods!();
        }
    };
}

commandable_binary_object!(BinaryOutput);
commandable_binary_object!(BinaryValue);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_pv_conversions() {
        assert_eq!(BinaryPV::from(true), BinaryPV::Active);
        assert_eq!(BinaryPV::from(false), BinaryPV::Inactive);
        assert!(bool::from(BinaryPV::Active));
        assert!(!bool::from(BinaryPV::Inactive));
    }

    #[test]
    fn test_binary_input_creation() {
        let bi = BinaryInput::new(1, "Door Switch".to_string());
        assert_eq!(bi.identifier.instance, 1);
        assert_eq!(bi.object_name, "Door Switch");
        assert_eq!(bi.present_value, BinaryPV::Inactive);
        assert_eq!(bi.change_of_state_count, 0);
    }

    #[test]
    fn test_binary_input_change_of_state() {
        let mut bi = BinaryInput::new(1, "Test".to_string());

        bi.set_present_value(BinaryPV::Active);
        assert_eq!(bi.present_value, BinaryPV::Active);
        assert_eq!(bi.change_of_state_count, 1);

        bi.set_present_value(BinaryPV::Active); // Same value, no change
        assert_eq!(bi.change_of_state_count, 1);

        bi.set_present_value(BinaryPV::Inactive);
        assert_eq!(bi.change_of_state_count, 2);
    }

    #[test]
    fn test_binary_output_priority() {
        let mut bo = BinaryOutput::new(1, "Fan Control".to_string());

        // Write to priority 8
        bo.write_priority(8, Some(BinaryPV::Active)).unwrap();
        assert_eq!(bo.present_value, BinaryPV::Active);
        assert_eq!(bo.get_effective_priority(), Some(8));

        // Write to higher priority 3
        bo.write_priority(3, Some(BinaryPV::Inactive)).unwrap();
        assert_eq!(bo.present_value, BinaryPV::Inactive);
        assert_eq!(bo.get_effective_priority(), Some(3));

        // Release priority 3
        bo.write_priority(3, None).unwrap();
        assert_eq!(bo.present_value, BinaryPV::Active);
        assert_eq!(bo.get_effective_priority(), Some(8));
    }

    #[test]
    fn binary_property_writes_preserve_priority_and_relinquish() {
        let mut output = BinaryOutput::new(1, "Fan Control".to_string());
        output
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Enumerated(1),
                Some(3),
            )
            .unwrap();
        assert_eq!(output.priority_array[2], Some(BinaryPV::Active));
        output
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Null,
                Some(3),
            )
            .unwrap();
        assert_eq!(output.priority_array[2], None);

        let mut value = BinaryValue::new(2, "Occupancy".to_string());
        value
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Enumerated(1),
                Some(4),
            )
            .unwrap();
        assert_eq!(value.priority_array[3], Some(BinaryPV::Active));
        value
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Null,
                Some(4),
            )
            .unwrap();
        assert_eq!(value.priority_array[3], None);
    }

    #[test]
    fn test_binary_object_properties() {
        let mut bv = BinaryValue::new(1, "Test Value".to_string());

        // Test property access
        let name = bv.get_property(PropertyIdentifier::ObjectName).unwrap();
        if let PropertyValue::CharacterString(n) = name {
            assert_eq!(n, "Test Value");
        } else {
            panic!("Expected CharacterString");
        }

        // Test property modification
        bv.set_property(
            PropertyIdentifier::PresentValue,
            PropertyValue::Enumerated(1),
        )
        .unwrap();
        assert_eq!(bv.present_value, BinaryPV::Active);

        // Test invalid binary value
        let result = bv.set_property(
            PropertyIdentifier::PresentValue,
            PropertyValue::Enumerated(2),
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_source_drives_an_input_but_cannot_relinquish_it() {
        let mut input = BinaryInput::new(1, "Door contact".to_string());

        input
            .set_sourced_value(PropertyValue::Enumerated(1))
            .unwrap();
        assert_eq!(input.present_value, BinaryPV::Active);

        // Null relinquishes a commandable object; an input has no priority array
        // to relinquish to, so there is nothing for it to mean.
        assert!(matches!(
            input.set_sourced_value(PropertyValue::Null),
            Err(ObjectError::InvalidPropertyType)
        ));
        assert_eq!(input.present_value, BinaryPV::Active);
    }
}
