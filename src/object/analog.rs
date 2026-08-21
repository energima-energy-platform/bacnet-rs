//! Analog Object Types Implementation
//!
//! This module implements the Analog Input, Analog Output, and Analog Value object types
//! as defined in ASHRAE 135. These objects represent analog (continuous) values in BACnet.

use crate::object::{
    common_get, common_set, effective_priority,
    engineering_units::EngineeringUnits,
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
use alloc::{string::String, vec, vec::Vec};

fn commandable_real(value: PropertyValue) -> Result<Option<f32>> {
    match value {
        PropertyValue::Real(value) => Ok(Some(value)),
        PropertyValue::Null => Ok(None),
        _ => Err(ObjectError::InvalidPropertyType),
    }
}

/// Read an alarm property from an analog object.
///
/// Returns `None` when the object has no intrinsic reporting configured, or when
/// `property` is not an alarm property. An analog object with reporting but no
/// limits runs CHANGE_OF_RELIABILITY, so its limit properties do not exist.
fn analog_alarm_get(
    high_limit: Option<f32>,
    low_limit: Option<f32>,
    deadband: f32,
    alarm: Option<&IntrinsicReporting>,
    property: PropertyIdentifier,
) -> Option<Result<PropertyValue>> {
    let alarm = alarm?;

    let value = match property {
        PropertyIdentifier::HighLimit => match high_limit {
            Some(limit) => PropertyValue::Real(limit),
            None => return Some(Err(ObjectError::UnknownProperty)),
        },
        PropertyIdentifier::LowLimit => match low_limit {
            Some(limit) => PropertyValue::Real(limit),
            None => return Some(Err(ObjectError::UnknownProperty)),
        },
        PropertyIdentifier::Deadband => PropertyValue::Real(deadband),
        // Limit_Enable is ordered low-limit-enable, high-limit-enable.
        PropertyIdentifier::LimitEnable => {
            PropertyValue::BitString(vec![low_limit.is_some(), high_limit.is_some()])
        }
        _ => return intrinsic_get(alarm, property),
    };

    Some(Ok(value))
}

/// Write an alarm property on an analog object. `None` follows the same
/// convention as [`analog_alarm_get`].
fn analog_alarm_set(
    high_limit: &mut Option<f32>,
    low_limit: &mut Option<f32>,
    deadband: &mut f32,
    alarm: Option<&mut IntrinsicReporting>,
    property: PropertyIdentifier,
    value: PropertyValue,
) -> Option<Result<()>> {
    let alarm = alarm?;

    let result = match property {
        PropertyIdentifier::HighLimit => match value {
            PropertyValue::Real(limit) => {
                *high_limit = Some(limit);
                Ok(())
            }
            PropertyValue::Null => {
                *high_limit = None;
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        },
        PropertyIdentifier::LowLimit => match value {
            PropertyValue::Real(limit) => {
                *low_limit = Some(limit);
                Ok(())
            }
            PropertyValue::Null => {
                *low_limit = None;
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        },
        PropertyIdentifier::Deadband => match value {
            PropertyValue::Real(band) => {
                *deadband = band;
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        },
        _ => return intrinsic_set(alarm, property, value),
    };

    Some(result)
}

/// Alarm properties an analog object exposes, given its configuration.
fn analog_alarm_property_list(
    high_limit: Option<f32>,
    low_limit: Option<f32>,
    alarm: Option<&IntrinsicReporting>,
) -> Vec<PropertyIdentifier> {
    if alarm.is_none() {
        return Vec::new();
    }

    let mut properties = intrinsic_property_list();
    if high_limit.is_some() || low_limit.is_some() {
        properties.extend([
            PropertyIdentifier::Deadband,
            PropertyIdentifier::LimitEnable,
        ]);
        if high_limit.is_some() {
            properties.push(PropertyIdentifier::HighLimit);
        }
        if low_limit.is_some() {
            properties.push(PropertyIdentifier::LowLimit);
        }
    }
    properties
}

/// Whether an analog alarm property accepts writes.
fn analog_alarm_writable(property: PropertyIdentifier, alarm_configured: bool) -> bool {
    alarm_configured
        && matches!(
            property,
            PropertyIdentifier::HighLimit
                | PropertyIdentifier::LowLimit
                | PropertyIdentifier::Deadband
                | PropertyIdentifier::NotificationClass
                | PropertyIdentifier::TimeDelay
                | PropertyIdentifier::TimeDelayNormal
                | PropertyIdentifier::EventEnable
                | PropertyIdentifier::NotifyType
                | PropertyIdentifier::EventDetectionEnable
        )
}

/// Run OUT_OF_RANGE, or CHANGE_OF_RELIABILITY when no limits are configured.
///
/// The deadband is hysteresis on the way back: once high-limit has tripped, the
/// value must fall below `high_limit - deadband` before the object returns to
/// normal (and symmetrically for low-limit). Without that, a value hovering on a
/// limit would emit a notification per evaluation.
fn evaluate_analog(
    present_value: f32,
    high_limit: Option<f32>,
    low_limit: Option<f32>,
    deadband: f32,
    reliability: Reliability,
    current_state: EventState,
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

    // No limits means this object only reports reliability changes.
    if high_limit.is_none() && low_limit.is_none() {
        return Some(AlarmEvaluation {
            desired_state: EventState::Normal,
            trigger: AlarmTrigger::ReliabilityChange { reliability },
        });
    }

    if let Some(limit) = high_limit {
        let tripped = if current_state == EventState::HighLimit {
            present_value > limit - deadband
        } else {
            present_value > limit
        };
        if tripped {
            return Some(AlarmEvaluation {
                desired_state: EventState::HighLimit,
                trigger: AlarmTrigger::OutOfRange {
                    exceeding_value: present_value,
                    exceeded_limit: limit,
                    deadband,
                },
            });
        }
    }

    if let Some(limit) = low_limit {
        let tripped = if current_state == EventState::LowLimit {
            present_value < limit + deadband
        } else {
            present_value < limit
        };
        if tripped {
            return Some(AlarmEvaluation {
                desired_state: EventState::LowLimit,
                trigger: AlarmTrigger::OutOfRange {
                    exceeding_value: present_value,
                    exceeded_limit: limit,
                    deadband,
                },
            });
        }
    }

    // Back in range: report the limit that was breached, which is the one the
    // object is returning from. Reporting the other limit would tell the
    // recipient a low-limit recovery cleared the high limit.
    let breached = if current_state == EventState::LowLimit {
        low_limit.or(high_limit)
    } else {
        high_limit.or(low_limit)
    };
    Some(AlarmEvaluation {
        desired_state: EventState::Normal,
        trigger: AlarmTrigger::OutOfRange {
            exceeding_value: present_value,
            exceeded_limit: breached.unwrap_or(present_value),
            deadband,
        },
    })
}

/// The intrinsic reporting trait methods shared by all analog object types.
/// The state every analog object type answers from, borrowed from whichever
/// object is answering.
struct AnalogView<'a> {
    identifier: ObjectIdentifier,
    object_type: ObjectType,
    object_name: &'a str,
    description: &'a str,
    present_value: f32,
    overridden: bool,
    event_state: EventState,
    reliability: Reliability,
    out_of_service: bool,
    units: EngineeringUnits,
    high_limit: Option<f32>,
    low_limit: Option<f32>,
    deadband: f32,
    alarm: Option<&'a IntrinsicReporting>,
}

/// Read a property common to every analog object type.
///
/// Returns `None` for properties belonging to a single type (device type,
/// priority array, relinquish default, COV increment) so callers fall through to
/// their own arms.
fn shared_get(view: AnalogView<'_>, property: PropertyIdentifier) -> Option<Result<PropertyValue>> {
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
        PropertyIdentifier::PresentValue => PropertyValue::Real(view.present_value),
        PropertyIdentifier::Units => PropertyValue::Enumerated(view.units.into()),
        _ => {
            return analog_alarm_get(
                view.high_limit,
                view.low_limit,
                view.deadband,
                view.alarm,
                property,
            )
        }
    };

    Some(Ok(value))
}

/// The writable fields shared by every analog object type.
struct AnalogWritable<'a> {
    object_name: &'a mut String,
    description: &'a mut String,
    reliability: &'a mut Reliability,
    out_of_service: &'a mut bool,
    high_limit: &'a mut Option<f32>,
    low_limit: &'a mut Option<f32>,
    deadband: &'a mut f32,
    alarm: Option<&'a mut IntrinsicReporting>,
}

/// Write a property common to every analog object type. `None` means the
/// property is not one this helper owns.
fn shared_set(
    fields: AnalogWritable<'_>,
    property: PropertyIdentifier,
    value: PropertyValue,
) -> Option<Result<()>> {
    let AnalogWritable {
        object_name,
        description,
        reliability,
        out_of_service,
        high_limit,
        low_limit,
        deadband,
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

    analog_alarm_set(high_limit, low_limit, deadband, alarm, property, value)
}

/// Whether a property shared by every analog object type accepts writes.
fn shared_writable(property: PropertyIdentifier, alarm_configured: bool) -> bool {
    matches!(
        property,
        PropertyIdentifier::ObjectName
            | PropertyIdentifier::Description
            | PropertyIdentifier::OutOfService
            | PropertyIdentifier::Reliability
    ) || analog_alarm_writable(property, alarm_configured)
}

/// Properties every analog object exposes, in the order they are reported.
///
/// The per-type additions sit inside that order rather than after it: Device_Type
/// between Description and Status_Flags, and the commandable and COV properties
/// in `trailing`, straight after Units.
fn shared_property_list(
    device_type: bool,
    trailing: &[PropertyIdentifier],
    high_limit: Option<f32>,
    low_limit: Option<f32>,
    alarm: Option<&IntrinsicReporting>,
) -> Vec<PropertyIdentifier> {
    let mut properties = vec![
        PropertyIdentifier::ObjectIdentifier,
        PropertyIdentifier::ObjectName,
        PropertyIdentifier::ObjectType,
        PropertyIdentifier::PresentValue,
        PropertyIdentifier::Description,
    ];
    if device_type {
        properties.push(PropertyIdentifier::DeviceType);
    }
    properties.extend([
        PropertyIdentifier::StatusFlags,
        PropertyIdentifier::EventState,
        PropertyIdentifier::Reliability,
        PropertyIdentifier::OutOfService,
        PropertyIdentifier::Units,
    ]);
    properties.extend_from_slice(trailing);
    properties.extend(analog_alarm_property_list(high_limit, low_limit, alarm));
    properties
}

/// The Priority_Array property of a commandable analog object.
fn priority_array_value(priority_array: &[Option<f32>; 16]) -> PropertyValue {
    PropertyValue::Array(
        priority_array
            .iter()
            .map(|slot| match slot {
                Some(value) => PropertyValue::Real(*value),
                None => PropertyValue::Null,
            })
            .collect(),
    )
}

/// Generate the borrowed views the shared analog handlers take.
///
/// All three analog types hold this state under the same field names, but on
/// three separate structs, so only the object type differs between them.
macro_rules! analog_views {
    ($object_type:expr) => {
        fn view(&self) -> AnalogView<'_> {
            AnalogView {
                identifier: self.identifier,
                object_type: $object_type,
                object_name: &self.object_name,
                description: &self.description,
                present_value: self.present_value,
                overridden: self.overridden,
                event_state: self.event_state,
                reliability: self.reliability,
                out_of_service: self.out_of_service,
                units: self.units,
                high_limit: self.high_limit,
                low_limit: self.low_limit,
                deadband: self.deadband,
                alarm: self.alarm.as_ref(),
            }
        }

        fn writable(&mut self) -> AnalogWritable<'_> {
            AnalogWritable {
                object_name: &mut self.object_name,
                description: &mut self.description,
                reliability: &mut self.reliability,
                out_of_service: &mut self.out_of_service,
                high_limit: &mut self.high_limit,
                low_limit: &mut self.low_limit,
                deadband: &mut self.deadband,
                alarm: self.alarm.as_mut(),
            }
        }
    };
}

macro_rules! analog_intrinsic_methods {
    () => {
        fn intrinsic(&self) -> Option<&IntrinsicReporting> {
            self.alarm.as_ref()
        }

        fn intrinsic_mut(&mut self) -> Option<&mut IntrinsicReporting> {
            self.alarm.as_mut()
        }

        fn evaluate_alarm(&self) -> Option<AlarmEvaluation> {
            evaluate_analog(
                self.present_value,
                self.high_limit,
                self.low_limit,
                self.deadband,
                self.reliability,
                self.event_state,
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

/// Analog Input object
#[derive(Debug, Clone)]
pub struct AnalogInput {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value
    pub present_value: f32,
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
    /// Units
    pub units: EngineeringUnits,
    /// Minimum present value
    pub min_pres_value: Option<f32>,
    /// Maximum present value
    pub max_pres_value: Option<f32>,
    /// Resolution
    pub resolution: Option<f32>,
    /// COV increment
    pub cov_increment: Option<f32>,
    /// OUT_OF_RANGE high limit; `None` disables the high-limit check.
    pub high_limit: Option<f32>,
    /// OUT_OF_RANGE low limit; `None` disables the low-limit check.
    pub low_limit: Option<f32>,
    /// Hysteresis applied before returning to normal.
    pub deadband: f32,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

/// Analog Output object
#[derive(Debug, Clone)]
pub struct AnalogOutput {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value
    pub present_value: f32,
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
    /// Units
    pub units: EngineeringUnits,
    /// Minimum present value
    pub min_pres_value: Option<f32>,
    /// Maximum present value
    pub max_pres_value: Option<f32>,
    /// Resolution
    pub resolution: Option<f32>,
    /// Priority array (16 levels)
    pub priority_array: [Option<f32>; 16],
    /// Relinquish default
    pub relinquish_default: f32,
    /// COV increment
    pub cov_increment: Option<f32>,
    /// OUT_OF_RANGE high limit; `None` disables the high-limit check.
    pub high_limit: Option<f32>,
    /// OUT_OF_RANGE low limit; `None` disables the low-limit check.
    pub low_limit: Option<f32>,
    /// Hysteresis applied before returning to normal.
    pub deadband: f32,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

/// Analog Value object
#[derive(Debug, Clone)]
pub struct AnalogValue {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value
    pub present_value: f32,
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
    /// Units
    pub units: EngineeringUnits,
    /// Priority array (16 levels)
    pub priority_array: [Option<f32>; 16],
    /// Relinquish default
    pub relinquish_default: f32,
    /// COV increment
    pub cov_increment: Option<f32>,
    /// OUT_OF_RANGE high limit; `None` disables the high-limit check.
    pub high_limit: Option<f32>,
    /// OUT_OF_RANGE low limit; `None` disables the low-limit check.
    pub low_limit: Option<f32>,
    /// Hysteresis applied before returning to normal.
    pub deadband: f32,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

// EngineeringUnits enum moved to src/object/engineering_units.rs for complete implementation

impl AnalogInput {
    /// Create a new Analog Input object
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::AnalogInput, instance),
            object_name,
            present_value: 0.0,
            description: String::new(),
            device_type: String::new(),
            overridden: false,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            units: EngineeringUnits::NoUnits,
            min_pres_value: None,
            max_pres_value: None,
            resolution: None,
            cov_increment: None,
            high_limit: None,
            low_limit: None,
            deadband: 0.0,
            alarm: None,
        }
    }

    /// Enable CHANGE_OF_RELIABILITY reporting through `notification_class`.
    pub fn with_intrinsic_reporting(mut self, notification_class: u32) -> Self {
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Enable OUT_OF_RANGE reporting through `notification_class`.
    pub fn with_out_of_range_reporting(
        mut self,
        notification_class: u32,
        low_limit: Option<f32>,
        high_limit: Option<f32>,
        deadband: f32,
    ) -> Self {
        self.low_limit = low_limit;
        self.high_limit = high_limit;
        self.deadband = deadband;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Set the present value
    pub fn set_present_value(&mut self, value: f32) {
        self.present_value = value;
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

    analog_views!(ObjectType::AnalogInput);
}

impl AnalogOutput {
    /// Create a new Analog Output object
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::AnalogOutput, instance),
            object_name,
            present_value: 0.0,
            description: String::new(),
            device_type: String::new(),
            overridden: false,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            units: EngineeringUnits::NoUnits,
            min_pres_value: None,
            max_pres_value: None,
            resolution: None,
            priority_array: [None; 16],
            relinquish_default: 0.0,
            cov_increment: None,
            high_limit: None,
            low_limit: None,
            deadband: 0.0,
            alarm: None,
        }
    }

    /// Enable CHANGE_OF_RELIABILITY reporting through `notification_class`.
    pub fn with_intrinsic_reporting(mut self, notification_class: u32) -> Self {
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Enable OUT_OF_RANGE reporting through `notification_class`.
    pub fn with_out_of_range_reporting(
        mut self,
        notification_class: u32,
        low_limit: Option<f32>,
        high_limit: Option<f32>,
        deadband: f32,
    ) -> Self {
        self.low_limit = low_limit;
        self.high_limit = high_limit;
        self.deadband = deadband;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<f32>) -> Result<()> {
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

    analog_views!(ObjectType::AnalogOutput);
}

impl AnalogValue {
    /// Create a new Analog Value object
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::AnalogValue, instance),
            object_name,
            present_value: 0.0,
            description: String::new(),
            overridden: false,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            units: EngineeringUnits::NoUnits,
            priority_array: [None; 16],
            relinquish_default: 0.0,
            cov_increment: None,
            high_limit: None,
            low_limit: None,
            deadband: 0.0,
            alarm: None,
        }
    }

    /// Enable CHANGE_OF_RELIABILITY reporting through `notification_class`.
    pub fn with_intrinsic_reporting(mut self, notification_class: u32) -> Self {
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Enable OUT_OF_RANGE reporting through `notification_class`.
    pub fn with_out_of_range_reporting(
        mut self,
        notification_class: u32,
        low_limit: Option<f32>,
        high_limit: Option<f32>,
        deadband: f32,
    ) -> Self {
        self.low_limit = low_limit;
        self.high_limit = high_limit;
        self.deadband = deadband;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<f32>) -> Result<()> {
        self.present_value = write_priority_slot(
            &mut self.priority_array,
            priority,
            value,
            self.relinquish_default,
        )?;
        Ok(())
    }

    analog_views!(ObjectType::AnalogValue);
}

impl BacnetObject for AnalogInput {
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        if property == PropertyIdentifier::DeviceType {
            return Ok(PropertyValue::CharacterString(self.device_type.clone()));
        }

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
        shared_property_list(
            true,
            &[],
            self.high_limit,
            self.low_limit,
            self.alarm.as_ref(),
        )
    }

    /// An input reflects a sensor, so its Present_Value has no priority array
    /// and is simply what the source last read.
    fn set_sourced_value(&mut self, value: PropertyValue) -> Result<()> {
        match value {
            PropertyValue::Real(value) => {
                self.present_value = value;
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        }
    }

    analog_intrinsic_methods!();
}

impl BacnetObject for AnalogOutput {
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::DeviceType => {
                Ok(PropertyValue::CharacterString(self.device_type.clone()))
            }
            PropertyIdentifier::PriorityArray => Ok(priority_array_value(&self.priority_array)),
            PropertyIdentifier::RelinquishDefault => {
                Ok(PropertyValue::Real(self.relinquish_default))
            }
            _ => shared_get(self.view(), property).unwrap_or(Err(ObjectError::UnknownProperty)),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
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

        self.write_priority(priority.unwrap_or(16), commandable_real(value)?)
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        property == PropertyIdentifier::PresentValue
            || shared_writable(property, self.alarm.is_some())
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        shared_property_list(
            true,
            &[
                PropertyIdentifier::PriorityArray,
                PropertyIdentifier::RelinquishDefault,
            ],
            self.high_limit,
            self.low_limit,
            self.alarm.as_ref(),
        )
    }

    analog_intrinsic_methods!();
}

impl BacnetObject for AnalogValue {
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::PriorityArray => Ok(priority_array_value(&self.priority_array)),
            PropertyIdentifier::RelinquishDefault => {
                Ok(PropertyValue::Real(self.relinquish_default))
            }
            PropertyIdentifier::CovIncrement => self
                .cov_increment
                .map(PropertyValue::Real)
                .ok_or(ObjectError::UnknownProperty),
            _ => shared_get(self.view(), property).unwrap_or(Err(ObjectError::UnknownProperty)),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
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

        self.write_priority(priority.unwrap_or(16), commandable_real(value)?)
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        property == PropertyIdentifier::PresentValue
            || shared_writable(property, self.alarm.is_some())
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        let mut trailing = vec![
            PropertyIdentifier::PriorityArray,
            PropertyIdentifier::RelinquishDefault,
        ];
        if self.cov_increment.is_some() {
            trailing.push(PropertyIdentifier::CovIncrement);
        }

        shared_property_list(
            false,
            &trailing,
            self.high_limit,
            self.low_limit,
            self.alarm.as_ref(),
        )
    }

    analog_intrinsic_methods!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analog_input_creation() {
        let ai = AnalogInput::new(1, "Temperature Sensor".to_string());
        assert_eq!(ai.identifier.instance, 1);
        assert_eq!(ai.object_name, "Temperature Sensor");
        assert_eq!(ai.present_value, 0.0);
        assert!(!ai.out_of_service);
    }

    #[test]
    fn test_analog_output_priority() {
        let mut ao = AnalogOutput::new(1, "Damper Position".to_string());

        // Write to priority 8
        ao.write_priority(8, Some(75.0)).unwrap();
        assert_eq!(ao.present_value, 75.0);
        assert_eq!(ao.get_effective_priority(), Some(8));

        // Write to higher priority 3
        ao.write_priority(3, Some(50.0)).unwrap();
        assert_eq!(ao.present_value, 50.0);
        assert_eq!(ao.get_effective_priority(), Some(3));

        // Release priority 3
        ao.write_priority(3, None).unwrap();
        assert_eq!(ao.present_value, 75.0);
        assert_eq!(ao.get_effective_priority(), Some(8));

        // Release all priorities
        ao.write_priority(8, None).unwrap();
        assert_eq!(ao.present_value, ao.relinquish_default);
        assert_eq!(ao.get_effective_priority(), None);
    }

    #[test]
    fn analog_output_property_write_preserves_priority_and_relinquishes() {
        let mut output = AnalogOutput::new(1, "Damper Position".to_string());

        output
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(50.0),
                Some(3),
            )
            .unwrap();
        assert_eq!(output.priority_array[2], Some(50.0));

        output
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Null,
                Some(3),
            )
            .unwrap();
        assert_eq!(output.priority_array[2], None);
    }

    #[test]
    fn test_analog_object_properties() {
        let mut av = AnalogValue::new(1, "Test Value".to_string());

        // Test property access
        let name = av.get_property(PropertyIdentifier::ObjectName).unwrap();
        if let PropertyValue::CharacterString(n) = name {
            assert_eq!(n, "Test Value");
        } else {
            panic!("Expected CharacterString");
        }

        // Test property modification
        av.set_property(PropertyIdentifier::PresentValue, PropertyValue::Real(42.5))
            .unwrap();
        assert_eq!(av.present_value, 42.5);

        // Test writable properties
        assert!(av.is_property_writable(PropertyIdentifier::PresentValue));
        assert!(!av.is_property_writable(PropertyIdentifier::ObjectIdentifier));
    }

    #[test]
    fn test_status_flags() {
        let mut ai = AnalogInput::new(1, "Test".to_string());
        assert_eq!(ai.get_status_flags(), (false, false, false, false));

        ai.event_state = EventState::Offnormal;
        ai.overridden = true;
        assert_eq!(ai.get_status_flags(), (true, false, true, false));
    }

    /// Status_Flags is derived, so a client that writes Out_Of_Service or
    /// Reliability sees it move. It used to be a cached byte that only the event
    /// engine refreshed, so both writes left it reading all-false.
    #[test]
    fn status_flags_follow_out_of_service_and_reliability() {
        let mut value = AnalogValue::new(1, "Temp".to_string());

        value
            .set_property(
                PropertyIdentifier::OutOfService,
                PropertyValue::Boolean(true),
            )
            .unwrap();
        assert_eq!(
            value.get_property(PropertyIdentifier::StatusFlags).unwrap(),
            PropertyValue::BitString(vec![false, false, false, true]),
            "out-of-service"
        );

        value
            .set_property(
                PropertyIdentifier::Reliability,
                PropertyValue::Enumerated(u32::from(Reliability::ProcessError)),
            )
            .unwrap();
        assert_eq!(
            value.get_property(PropertyIdentifier::StatusFlags).unwrap(),
            PropertyValue::BitString(vec![false, true, false, true]),
            "fault follows Reliability even while Event_State is normal"
        );

        value
            .set_property(
                PropertyIdentifier::Reliability,
                PropertyValue::Enumerated(u32::from(Reliability::NoFaultDetected)),
            )
            .unwrap();
        assert_eq!(
            value.get_property(PropertyIdentifier::StatusFlags).unwrap(),
            PropertyValue::BitString(vec![false, false, false, true]),
            "and clears again"
        );
    }

    /// The point of the hook: a host can drive an input whose Present_Value no
    /// network client is allowed to write.
    #[test]
    fn a_source_can_drive_an_input_that_clients_cannot_write() {
        let mut input = AnalogInput::new(1, "Outdoor temperature".to_string());

        assert!(!input.is_property_writable(PropertyIdentifier::PresentValue));
        assert!(matches!(
            input.set_property(PropertyIdentifier::PresentValue, PropertyValue::Real(5.0)),
            Err(ObjectError::PropertyNotWritable)
        ));

        input.set_sourced_value(PropertyValue::Real(5.0)).unwrap();

        assert_eq!(
            input
                .get_property(PropertyIdentifier::PresentValue)
                .unwrap(),
            PropertyValue::Real(5.0)
        );
        assert!(matches!(
            input.set_sourced_value(PropertyValue::Boolean(true)),
            Err(ObjectError::InvalidPropertyType)
        ));
    }

    /// A commandable object has a priority array, so a source driving it must go
    /// through the command path rather than around it.
    #[test]
    fn a_commandable_object_reports_the_hook_as_unsupported() {
        let mut value = AnalogValue::new(1, "Setpoint".to_string());

        assert!(matches!(
            value.set_sourced_value(PropertyValue::Real(5.0)),
            Err(ObjectError::OptionalFunctionalityNotSupported)
        ));
    }
}
