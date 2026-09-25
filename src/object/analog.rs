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
    override_permits_write,
    reliability::Reliability,
    write_priority_slot, BacnetObject, CommonView, CommonWritable, CommonWrite, LocalOverride,
    ObjectError, ObjectIdentifier, ObjectType, OptionalProperties, PropertyIdentifier,
    PropertyValue, Result,
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
    cov_increment: Option<f32>,
    alarm: Option<&'a IntrinsicReporting>,
    optional: OptionalProperties,
}

/// Read a property common to every analog object type.
///
/// Returns `None` for properties belonging to a single type (device type,
/// priority array, relinquish default) so callers fall through to their own
/// arms.
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
            optional: view.optional,
        },
        property,
    ) {
        return Some(result);
    }

    // Optional on all three analog types, not just the commandable one, and
    // present exactly when the object has an increment. Absent it is an unknown
    // property rather than a zero, which a COV engine would read as "report
    // every change".
    if property == PropertyIdentifier::CovIncrement {
        return Some(
            view.cov_increment
                .map(PropertyValue::Real)
                .ok_or(ObjectError::UnknownProperty),
        );
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
    optional: OptionalProperties,
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
        optional,
    } = fields;

    let value = match common_set(
        CommonWritable {
            object_name,
            description,
            reliability,
            out_of_service,
            optional,
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
fn shared_writable(
    property: PropertyIdentifier,
    alarm_configured: bool,
    optional: OptionalProperties,
) -> bool {
    optional.has(property)
        && matches!(
            property,
            PropertyIdentifier::ObjectName
                | PropertyIdentifier::Description
                | PropertyIdentifier::OutOfService
                | PropertyIdentifier::Reliability
        )
        || analog_alarm_writable(property, alarm_configured)
}

/// Commandable, or written straight through: an Analog Value may be either,
/// and only a commandable one has Priority_Array and Relinquish_Default.
fn commandable_trailing(commandable: bool) -> &'static [PropertyIdentifier] {
    if commandable {
        &[
            PropertyIdentifier::PriorityArray,
            PropertyIdentifier::RelinquishDefault,
        ]
    } else {
        &[]
    }
}

/// Properties every analog object exposes, in the order they are reported.
///
/// The per-type additions sit inside that order rather than after it: Device_Type
/// between Description and Status_Flags, and the commandable properties in
/// `trailing`, straight after Units. COV_Increment follows them, and is listed
/// only when the object has one - it is optional on every analog type.
fn shared_property_list(
    device_type: bool,
    trailing: &[PropertyIdentifier],
    view: &AnalogView<'_>,
) -> Vec<PropertyIdentifier> {
    let AnalogView {
        cov_increment,
        high_limit,
        low_limit,
        alarm,
        optional,
        ..
    } = *view;
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
    if cov_increment.is_some() {
        properties.push(PropertyIdentifier::CovIncrement);
    }
    properties.extend(analog_alarm_property_list(high_limit, low_limit, alarm));
    optional.retain(&mut properties);
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
                present_value: self.effective_present_value(),
                overridden: self.overridden || self.local_override.is_some(),
                event_state: self.event_state,
                reliability: self.reliability,
                out_of_service: self.out_of_service,
                units: self.units,
                high_limit: self.high_limit,
                low_limit: self.low_limit,
                deadband: self.deadband,
                cov_increment: self.cov_increment,
                alarm: self.alarm.as_ref(),
                optional: self.optional,
            }
        }

        /// What Present_Value reads: the local override while there is one.
        pub fn effective_present_value(&self) -> f32 {
            self.local_override
                .map_or(self.present_value, |local| local.value)
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
                optional: self.optional,
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
                self.effective_present_value(),
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
    /// Which optional properties the object has.
    pub optional: OptionalProperties,
    /// A local mechanism holding Present_Value, when one is.
    pub local_override: Option<LocalOverride<f32>>,
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
    /// Which optional properties the object has.
    pub optional: OptionalProperties,
    /// A local mechanism holding Present_Value, when one is.
    pub local_override: Option<LocalOverride<f32>>,
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
    /// Whether Present_Value is commanded through a priority array, or
    /// written straight through.
    pub commandable: bool,
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
    /// Which optional properties the object has.
    pub optional: OptionalProperties,
    /// A local mechanism holding Present_Value, when one is.
    pub local_override: Option<LocalOverride<f32>>,
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
            optional: OptionalProperties::default(),
            local_override: None,
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
            optional: OptionalProperties::default(),
            local_override: None,
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
            commandable: true,
            priority_array: [None; 16],
            relinquish_default: 0.0,
            cov_increment: None,
            high_limit: None,
            low_limit: None,
            deadband: 0.0,
            alarm: None,
            optional: OptionalProperties::default(),
            local_override: None,
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
        shared_writable(property, self.alarm.is_some(), self.optional)
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        shared_property_list(true, &[], &self.view())
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
        override_permits_write(&self.local_override)?;

        self.write_priority(priority.unwrap_or(16), commandable_real(value)?)
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        property == PropertyIdentifier::PresentValue
            || shared_writable(property, self.alarm.is_some(), self.optional)
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        shared_property_list(true, commandable_trailing(true), &self.view())
    }

    analog_intrinsic_methods!();
}

impl BacnetObject for AnalogValue {
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::PriorityArray if self.commandable => {
                Ok(priority_array_value(&self.priority_array))
            }
            PropertyIdentifier::RelinquishDefault if self.commandable => {
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
        override_permits_write(&self.local_override)?;

        // Not commandable: the value is simply written, and a priority has
        // nothing to act on. Nor is there anything to relinquish to.
        if !self.commandable {
            let value = commandable_real(value)?.ok_or(ObjectError::InvalidPropertyType)?;
            self.present_value = value;
            return Ok(());
        }
        self.write_priority(priority.unwrap_or(16), commandable_real(value)?)
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        property == PropertyIdentifier::PresentValue
            || shared_writable(property, self.alarm.is_some(), self.optional)
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        shared_property_list(false, commandable_trailing(self.commandable), &self.view())
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

    /// COV_Increment is optional on all three analog types, and it was the
    /// commandable one that had it: an input's increment was stored and never
    /// answered, so a COV engine asking for it found nothing and reported every
    /// change a sensor made.
    #[test]
    fn every_analog_type_answers_the_cov_increment_it_holds() {
        let mut input = AnalogInput::new(1, "Room CO2".to_string());
        let mut output = AnalogOutput::new(1, "Damper".to_string());
        let mut value = AnalogValue::new(1, "Setpoint".to_string());

        for object in [&input as &dyn BacnetObject, &output, &value] {
            assert!(matches!(
                object.get_property(PropertyIdentifier::CovIncrement),
                Err(ObjectError::UnknownProperty)
            ));
            assert!(!object
                .property_list()
                .contains(&PropertyIdentifier::CovIncrement));
        }

        input.cov_increment = Some(25.0);
        output.cov_increment = Some(2.0);
        value.cov_increment = Some(0.5);

        for (object, increment) in [
            (&input as &dyn BacnetObject, 25.0),
            (&output, 2.0),
            (&value, 0.5),
        ] {
            assert_eq!(
                object
                    .get_property(PropertyIdentifier::CovIncrement)
                    .unwrap(),
                PropertyValue::Real(increment)
            );
            assert!(object
                .property_list()
                .contains(&PropertyIdentifier::CovIncrement));
        }
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

    fn status_flags(object: &impl BacnetObject) -> Vec<bool> {
        match object
            .get_property(PropertyIdentifier::StatusFlags)
            .unwrap()
        {
            PropertyValue::BitString(bits) => bits,
            other => panic!("expected a bit string, got {other:?}"),
        }
    }

    #[test]
    fn a_value_that_is_not_commandable_is_written_straight_through() {
        let mut value = AnalogValue::new(1, "Setpoint".to_string());
        value.commandable = false;

        assert!(matches!(
            value.get_property(PropertyIdentifier::PriorityArray),
            Err(ObjectError::UnknownProperty)
        ));
        assert!(!value
            .property_list()
            .contains(&PropertyIdentifier::RelinquishDefault));

        value
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(22.0),
                Some(8),
            )
            .unwrap();
        assert_eq!(value.present_value, 22.0);
        assert!(value
            .set_property(PropertyIdentifier::PresentValue, PropertyValue::Null)
            .is_err());
    }

    #[test]
    fn an_absent_reliability_is_an_unknown_property() {
        let mut input = AnalogInput::new(1, "Outdoor".to_string());
        input.optional.reliability = false;

        assert!(matches!(
            input.get_property(PropertyIdentifier::Reliability),
            Err(ObjectError::UnknownProperty)
        ));
        assert!(!input
            .property_list()
            .contains(&PropertyIdentifier::Reliability));
        assert!(input
            .property_list()
            .contains(&PropertyIdentifier::Description));
    }

    #[test]
    fn a_local_override_holds_the_value_until_it_is_released() {
        let mut value = AnalogValue::new(1, "Setpoint".to_string());
        value.local_override = Some(LocalOverride {
            value: 19.0,
            writes: crate::object::OverrideWrites::Accepted,
        });

        value
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(22.0),
                Some(8),
            )
            .unwrap();
        assert_eq!(
            value
                .get_property(PropertyIdentifier::PresentValue)
                .unwrap(),
            PropertyValue::Real(19.0),
            "the write waits behind the override"
        );
        assert!(status_flags(&value)[2], "OVERRIDDEN");

        value.local_override = None;
        assert_eq!(
            value
                .get_property(PropertyIdentifier::PresentValue)
                .unwrap(),
            PropertyValue::Real(22.0)
        );
        assert!(!status_flags(&value)[2]);
    }

    #[test]
    fn a_local_override_can_refuse_writes_outright() {
        let mut output = AnalogOutput::new(1, "Valve".to_string());
        output.local_override = Some(LocalOverride {
            value: 100.0,
            writes: crate::object::OverrideWrites::Denied,
        });

        assert!(matches!(
            output.set_property(PropertyIdentifier::PresentValue, PropertyValue::Real(0.0)),
            Err(ObjectError::WriteAccessDenied)
        ));
    }
}
