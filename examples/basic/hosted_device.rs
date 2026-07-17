//! Host a small BACnet/IP device backed by an ObjectDatabase.
//!
//! ```text
//! cargo run --example hosted_device -- 127.0.0.2:47808 1234
//! BACNET_IFACE=lo BACNET_IP_PORT=47808 bacrpm \
//!     1234 2 1 77,85 --mac 127.0.0.2:47808
//! ```

use std::{env, sync::Arc};

use bacnet_rs::{
    object::{database::ObjectDatabase, AnalogValue, Device},
    server::BacnetIpServer,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let bind_address = args.next().unwrap_or_else(|| "0.0.0.0:47808".to_string());
    let device_instance = args
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(1234);

    let mut device = Device::new(device_instance, "Hosted BACnet device".to_string());
    device.vendor_identifier = 1;
    device.model_name = "bacnet-rs hosted device".to_string();

    let database = Arc::new(ObjectDatabase::new(device));
    let mut setpoint = AnalogValue::new(1, "Zone temperature setpoint".to_string());
    setpoint.description = "Example commandable analog value".to_string();
    setpoint.present_value = 21.5;
    database.add_object(Box::new(setpoint))?;

    let server = BacnetIpServer::bind(&bind_address, database)?;
    println!("Hosting BACnet device {device_instance} on {bind_address}");

    loop {
        server.serve_once()?;
    }
}
