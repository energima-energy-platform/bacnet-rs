//! Persisted device address bindings (`DeviceID MAC SNET SADR MAX-APDU`),
//! so a client can resume talking to known devices without repeating
//! discovery.

use std::{fs, io, net::SocketAddr, path::Path};

use crate::{network::NetworkAddress, object::Segmentation};

use super::{BacnetTarget, DeviceCapabilities};

/// One cached device binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedDevice {
    pub device_id: u32,
    pub target: BacnetTarget,
    pub max_apdu: u32,
    pub segmentation: Segmentation,
}

/// Load every entry from an address-cache file.
///
/// A malformed line is skipped rather than failing the whole load - a
/// hand-edited or half-written cache shouldn't block startup.
pub fn load(path: &Path) -> io::Result<Vec<CachedDevice>> {
    Ok(fs::read_to_string(path)?
        .lines()
        .filter_map(parse_line)
        .collect())
}

/// Overwrite `path` with `devices`, one line each.
pub fn save(path: &Path, devices: &[CachedDevice]) -> io::Result<()> {
    let mut contents = String::new();
    for device in devices {
        contents.push_str(&format_line(device));
        contents.push('\n');
    }
    fs::write(path, contents)
}

fn parse_line(line: &str) -> Option<CachedDevice> {
    let line = line.trim();
    if line.is_empty() || line.starts_with(';') {
        return None;
    }
    let mut fields = line.split_whitespace();
    let device_id = fields.next()?.parse().ok()?;
    let address: SocketAddr = fields.next()?.parse().ok()?;
    let snet: u16 = fields.next()?.parse().ok()?;
    let sadr = fields.next()?;
    let max_apdu = fields.next()?.parse().ok()?;
    // Absent or unrecognized (an older cache, or a real bacnet-stack file,
    // neither of which carries this column) defaults to the conservative
    // choice - assuming less capability than a device has costs a few extra
    // round trips, assuming more is the failure mode this exists to avoid.
    let segmentation = fields
        .next()
        .map(segmentation_from_str)
        .unwrap_or(Segmentation::NoSegmentation);

    let route = (snet != 0)
        .then(|| parse_hex_bytes(sadr).map(|bytes| NetworkAddress::new(snet, bytes)))
        .flatten();

    Some(CachedDevice {
        device_id,
        target: BacnetTarget {
            address,
            route,
            capabilities: Some(DeviceCapabilities {
                max_apdu,
                segmentation,
            }),
        },
        max_apdu,
        segmentation,
    })
}

fn format_line(device: &CachedDevice) -> String {
    let (snet, sadr) = match &device.target.route {
        Some(route) => (route.network, format_hex_bytes(&route.address)),
        None => (0, "0".to_string()),
    };
    format!(
        "{} {} {snet} {sadr} {} {}",
        device.device_id,
        device.target.address,
        device.max_apdu,
        segmentation_to_str(device.segmentation)
    )
}

fn segmentation_to_str(segmentation: Segmentation) -> &'static str {
    match segmentation {
        Segmentation::Both => "both",
        Segmentation::Transmit => "transmit",
        Segmentation::Receive => "receive",
        Segmentation::NoSegmentation => "none",
    }
}

fn segmentation_from_str(text: &str) -> Segmentation {
    match text {
        "both" => Segmentation::Both,
        "transmit" => Segmentation::Transmit,
        "receive" => Segmentation::Receive,
        _ => Segmentation::NoSegmentation,
    }
}

fn parse_hex_bytes(text: &str) -> Option<Vec<u8>> {
    if text == "0" {
        return Some(Vec::new());
    }
    text.split(':')
        .map(|byte| u8::from_str_radix(byte, 16).ok())
        .collect()
}

fn format_hex_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0".to_string();
    }
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_device() -> CachedDevice {
        CachedDevice {
            device_id: 4001,
            target: BacnetTarget {
                address: "127.0.0.1:47808".parse().unwrap(),
                route: None,
                capabilities: Some(DeviceCapabilities {
                    max_apdu: 1476,
                    segmentation: Segmentation::Both,
                }),
            },
            max_apdu: 1476,
            segmentation: Segmentation::Both,
        }
    }

    fn routed_device() -> CachedDevice {
        CachedDevice {
            device_id: 55555,
            target: BacnetTarget {
                address: "192.168.1.5:47808".parse().unwrap(),
                route: Some(NetworkAddress::new(
                    26001,
                    vec![0xc0, 0xa8, 0x00, 0x18, 0xba, 0xc0],
                )),
                capabilities: Some(DeviceCapabilities {
                    max_apdu: 50,
                    segmentation: Segmentation::NoSegmentation,
                }),
            },
            max_apdu: 50,
            segmentation: Segmentation::NoSegmentation,
        }
    }

    #[test]
    fn round_trips_direct_and_routed_devices() {
        let path = std::env::temp_dir().join("bacnet_rs_address_cache_round_trip.txt");
        let devices = vec![direct_device(), routed_device()];
        save(&path, &devices).expect("save");
        assert_eq!(load(&path).expect("load"), devices);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn skips_malformed_lines_without_failing() {
        let path = std::env::temp_dir().join("bacnet_rs_address_cache_malformed.txt");
        fs::write(
            &path,
            "not a valid line\n4001 127.0.0.1:47808 0 0 1476 both\n",
        )
        .unwrap();
        assert_eq!(load(&path).expect("load"), vec![direct_device()]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_missing_file_is_an_error_not_an_empty_cache() {
        let path = std::env::temp_dir().join("bacnet_rs_address_cache_does_not_exist.txt");
        assert!(load(&path).is_err());
    }

    #[test]
    fn a_missing_segmentation_column_defaults_conservatively() {
        let path = std::env::temp_dir().join("bacnet_rs_address_cache_no_segmentation_column.txt");
        fs::write(&path, "4001 127.0.0.1:47808 0 0 1476\n").unwrap();
        let loaded = load(&path).expect("load");
        assert_eq!(loaded[0].segmentation, Segmentation::NoSegmentation);
        let _ = fs::remove_file(&path);
    }
}
