//! Segmentation, driven against a stack that implements ASHRAE 135 clause 5.4
//! in full.
//!
//! The peer is bacpypes3, not bacnet-stack. The C stack's own CHANGELOG says
//! it has "no support for segmentation in the TSM or APDU handlers", and its
//! `PDU_TYPE_SEGMENT_ACK` case does nothing but free the invoke ID - so it
//! cannot exercise either direction. bacpypes3 carries the whole state
//! machine.
//!
//! Why an outside stack at all, when `segmentation.rs` already tests both
//! halves over loopback: those tests are this crate answering itself, so a
//! misreading of the spec would be shared by both ends and pass. These are the
//! ones that would catch it.
//!
//! Skipped, loudly, when no interpreter with bacpypes3 is available. Point
//! `BACNET_INTEROP_PYTHON` at one, or `pip install bacpypes3` into the
//! `python3` on PATH.

#![cfg(feature = "async")]

use std::{
    net::SocketAddr,
    path::PathBuf,
    process::Stdio,
    time::{Duration, Instant},
};

use bacnet_rs::{
    client::{AsyncBacnetClient, BacnetTarget, ClientConfig},
    object::{ObjectIdentifier, ObjectType, PropertyIdentifier},
    property::PropertyValue,
    service::{PropertyReference, ReadAccessSpecification, ReadPropertyMultipleRequest},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
};

/// An interpreter that can import bacpypes3, or `None`.
fn interop_python() -> Option<PathBuf> {
    let candidates = std::env::var("BACNET_INTEROP_PYTHON")
        .ok()
        .map(|path| vec![PathBuf::from(path)])
        .unwrap_or_else(|| vec![PathBuf::from("python3")]);
    candidates.into_iter().find(|python| {
        std::process::Command::new(python)
            .args(["-c", "import bacpypes3"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    })
}

/// The peer, killed when the test drops it.
struct Peer {
    child: Child,
    address: SocketAddr,
    /// Objects the peer reports, the device object included.
    objects: usize,
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Start the peer and wait until it says it is listening.
///
/// Waited for rather than slept past: a fixed sleep is either too short on a
/// loaded machine or wasted on an idle one, and the peer prints a line for
/// exactly this purpose.
async fn spawn_peer(python: &PathBuf, port: u16, objects: usize, max_apdu: u32) -> Peer {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("interop")
        .join("segpeer.py");
    let mut child = Command::new(python)
        .arg(script)
        .arg("--address")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--instance")
        .arg("4999")
        .arg("--objects")
        .arg(objects.to_string())
        .arg("--max-apdu")
        .arg(max_apdu.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("start the bacpypes3 peer");

    let stdout = child.stdout.take().expect("peer stdout");
    let mut lines = BufReader::new(stdout).lines();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut reported = None;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(30), lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                if let Some(count) = line.strip_prefix("ready objects=") {
                    reported = count.trim().parse::<usize>().ok();
                    break;
                }
            }
            Ok(Ok(None)) => panic!("peer exited before it was ready"),
            Ok(Err(error)) => panic!("reading peer output: {error}"),
            Err(_) => panic!("peer did not become ready within 30s"),
        }
    }
    let objects = reported.expect("peer never reported readiness");

    Peer {
        child,
        address: format!("127.0.0.1:{port}").parse().expect("peer address"),
        objects,
    }
}

async fn client() -> AsyncBacnetClient {
    AsyncBacnetClient::from_config(ClientConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        // Generous: a segmented transfer is a round trip per segment at a
        // granted window of one, and the peer is a Python process.
        timeout: Duration::from_secs(5),
        retries: 2,
    })
    .await
    .expect("bind the client")
}

/// Reading a device's Object_List when it runs past one APDU.
///
/// The case that pays for all of this. Without reassembly the whole-property
/// read fails and the caller falls back to reading the array a slice at a
/// time - hundreds of round trips on a large controller, repeated every time
/// the list is re-read.
#[tokio::test]
async fn a_segmented_response_is_reassembled() {
    let Some(python) = interop_python() else {
        eprintln!(
            "SKIPPED: no interpreter with bacpypes3. \
             Set BACNET_INTEROP_PYTHON or `pip install bacpypes3`."
        );
        return;
    };
    let peer = spawn_peer(&python, 47820, 400, 1476).await;
    let client = client().await;
    let target = BacnetTarget::new(peer.address);

    let values = client
        .read_property(
            target,
            ObjectIdentifier::new(ObjectType::Device, 4999),
            PropertyIdentifier::ObjectList,
        )
        .await
        .expect("read a segmented Object_List");

    assert_eq!(
        values.len(),
        peer.objects,
        "every object the peer serves should survive reassembly"
    );
    assert!(
        values
            .iter()
            .all(|value| matches!(value, PropertyValue::ObjectIdentifier(_))),
        "reassembled bytes should decode as object identifiers, not as rubble"
    );
}

/// A transfer long enough that getting the second segment right is not
/// enough.
///
/// Two thousand objects is an Object_List around ten kilobytes, so seven or
/// more segments at the APDU size this client accepts. That is where an
/// off-by-one in the sequence handling shows up - a two-segment transfer
/// passes with the comparison the wrong way round.
///
/// Note that the peer's `--max-apdu` is *not* what sets the segment size: the
/// segments a device sends are bounded by the `max-APDU-length-accepted` this
/// client states in its request, per clause 20.1.2.5. The peer's own figure
/// is its receive limit, which is what the segmented-request test below
/// exercises instead.
#[tokio::test]
async fn a_long_transfer_of_many_segments_is_reassembled() {
    let Some(python) = interop_python() else {
        eprintln!("SKIPPED: no interpreter with bacpypes3.");
        return;
    };
    let peer = spawn_peer(&python, 47821, 2000, 1476).await;
    let client = client().await;

    let values = client
        .read_property(
            BacnetTarget::new(peer.address),
            ObjectIdentifier::new(ObjectType::Device, 4999),
            PropertyIdentifier::ObjectList,
        )
        .await
        .expect("read Object_List across many segments");

    assert_eq!(values.len(), peer.objects);
}

/// A request too large for one APDU, which this client must send in pieces.
///
/// A ReadPropertyMultiple naming twelve hundred objects is the realistic
/// shape of this: the request runs to nine or ten segments, so the peer's
/// granted window actually governs how many go out between acknowledgements,
/// and the response is segmented too - one exchange drives both state
/// machines against each other.
#[tokio::test]
async fn a_segmented_request_is_accepted() {
    let Some(python) = interop_python() else {
        eprintln!("SKIPPED: no interpreter with bacpypes3.");
        return;
    };
    let peer = spawn_peer(&python, 47822, 1200, 1476).await;
    let client = client().await;

    let specifications: Vec<ReadAccessSpecification> = (0..1200)
        .map(|instance| ReadAccessSpecification {
            object_identifier: ObjectIdentifier::new(ObjectType::AnalogValue, instance),
            property_references: vec![PropertyReference {
                property_identifier: PropertyIdentifier::PresentValue,
                property_array_index: None,
            }],
        })
        .collect();
    let request = ReadPropertyMultipleRequest::new(specifications);

    let response = client
        .read_property_multiple(BacnetTarget::new(peer.address), &request)
        .await
        .expect("send a segmented request and read its segmented answer");

    assert_eq!(
        response.read_access_results.len(),
        1200,
        "every object asked about should come back"
    );
}
