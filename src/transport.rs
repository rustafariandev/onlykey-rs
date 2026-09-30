//! Moving 64-byte reports to and from the device.
//!
//! [`HidTransport`] is the seam between the protocol logic and the USB stack:
//! [`HidapiTransport`] talks to real hardware, [`fake::ScriptedTransport`]
//! replays a scripted exchange in tests.

use crate::protocol::{REPORT_SIZE, Report};
use hidapi::{DeviceInfo, HidApi, HidDevice, HidError};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use thiserror::Error;

/// USB vendor/product pairs an OnlyKey may present.
pub const USB_IDS: [(u16, u16); 2] = [(0x1D50, 0x60FC), (0x16C0, 0x0486)];
/// Serial string of the original OnlyKey (the DUO reports a different one).
pub const ORIGINAL_SERIAL: &str = "1000000000";
/// Vendor HID usage page of the OnlyKey command interface.
pub const COMMAND_USAGE_PAGE: u16 = 0xFFAB;
/// USB interface number of the command interface on the original OnlyKey,
/// used when the usage page is not reported.
pub const COMMAND_INTERFACE: i32 = 2;
/// HID usage page of the FIDO/U2F authenticator interface (CTAPHID).
pub const FIDO_USAGE_PAGE: u16 = 0xF1D0;
/// HID usage of the FIDO/U2F authenticator interface.
pub const FIDO_USAGE: u16 = 0x01;

#[cfg(target_os = "linux")]
const PERMISSION_HINT: &str =
    "install the OnlyKey udev rule (49-onlykey.rules) and replug the device";
#[cfg(not(target_os = "linux"))]
const PERMISSION_HINT: &str = "check that no other program has the OnlyKey open";

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("no OnlyKey found; is it plugged in?")]
    NotFound,
    #[error("no FIDO security key found; is one plugged in?")]
    NoDevice,
    #[error("permission denied opening {path}; {PERMISSION_HINT}")]
    PermissionDenied { path: String },
    #[error("USB HID error: {0}")]
    Hid(#[from] HidError),
    #[error("short write: {0} of {REPORT_SIZE} bytes")]
    ShortWrite(usize),
}

impl TransportError {
    /// Whether waiting and trying again could help.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            TransportError::NotFound | TransportError::NoDevice | TransportError::Hid(_)
        )
    }
}

/// A channel carrying whole HID reports.
pub trait HidTransport: Send {
    /// Send one report; must write all 64 bytes.
    fn write_report(&mut self, report: &Report) -> Result<(), TransportError>;
    /// Wait up to `timeout` for one report. `None` on timeout or on a report
    /// that is not exactly 64 bytes.
    fn read_report(&mut self, timeout: Duration) -> Result<Option<Report>, TransportError>;
}

impl HidTransport for Box<dyn HidTransport> {
    fn write_report(&mut self, report: &Report) -> Result<(), TransportError> {
        (**self).write_report(report)
    }

    fn read_report(&mut self, timeout: Duration) -> Result<Option<Report>, TransportError> {
        (**self).read_report(timeout)
    }
}

fn hid_api() -> &'static Mutex<HidApi> {
    static API: OnceLock<Mutex<HidApi>> = OnceLock::new();
    API.get_or_init(|| Mutex::new(HidApi::new().expect("hidapi initialises")))
}

/// Whether an enumerated HID interface is an original OnlyKey's command channel.
fn is_command_interface(info: &DeviceInfo) -> bool {
    USB_IDS.contains(&(info.vendor_id(), info.product_id()))
        && info.serial_number() == Some(ORIGINAL_SERIAL)
        && (info.usage_page() == COMMAND_USAGE_PAGE || info.interface_number() == COMMAND_INTERFACE)
}

/// A real OnlyKey reached through hidapi.
pub struct HidapiTransport {
    device: HidDevice,
    path: String,
}

impl HidapiTransport {
    /// Enumerate and open the attached OnlyKey's command interface.
    pub fn open() -> Result<Self, TransportError> {
        Self::open_with("OnlyKey", is_command_interface, TransportError::NotFound)
    }

    /// Enumerate and open the attached FIDO security key's CTAPHID interface.
    ///
    /// `device` is an optional path substring, for hosts with more than one
    /// authenticator; without it the first (sorted) match is used.
    pub fn open_fido(device: Option<&str>) -> Result<Self, TransportError> {
        let device = device.map(str::to_owned);
        let filter = move |info: &DeviceInfo| {
            info.usage_page() == FIDO_USAGE_PAGE
                && info.usage() == FIDO_USAGE
                && device
                    .as_deref()
                    .map(|wanted| info.path().to_string_lossy().contains(wanted))
                    .unwrap_or(true)
        };
        Self::open_with("FIDO security key", filter, TransportError::NoDevice)
    }

    /// Open the first enumerated interface matching `filter`.
    fn open_with(
        label: &str,
        filter: impl Fn(&DeviceInfo) -> bool,
        missing: TransportError,
    ) -> Result<Self, TransportError> {
        let mut api = hid_api().lock().unwrap_or_else(|p| p.into_inner());
        api.refresh_devices()?;
        let mut candidates: Vec<&DeviceInfo> = api.device_list().filter(|d| filter(d)).collect();
        candidates.sort_by_key(|d| d.path().to_bytes().to_vec());
        // macOS lists a device once per top-level usage, all with one path.
        candidates.dedup_by_key(|d| d.path().to_bytes().to_vec());
        let Some(info) = candidates.first() else {
            return Err(missing);
        };
        let path = info.path().to_string_lossy().into_owned();
        if candidates.len() > 1 {
            tracing::warn!(count = candidates.len(), chosen = %path, "several {label} interfaces matched");
        }
        let device = match info.open_device(&api) {
            Ok(device) => device,
            Err(HidError::IoError { error })
                if error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return Err(TransportError::PermissionDenied { path });
            }
            Err(e) => return Err(e.into()),
        };
        device.set_blocking_mode(true)?;
        tracing::debug!(%path, "opened {label}");
        Ok(HidapiTransport { device, path })
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

impl HidTransport for HidapiTransport {
    fn write_report(&mut self, report: &Report) -> Result<(), TransportError> {
        let written = self.device.write(report)?;
        if written != REPORT_SIZE {
            return Err(TransportError::ShortWrite(written));
        }
        Ok(())
    }

    fn read_report(&mut self, timeout: Duration) -> Result<Option<Report>, TransportError> {
        let mut buf = [0u8; REPORT_SIZE];
        let millis = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
        let n = self.device.read_timeout(&mut buf, millis)?;
        if n == REPORT_SIZE {
            Ok(Some(buf))
        } else {
            if n != 0 {
                tracing::trace!(len = n, "ignoring short report");
            }
            Ok(None)
        }
    }
}

/// Test doubles.
pub mod fake {
    use super::*;
    use std::collections::VecDeque;

    /// One step of a scripted exchange.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Step {
        /// The next write must be exactly this report.
        ExpectWrite(Report),
        /// The next read returns this report.
        Reply(Report),
        /// The next read returns nothing.
        Timeout,
    }

    /// Replays a script and panics on any deviation from it.
    ///
    /// Reads while a write is pending return `None`, so a device loop that
    /// polls before sending simply sees silence. Once the script is exhausted
    /// every read returns `None`.
    #[derive(Debug)]
    pub struct ScriptedTransport {
        steps: VecDeque<Step>,
        writes: Vec<Report>,
    }

    impl ScriptedTransport {
        pub fn new(steps: Vec<Step>) -> Self {
            ScriptedTransport {
                steps: steps.into(),
                writes: Vec::new(),
            }
        }

        /// Every report written so far.
        pub fn writes(&self) -> &[Report] {
            &self.writes
        }

        /// Panic unless the whole script was consumed.
        pub fn assert_done(&self) {
            assert!(
                self.steps.is_empty(),
                "unconsumed script steps: {:?}",
                self.steps
            );
        }
    }

    impl HidTransport for ScriptedTransport {
        fn write_report(&mut self, report: &Report) -> Result<(), TransportError> {
            self.writes.push(*report);
            match self.steps.pop_front() {
                Some(Step::ExpectWrite(expected)) => {
                    assert_eq!(
                        hex::encode(report),
                        hex::encode(expected),
                        "unexpected report written"
                    );
                    Ok(())
                }
                other => panic!(
                    "unexpected write {}; next step was {other:?}",
                    hex::encode(report)
                ),
            }
        }

        fn read_report(&mut self, _timeout: Duration) -> Result<Option<Report>, TransportError> {
            match self.steps.front() {
                Some(Step::Reply(_)) => {
                    let Some(Step::Reply(report)) = self.steps.pop_front() else {
                        unreachable!()
                    };
                    Ok(Some(report))
                }
                Some(Step::Timeout) => {
                    self.steps.pop_front();
                    Ok(None)
                }
                Some(Step::ExpectWrite(_)) | None => Ok(None),
            }
        }
    }
}
