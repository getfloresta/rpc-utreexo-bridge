// SPDX-License-Identifier: MIT

//! Wall time and thread-local major faults for steady-state position lookup phases.

use std::time::Duration;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct PositionTiming {
    pub(crate) elapsed: Duration,
    // None means the OS counter was unavailable, not that no faults occurred.
    pub(crate) major_faults: Option<u64>,
}

pub(crate) struct PositionTimer {
    started: Instant,
    major_faults: Option<u64>,
}

impl PositionTimer {
    pub(crate) fn start() -> Self {
        let major_faults = thread_major_faults();
        Self {
            started: Instant::now(),
            major_faults,
        }
    }

    pub(crate) fn finish(self) -> PositionTiming {
        let elapsed = self.started.elapsed();
        let major_faults = self
            .major_faults
            .zip(thread_major_faults())
            .and_then(|(before, after)| after.checked_sub(before));
        PositionTiming {
            elapsed,
            major_faults,
        }
    }
}

fn thread_major_faults() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // RUSAGE_THREAD excludes the journal worker and other threads. Only inspect
        // the output after getrusage has successfully initialized it.
        if unsafe { libc::getrusage(libc::RUSAGE_THREAD, usage.as_mut_ptr()) } != 0 {
            return None;
        }
        u64::try_from(unsafe { usage.assume_init() }.ru_majflt).ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
