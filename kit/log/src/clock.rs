// SPDX-License-Identifier: MIT
//! Hybrid logical clocks: an order of events across devices that respects causality and stays close to real time.

use std::{fmt, str::FromStr};

use kernoid_base::{ParseError, as_text};
use serde::{Deserialize, Serialize};

/// The name of a device that writes events, unique within a space: 1–64 characters of `a-z`, `0-9`, `-`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(String);

impl DeviceId {
    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for DeviceId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let valid =
            (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if valid { Ok(DeviceId(s.to_owned())) } else { Err(ParseError::new("device name", s)) }
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

as_text!(DeviceId);

/// A timestamp of a hybrid logical clock.
///
/// Ordered by wall time, then counter, then device – a total order on which every device agrees. The wall time is
/// in milliseconds since 1970-01-01 UTC; the counter orders events within the same millisecond and lets the clock
/// move on when a device's own clock is behind a time it has seen.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hlc {
    /// Milliseconds since 1970-01-01 UTC.
    #[serde(deserialize_with = "kernoid_base::safe_u64")]
    pub wall_ms: u64,
    /// Order within the same millisecond.
    pub counter: u32,
    /// The device that made the timestamp.
    pub device: DeviceId,
}

/// The hybrid logical clock of one device.
#[derive(Debug, Clone)]
pub struct Clock {
    device: DeviceId,
    wall_ms: u64,
    counter: u32,
}

impl Clock {
    /// A clock for a device that has not made or seen any timestamp yet.
    pub fn new(device: DeviceId) -> Self {
        Clock { device, wall_ms: 0, counter: 0 }
    }

    /// The device the clock belongs to.
    pub fn device(&self) -> &DeviceId {
        &self.device
    }

    /// A timestamp for a new local event, given the device's physical time in milliseconds.
    pub fn now(&mut self, physical_ms: u64) -> Hlc {
        if physical_ms > self.wall_ms {
            self.wall_ms = physical_ms;
            self.counter = 0;
        } else {
            self.counter += 1;
        }
        Hlc { wall_ms: self.wall_ms, counter: self.counter, device: self.device.clone() }
    }

    /// Takes note of a timestamp received from another device, so that every later local timestamp is after it.
    pub fn observe(&mut self, seen: &Hlc, physical_ms: u64) {
        let wall_ms = self.wall_ms.max(seen.wall_ms).max(physical_ms);
        self.counter = match (wall_ms == self.wall_ms, wall_ms == seen.wall_ms) {
            (true, true) => self.counter.max(seen.counter),
            (true, false) => self.counter,
            (false, true) => seen.counter,
            (false, false) => 0,
        };
        self.wall_ms = wall_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(name: &str) -> DeviceId {
        name.parse().unwrap()
    }

    #[test]
    fn device_names() {
        assert!("laptop-2".parse::<DeviceId>().is_ok());
        for s in ["", "Laptop", "my laptop", &"x".repeat(65)] {
            assert!(s.parse::<DeviceId>().is_err(), "{s:?}");
        }
    }

    #[test]
    fn local_timestamps_always_increase() {
        let mut clock = Clock::new(device("a"));
        let first = clock.now(1000);
        let same_ms = clock.now(1000);
        let clock_went_back = clock.now(500);
        assert!(first < same_ms && same_ms < clock_went_back);
        assert_eq!(clock_went_back.wall_ms, 1000);
    }

    #[test]
    fn after_observing_a_later_timestamp_the_next_one_is_later_still() {
        let mut ahead = Clock::new(device("ahead"));
        let mut behind = Clock::new(device("behind"));
        let remote = ahead.now(5000);
        behind.observe(&remote, 1000);
        let local = behind.now(1000);
        assert!(local > remote);
        assert_eq!(local.wall_ms, 5000);
    }

    #[test]
    fn ties_are_broken_by_device() {
        let a = Clock::new(device("a")).now(1000);
        let b = Clock::new(device("b")).now(1000);
        assert!(a < b);
    }
}
