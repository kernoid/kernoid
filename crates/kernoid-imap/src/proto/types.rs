/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What the parser took from Stalwart's internal crates: an object id (RFC 8474) – kernoid's ids are UUIDs, kept as
//! text – and a slice of bytes that may be split in two (from `utils::chained_bytes`).

use std::{fmt::Display, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id(String);

impl FromStr for Id {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, ()> {
        if !value.is_empty()
            && value.len() <= 255
            && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            Ok(Self(value.to_owned()))
        } else {
            Err(())
        }
    }
}

impl From<u32> for Id {
    fn from(value: u32) -> Self {
        Self(value.to_string())
    }
}

impl Id {
    pub fn from_parts(prefix: u32, id: u32) -> Self {
        Self(format!("{prefix}{id}"))
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceRange<'x> {
    Single(&'x [u8]),
    Split(&'x [u8], &'x [u8]),
    None,
}

impl<'x> SliceRange<'x> {
    pub fn len(&self) -> usize {
        match self {
            SliceRange::Single(bytes) => bytes.len(),
            SliceRange::Split(first, last) => first.len() + last.len(),
            SliceRange::None => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn into_pairs(self) -> (&'x [u8], &'x [u8]) {
        match self {
            SliceRange::Single(bytes) => (bytes, &[][..]),
            SliceRange::Split(first, last) => (first, last),
            SliceRange::None => (&[][..], &[][..]),
        }
    }
}

impl<'x> IntoIterator for SliceRange<'x> {
    type Item = &'x u8;
    type IntoIter = std::iter::Chain<std::slice::Iter<'x, u8>, std::slice::Iter<'x, u8>>;

    fn into_iter(self) -> Self::IntoIter {
        let (first, last) = self.into_pairs();
        first.iter().chain(last.iter())
    }
}
