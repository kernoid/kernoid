/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What the protocol code needs of Stalwart's `crates/types` (v0.16.27): a time range of CalDAV queries and dead
//! properties – properties a client sets that the server does not know. Taken over without the archived (rkyv)
//! forms; dead properties are serialised with serde instead, so that kernoid can keep them as JSON.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: i64,
    pub end: i64,
}

impl TimeRange {
    pub fn new(start: i64, end: i64) -> Self {
        Self { start, end }
    }

    pub fn is_in_range(&self, match_overlap: bool, start: i64, end: i64) -> bool {
        if !match_overlap {
            // RFC4791#9.9: (start <  DTEND AND end > DTSTART)
            self.start < end && self.end > start
        } else {
            // RFC4791#9.9: ((start <  DUE) OR (start <= DTSTART)) AND ((end > DTSTART) OR (end >= DUE))
            ((start < self.end) || (start <= self.start)) && (end > self.start || end >= self.end)
        }
    }
}

impl Default for TimeRange {
    fn default() -> Self {
        Self { start: i64::MIN, end: i64::MAX }
    }
}

pub mod dead_property {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "type", content = "data")]
    pub enum DeadPropertyTag {
        ElementStart(DeadElementTag),
        ElementEnd,
        Text(String),
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DeadElementTag {
        pub name: String,
        pub attrs: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct DeadProperty(pub Vec<DeadPropertyTag>);

    impl DeadProperty {
        pub fn find_tag(&self, needle: &str) -> Option<DeadProperty> {
            let mut depth: u32 = 0;
            let mut tags = Vec::new();
            let mut found_tag = false;

            for tag in self.0.iter() {
                match tag {
                    DeadPropertyTag::ElementStart(start) => {
                        if depth == 0 && start.name == needle {
                            found_tag = true;
                        } else if found_tag {
                            tags.push(tag.clone());
                        }

                        depth += 1;
                    }
                    DeadPropertyTag::ElementEnd => {
                        if found_tag {
                            if depth == 1 {
                                break;
                            } else {
                                tags.push(tag.clone());
                            }
                        }
                        depth = depth.saturating_sub(1);
                    }
                    DeadPropertyTag::Text(_) => {
                        if found_tag {
                            tags.push(tag.clone());
                        }
                    }
                }
            }

            if found_tag { Some(DeadProperty(tags)) } else { None }
        }

        pub fn remove_element(&mut self, element: &DeadElementTag) {
            let mut depth = 0;
            let mut remove = false;
            self.0.retain(|item| match item {
                DeadPropertyTag::ElementStart(tag) => {
                    if depth == 0 && !remove && tag.name == element.name {
                        remove = true;
                    }
                    depth += 1;

                    !remove
                }
                DeadPropertyTag::ElementEnd => {
                    depth -= 1;
                    if remove && depth == 0 {
                        remove = false;
                        false
                    } else {
                        !remove
                    }
                }
                _ => !remove,
            });
        }

        pub fn add_element(&mut self, element: DeadElementTag, values: Vec<DeadPropertyTag>) {
            self.0.push(DeadPropertyTag::ElementStart(element));
            self.0.extend(values);
            self.0.push(DeadPropertyTag::ElementEnd);
        }

        pub fn size(&self) -> usize {
            let mut size = 0;
            for item in &self.0 {
                match item {
                    DeadPropertyTag::ElementStart(tag) => {
                        size += tag.size();
                    }
                    DeadPropertyTag::ElementEnd => {
                        size += 1;
                    }
                    DeadPropertyTag::Text(text) => {
                        size += text.len();
                    }
                }
            }
            size
        }
    }

    impl DeadElementTag {
        pub fn new(name: String, attrs: Option<String>) -> Self {
            DeadElementTag { name, attrs }
        }

        pub fn size(&self) -> usize {
            self.name.len() + self.attrs.as_ref().map_or(0, |attrs| attrs.len())
        }
    }

    impl Default for DeadProperty {
        fn default() -> Self {
            DeadProperty(Vec::with_capacity(4))
        }
    }
}
