//! Payload key discovery. The service payloads (`request`, `response`,
//! `resources`) are stored as JSON because their shape differs per service;
//! rules address them by path (`request.bucketName`). Nothing has to be
//! declared for that to work, but the analyst has to know which paths the
//! data holds. The parser counts every leaf path it stores, per log type,
//! and the rule editor offers them (docs/04 "페이로드 키").

use std::collections::HashMap;

use serde_json::Value;

use crate::model::NormalizedEvent;

/// Counts leaf paths under the payload columns of the events it is shown.
/// Paths are spelled as a rule spells them: `column.key.0.key`.
#[derive(Default)]
pub struct KeyCounter {
    counts: HashMap<String, u64>,
    /// Reused across events; a path is only allocated the first time it is
    /// seen, so steady state does not allocate per key per event.
    path: String,
}

impl KeyCounter {
    /// Distinct paths kept per counter. Beyond this a schema is data (keys
    /// that are ids, say); known paths keep counting, new ones are dropped.
    pub const MAX_PATHS: usize = 5_000;
    /// Segments below the column. Deeper than this is not something an
    /// analyst types into a rule.
    const MAX_DEPTH: usize = 6;
    /// Array elements indexed per list. `resources` is a short list; beyond
    /// a few elements the elements are data, not shape.
    const MAX_INDEX: usize = 4;

    /// Records the paths of one stored event. The payload columns are
    /// parsed here from their stored text; that is one small JSON parse per
    /// column per event, on the worker thread, next to the append.
    pub fn record_event(&mut self, event: &NormalizedEvent) {
        for (column, text) in [
            ("request", &event.request),
            ("response", &event.response),
            ("resources", &event.resources),
        ] {
            if let Some(value) = text.as_deref().and_then(|t| serde_json::from_str(t).ok()) {
                self.record(column, &value);
            }
        }
    }

    /// Records the leaf paths of one payload value under `column`.
    pub fn record(&mut self, column: &str, value: &Value) {
        self.path.clear();
        self.path.push_str(column);
        self.walk(value, 0);
    }

    fn walk(&mut self, value: &Value, depth: usize) {
        match value {
            Value::Object(map) => {
                if depth == Self::MAX_DEPTH {
                    return;
                }
                for (key, child) in map {
                    let len = self.path.len();
                    self.path.push('.');
                    self.path.push_str(key);
                    self.walk(child, depth + 1);
                    self.path.truncate(len);
                }
            }
            Value::Array(items) => {
                if depth == Self::MAX_DEPTH {
                    return;
                }
                for (index, child) in items.iter().enumerate().take(Self::MAX_INDEX + 1) {
                    let len = self.path.len();
                    self.path.push('.');
                    self.path.push_str(&index.to_string());
                    self.walk(child, depth + 1);
                    self.path.truncate(len);
                }
            }
            // A null names nothing the event has; rules treat it as absent.
            Value::Null => {}
            _ => {
                // The column itself is not a leaf path.
                if depth == 0 {
                    return;
                }
                if let Some(count) = self.counts.get_mut(self.path.as_str()) {
                    *count += 1;
                } else if self.counts.len() < Self::MAX_PATHS {
                    self.counts.insert(self.path.clone(), 1);
                }
            }
        }
    }

    /// Folds another counter in, summing shared paths. The size bound holds
    /// for the union.
    pub fn merge(&mut self, other: KeyCounter) {
        for (path, n) in other.counts {
            if let Some(count) = self.counts.get_mut(&path) {
                *count += n;
            } else if self.counts.len() < Self::MAX_PATHS {
                self.counts.insert(path, n);
            }
        }
    }

    pub fn counts(&self) -> impl Iterator<Item = (&str, u64)> {
        self.counts.iter().map(|(path, n)| (path.as_str(), *n))
    }

    pub fn len(&self) -> usize {
        self.counts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}
