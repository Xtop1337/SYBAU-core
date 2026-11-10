//! Response cache keyed by upstream, name and type.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::message::Message;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    upstream: String,
    name: String,
    qtype: u16,
}

struct Entry {
    message: Message,
    stored: Instant,
    expires: Instant,
}

pub struct Cache {
    entries: Mutex<HashMap<Key, Entry>>,
    max_entries: usize,
    min_ttl: u32,
    max_ttl: u32,
}

impl Cache {
    pub fn new(max_entries: usize, min_ttl: u32, max_ttl: u32) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries: max_entries.max(1),
            min_ttl,
            max_ttl: max_ttl.max(min_ttl),
        }
    }

    /// A cached answer with TTLs reduced by the time spent in the cache.
    pub fn get(&self, upstream: &str, name: &str, qtype: u16) -> Option<Message> {
        let key = Key {
            upstream: upstream.into(),
            name: name.into(),
            qtype,
        };
        let mut entries = self.entries.lock();
        let entry = entries.get(&key)?;
        let now = Instant::now();
        if now >= entry.expires {
            entries.remove(&key);
            return None;
        }
        let elapsed = now.duration_since(entry.stored).as_secs() as u32;
        let mut message = entry.message.clone();
        for r in message.answers.iter_mut().chain(&mut message.authority) {
            r.ttl = r.ttl.saturating_sub(elapsed).max(1);
        }
        Some(message)
    }

    /// Stores a successful or negative (NXDOMAIN, NODATA) answer.
    pub fn put(&self, upstream: &str, name: &str, qtype: u16, message: &Message) {
        let ttl = message
            .min_ttl()
            .unwrap_or(self.min_ttl)
            .clamp(self.min_ttl, self.max_ttl);
        if ttl == 0 {
            return;
        }
        let now = Instant::now();
        let mut entries = self.entries.lock();
        if entries.len() >= self.max_entries {
            entries.retain(|_, e| e.expires > now);
            if entries.len() >= self.max_entries {
                // Still full: drop the entry closest to expiry.
                if let Some(k) = entries
                    .iter()
                    .min_by_key(|(_, e)| e.expires)
                    .map(|(k, _)| k.clone())
                {
                    entries.remove(&k);
                }
            }
        }
        let mut stored = message.clone();
        for r in stored.answers.iter_mut().chain(&mut stored.authority) {
            r.ttl = r.ttl.clamp(self.min_ttl.max(1), self.max_ttl.max(1));
        }
        entries.insert(
            Key {
                upstream: upstream.into(),
                name: name.into(),
                qtype,
            },
            Entry {
                message: stored,
                stored: now,
                expires: now + Duration::from_secs(ttl as u64),
            },
        );
    }

    pub fn clear(&self) -> usize {
        let mut entries = self.entries.lock();
        let n = entries.len();
        entries.clear();
        n
    }

    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Record, RecordData, CLASS_IN, TYPE_A};

    fn answer(ttl: u32) -> Message {
        let mut m = Message::query(1, "a.test", TYPE_A).reply(0);
        m.answers.push(Record {
            name: "a.test".into(),
            rtype: TYPE_A,
            class: CLASS_IN,
            ttl,
            data: RecordData::A([1, 2, 3, 4].into()),
        });
        m
    }

    #[test]
    fn ttl_clamping_expiry_and_eviction() {
        let cache = Cache::new(2, 10, 100);
        cache.put("u", "a.test", TYPE_A, &answer(1));
        let got = cache.get("u", "a.test", TYPE_A).unwrap();
        assert_eq!(got.answers[0].ttl, 10, "raised to min_ttl");
        assert!(
            cache.get("other", "a.test", TYPE_A).is_none(),
            "per upstream"
        );
        cache.put("u", "b.test", TYPE_A, &answer(100_000));
        assert_eq!(
            cache.get("u", "b.test", TYPE_A).unwrap().answers[0].ttl,
            100
        );
        cache.put("u", "c.test", TYPE_A, &answer(50));
        assert_eq!(cache.len(), 2, "evicted to stay within max_entries");
        assert!(
            cache.get("u", "a.test", TYPE_A).is_none(),
            "the entry closest to expiry went first"
        );
        assert_eq!(cache.clear(), 2);
    }
}
