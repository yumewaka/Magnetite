//! TTL response cache for forwarded queries (E1c). Keyed by (qname, qtype);
//! entries expire at the response's minimum TTL. Bounded in size with
//! expiry-first eviction (mirrors the source dns-server cache).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 4096;

struct Entry {
    response: Vec<u8>,
    expires_at: Instant,
}

/// A cheaply-cloneable shared cache handle.
#[derive(Clone, Default)]
pub struct DnsCache {
    entries: Arc<Mutex<HashMap<String, Entry>>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cache key for a question.
    pub fn key(qname: &str, qtype: &str) -> String {
        format!(
            "{}|{qtype}",
            qname.trim_end_matches('.').to_ascii_lowercase()
        )
    }

    /// Fetch a non-expired cached response.
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let mut entries = self.entries.lock().ok()?;
        match entries.get(key) {
            Some(entry) if entry.expires_at > Instant::now() => Some(entry.response.clone()),
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    /// Store a response for `ttl`. A zero TTL is not cached.
    pub fn put(&self, key: String, response: Vec<u8>, ttl: Duration) {
        if ttl.is_zero() {
            return;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.len() >= MAX_ENTRIES {
            let now = Instant::now();
            entries.retain(|_, e| e.expires_at > now);
        }
        if entries.len() >= MAX_ENTRIES {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, e)| e.expires_at)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            key,
            Entry {
                response,
                expires_at: Instant::now() + ttl,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_and_expires() {
        let cache = DnsCache::new();
        let key = DnsCache::key("example.com.", "A");
        cache.put(key.clone(), vec![1, 2, 3], Duration::from_secs(60));
        assert_eq!(cache.get(&key), Some(vec![1, 2, 3]));

        // A zero TTL is never stored.
        let k2 = DnsCache::key("zero.com", "A");
        cache.put(k2.clone(), vec![9], Duration::ZERO);
        assert_eq!(cache.get(&k2), None);

        // Already-expired entry is treated as a miss.
        let k3 = DnsCache::key("past.com", "A");
        cache.put(k3.clone(), vec![7], Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.get(&k3), None);
    }
}
