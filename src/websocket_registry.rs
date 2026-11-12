//! Process-local socket/room routing state. This performs no authentication,
//! room ownership check, transport handling or live delivery; callers must
//! verify those separately and call `remove` when a socket disconnects.
use std::collections::{HashMap, HashSet};

/// Fixed-window control-event limit from the fixed TS implementation.
pub struct MinuteRateLimiter {
    limit: i64,
    started: i64,
    events: i64,
}
impl MinuteRateLimiter {
    pub fn new(limit: i64, now: i64) -> Self {
        Self {
            limit,
            started: now,
            events: 0,
        }
    }
    pub fn consume(&mut self, now: i64) -> bool {
        if self.limit == -1 {
            return true;
        }
        if i128::from(now) - i128::from(self.started) >= 60_000 {
            self.started = now;
            self.events = 0;
        }
        if self.events >= self.limit {
            return false;
        }
        self.events += 1;
        true
    }
}

#[derive(Default)]
pub struct WebSocketRegistry {
    sockets: Vec<String>,
    identities: HashMap<String, String>,
    rooms: HashMap<String, HashSet<String>>,
}
fn limited(size: usize, limit: i64) -> bool {
    limit != -1 && (size as i128) >= i128::from(limit)
}
impl WebSocketRegistry {
    pub fn register(&mut self, id: &str, maximum: i64) -> bool {
        if limited(self.sockets.len(), maximum) {
            return false;
        }
        if !self.sockets.iter().any(|item| item == id) {
            self.sockets.push(id.to_owned());
        }
        true
    }
    pub fn authenticate(&mut self, id: &str, identity: &str, maximum: i64) -> bool {
        if !self.sockets.iter().any(|item| item == id) {
            return false;
        }
        if let Some(current) = self.identities.get(id) {
            return current == identity;
        }
        if limited(
            self.identities
                .values()
                .filter(|item| item.as_str() == identity)
                .count(),
            maximum,
        ) {
            return false;
        }
        self.identities.insert(id.to_owned(), identity.to_owned());
        true
    }
    pub fn is_authenticated(&self, id: &str) -> bool {
        self.identities.contains_key(id)
    }
    pub fn identity(&self, id: &str) -> Option<&str> {
        self.identities.get(id).map(String::as_str)
    }
    pub fn join(&mut self, id: &str, room: &str, maximum: i64) -> bool {
        if !self.is_authenticated(id) {
            return false;
        }
        let existing = self.rooms.get(id);
        if existing.is_some_and(|rooms| rooms.contains(room)) {
            return true;
        }
        if limited(existing.map_or(0, HashSet::len), maximum) {
            return false;
        }
        self.rooms
            .entry(id.to_owned())
            .or_default()
            .insert(room.to_owned());
        true
    }
    pub fn leave(&mut self, id: &str, room: &str) {
        if let Some(rooms) = self.rooms.get_mut(id) {
            rooms.remove(room);
            if rooms.is_empty() {
                self.rooms.remove(id);
            }
        }
    }
    pub fn recipient_sockets(&self, identity: &str, room: &str, maximum: i64) -> Vec<&str> {
        let matching: Vec<&str> = self
            .sockets
            .iter()
            .filter(|id| {
                self.identity(id) == Some(identity)
                    && self.rooms.get(*id).is_some_and(|r| r.contains(room))
            })
            .map(String::as_str)
            .collect();
        let start = if maximum == -1 || maximum == 0 {
            0
        } else if maximum > 0 {
            matching
                .len()
                .saturating_sub(usize::try_from(maximum).unwrap_or(usize::MAX))
        } else {
            usize::try_from(maximum.unsigned_abs())
                .unwrap_or(usize::MAX)
                .min(matching.len())
        };
        matching[start..].to_vec()
    }
    pub fn sockets(&self) -> Vec<&str> {
        self.sockets.iter().map(String::as_str).collect()
    }
    pub fn connection_count(&self) -> usize {
        self.sockets.len()
    }
    pub fn room_count(&self, id: &str) -> usize {
        self.rooms.get(id).map_or(0, HashSet::len)
    }
    pub fn remove(&mut self, id: &str) {
        self.identities.remove(id);
        self.rooms.remove(id);
        self.sockets.retain(|item| item != id);
    }
    pub fn clear(&mut self) {
        self.sockets.clear();
        self.identities.clear();
        self.rooms.clear();
    }
}
