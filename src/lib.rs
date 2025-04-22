#![allow(unused_crate_dependencies)] // mixed lib/bin crate TODO split into separate crates to get rid of unused dependencies in dependents of this lib

use {
    std::{
        collections::HashSet,
        fmt,
    },
    async_proto::Protocol,
    url::Url,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Protocol)]
pub struct RaceId(pub u64);

impl fmt::Display for RaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Protocol)]
pub enum EventKind {
    Normal,
    Async1,
    Async2,
    Async3,
}

#[derive(Clone, PartialEq, Eq, Hash, Protocol)]
pub enum OpenRoom {
    Discord(RaceId, EventKind),
    RaceTime {
        room_url: String,
        public: bool,
    },
}

impl OpenRoom {
    pub fn is_public(&self) -> bool {
        match self {
            Self::Discord(..) => false,
            Self::RaceTime { public, .. } => *public,
        }
    }

    pub fn public_url(&self, racetime_host: &'static str) -> Option<Url> {
        match self {
            Self::Discord(..) => None,
            Self::RaceTime { room_url, public } => if *public {
                Some(format!("https://{racetime_host}{room_url}").parse().unwrap())
            } else {
                None
            },
        }
    }

    pub fn to_string(&self, racetime_host: &'static str) -> String {
        match self {
            Self::Discord(race_id, kind) => format!("Discord race handler for {}race {race_id}", match kind {
                EventKind::Normal => "",
                EventKind::Async1 => "async 1 of ",
                EventKind::Async2 => "async 2 of ",
                EventKind::Async3 => "async 3 of ",
            }),
            Self::RaceTime { room_url, public: _ } => format!("https://{racetime_host}{room_url}"),
        }
    }
}

#[derive(Protocol)]
pub enum PrepareStopUpdate {
    AcquiringMutex,
    WaitingForRooms(HashSet<OpenRoom>),
    RoomOpened(OpenRoom),
    RoomClosed(OpenRoom),
}

impl fmt::Display for PrepareStopUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AcquiringMutex => write!(f, "acquiring clean shutdown mutex"),
            Self::WaitingForRooms(rooms) => {
                write!(f, "waiting for {} rooms to close:", rooms.len())?;
                for room in rooms {
                    write!(f, "\n{}", room.to_string("racetime.gg"))?;
                }
                Ok(())
            }
            Self::RoomOpened(room) => write!(f, "new room opened: {}", room.to_string("racetime.gg")),
            Self::RoomClosed(room) => write!(f, "room closed: {}", room.to_string("racetime.gg")),
        }
    }
}
