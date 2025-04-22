#![allow(unused_crate_dependencies)] // mixed lib/bin crate

use {
    std::{
        collections::HashSet,
        fmt,
    },
    async_proto::Protocol,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Protocol)]
pub struct RaceId(u64);

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
    RaceTime(String),
}

impl OpenRoom {
    fn to_string(&self, racetime_host: &'static str) -> String {
        match self {
            Self::Discord(race_id, kind) => format!("Discord race handler for {}race {race_id}", match kind {
                EventKind::Normal => "",
                EventKind::Async1 => "async 1 of ",
                EventKind::Async2 => "async 2 of ",
                EventKind::Async3 => "async 3 of ",
            }),
            Self::RaceTime(room_url) => format!("https://{racetime_host}{room_url}"),
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
