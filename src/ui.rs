use std::process;

pub struct ProcessSlot {
    pub child: process::Child,
    pub paused: bool,
}
