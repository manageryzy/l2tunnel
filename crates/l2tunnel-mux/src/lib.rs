//! Bounded FIFO-per-channel admission with round-robin service.
//! Frame classification and negotiated connection mapping remain planned.
use std::collections::VecDeque;

/// Admission failure returns ownership of the rejected frame.
#[derive(Debug, Eq, PartialEq)]
pub enum AdmissionError {
    /// Channel outside the configured pool.
    Channel(Vec<u8>),
    /// Shared byte/count budget exhausted or empty frame.
    Budget(Vec<u8>),
}

/// One direction's shared queue for all user frames, including measurements.
pub struct Mux {
    lanes: Vec<VecDeque<Box<[u8]>>>,
    byte_limit: usize,
    queued_bytes: usize,
    next: usize,
    frame_limit: usize,
    queued_frames: usize,
}

impl Mux {
    /// Construct a common channel pool with shared payload-byte and frame-count bounds.
    pub fn new(channels: u16, byte_limit: usize, frame_limit: usize) -> Result<Self, &'static str> {
        if !(1..=256).contains(&channels) || byte_limit == 0 || frame_limit == 0 {
            return Err("invalid queue limits");
        }
        Ok(Self {
            lanes: vec![VecDeque::new(); usize::from(channels)],
            byte_limit,
            queued_bytes: 0,
            next: 0,
            frame_limit,
            queued_frames: 0,
        })
    }
    /// Admit an opaque frame using the same policy for every traffic class.
    pub fn push(&mut self, channel: u16, frame: Vec<u8>) -> Result<(), AdmissionError> {
        let Some(lane) = self.lanes.get_mut(usize::from(channel)) else {
            return Err(AdmissionError::Channel(frame));
        };
        if frame.is_empty()
            || self.queued_frames >= self.frame_limit
            || frame.len() > self.byte_limit - self.queued_bytes
        {
            return Err(AdmissionError::Budget(frame));
        }
        self.queued_bytes += frame.len();
        self.queued_frames += 1;
        lane.push_back(frame.into_boxed_slice());
        Ok(())
    }
    /// Release one frame when downstream capacity is available.
    pub fn pop(&mut self) -> Option<(u16, Vec<u8>)> {
        for _ in 0..self.lanes.len() {
            let index = self.next;
            self.next = (self.next + 1) % self.lanes.len();
            if let Some(frame) = self.lanes[index].pop_front() {
                self.queued_bytes -= frame.len();
                self.queued_frames -= 1;
                // Constructor bounds index to 0..256.
                return Some((index as u16, frame.into_vec()));
            }
        }
        None
    }
    /// Payload bytes retained in the shared queue.
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_fair_fifo_admission() -> Result<(), &'static str> {
        let mut mux = Mux::new(2, 6, 3)?;
        assert!(mux.push(0, vec![1, 1]).is_ok());
        assert!(mux.push(0, vec![2, 2]).is_ok());
        assert!(mux.push(1, vec![3, 3]).is_ok());
        assert_eq!(mux.push(1, vec![9]), Err(AdmissionError::Budget(vec![9])));
        assert_eq!(mux.push(2, vec![9]), Err(AdmissionError::Channel(vec![9])));
        assert_eq!(mux.pop(), Some((0, vec![1, 1])));
        assert_eq!(mux.pop(), Some((1, vec![3, 3])));
        assert_eq!(mux.pop(), Some((0, vec![2, 2])));
        assert_eq!(mux.pop(), None);
        assert_eq!(mux.queued_bytes(), 0);
        Ok(())
    }
    #[test]
    fn spare_capacity_and_small_frames_are_bounded() -> Result<(), &'static str> {
        let mut mux = Mux::new(1, 1024, 2)?;
        let mut reserved = Vec::with_capacity(1024 * 1024);
        reserved.push(7);
        assert!(mux.push(0, reserved).is_ok());
        assert!(mux.push(0, vec![8]).is_ok());
        assert_eq!(mux.push(0, vec![9]), Err(AdmissionError::Budget(vec![9])));
        let (_, first) = mux.pop().ok_or("missing frame")?;
        assert_eq!(first.len(), 1);
        assert_eq!(first.capacity(), 1);
        assert!(mux.push(0, vec![9]).is_ok());
        Ok(())
    }
}
