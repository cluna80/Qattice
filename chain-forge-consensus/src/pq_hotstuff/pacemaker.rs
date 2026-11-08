//! Pacemaker timeout with exponential backoff (spec section 6 "round advance"; timeouts are caller-scheduled). The timeout for the
//! current round doubles with every consecutive local timeout that produced no progress, up to a cap, and returns to the base on
//! progress (a QC for the current round or later). All arithmetic is saturating or checked, so no sequence of calls can wrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacemakerConfig { pub base: u64, pub max: u64 }

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PacemakerError {
    #[error("the base timeout must be at least 1")]
    ZeroBase,
    #[error("the maximum timeout is below the base")]
    MaxBelowBase,
}

impl PacemakerConfig {
    pub fn validate(&self) -> Result<(), PacemakerError> {
        if self.base == 0 { return Err(PacemakerError::ZeroBase); }
        if self.max < self.base { return Err(PacemakerError::MaxBelowBase); }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Pacemaker { cfg: PacemakerConfig, consecutive: u32 }

impl Pacemaker {
    pub fn new(cfg: PacemakerConfig) -> Result<Self, PacemakerError> { cfg.validate()?; Ok(Pacemaker { cfg, consecutive: 0 }) }
    /// How long to wait in the current round before timing out.
    pub fn timeout(&self) -> u64 {
        let shift = self.consecutive.min(63);
        let scaled = self.cfg.base.checked_shl(shift).filter(|v| v >> shift == self.cfg.base).unwrap_or(u64::MAX);
        scaled.min(self.cfg.max)
    }
    /// The timer fired and a timeout was sent: back off.
    pub fn on_timeout(&mut self) { self.consecutive = self.consecutive.saturating_add(1); }
    /// A QC for the current round or later arrived (real progress): return to the base.
    pub fn on_progress(&mut self) { self.consecutive = 0; }
    pub fn consecutive_timeouts(&self) -> u32 { self.consecutive }
}
