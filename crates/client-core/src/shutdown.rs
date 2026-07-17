//! Explicit cancellation and shutdown ordering state.

/// Shutdown coordinator phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownPhase {
    /// Normal packet processing is allowed.
    Running,
    /// New flows are cancelled and bounded buffers are being closed.
    Draining,
    /// Streams and packet tunnel are closed; kill switch may be handled by the orchestrator.
    Complete,
}

/// Monotonic, idempotent shutdown coordinator.
#[derive(Debug)]
pub struct ShutdownCoordinator {
    phase: ShutdownPhase,
    deadline_ms: Option<u64>,
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self {
            phase: ShutdownPhase::Running,
            deadline_ms: None,
        }
    }
}

impl ShutdownCoordinator {
    /// Returns the current phase.
    pub const fn phase(&self) -> ShutdownPhase {
        self.phase
    }

    /// Starts draining with an absolute monotonic deadline.
    pub fn begin(&mut self, deadline_ms: u64) {
        if self.phase == ShutdownPhase::Running {
            self.phase = ShutdownPhase::Draining;
            self.deadline_ms = Some(deadline_ms);
        }
    }

    /// Returns whether in-flight work must cancel at `now_ms`.
    pub fn cancelled(&self, now_ms: u64) -> bool {
        self.phase != ShutdownPhase::Running
            || self.deadline_ms.is_some_and(|deadline| now_ms >= deadline)
    }

    /// Marks teardown complete. The caller still owns kill-switch ordering.
    pub fn complete(&mut self) {
        self.phase = ShutdownPhase::Complete;
    }
}
