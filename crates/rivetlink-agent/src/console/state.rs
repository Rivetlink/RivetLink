use rivetlink_protocol::HostConsoleState;

/// Sanitized result of Linux seat discovery. It deliberately holds no account
/// name, session ID, display address, or other privacy-sensitive metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleObservation {
    /// The non-root RivetLink broker is connected and healthy.
    pub broker_online: bool,
    /// The local GDM greeter currently owns the physical seat0 console.
    pub gdm_active: bool,
    /// A graphical user session currently owns the physical seat0 console.
    pub desktop_active: bool,
    /// The active graphical desktop reports its normal lock screen.
    pub desktop_locked: bool,
}

impl ConsoleObservation {
    /// The absence of an active owner during a normal handover, rather than a
    /// broker failure, means the display is switching sessions.
    #[must_use]
    pub const fn switching() -> Self {
        Self {
            broker_online: true,
            gdm_active: false,
            desktop_active: false,
            desktop_locked: false,
        }
    }
}

/// Converts Linux seat observations into the externally visible lifecycle and
/// maintains a monotonically increasing generation for capture restarts.
#[derive(Debug, Clone, Copy)]
pub struct ConsoleStateMachine {
    state: HostConsoleState,
    generation: u64,
}

impl Default for ConsoleStateMachine {
    fn default() -> Self {
        Self {
            state: HostConsoleState::Booting,
            generation: 0,
        }
    }
}

impl ConsoleStateMachine {
    /// Apply one discovery observation. Returns `Some` only if the public state
    /// changed; a changed state always increments the capture generation.
    pub fn observe(&mut self, observation: ConsoleObservation) -> Option<(HostConsoleState, u64)> {
        let next = state_for(observation, self.state);
        if next == self.state {
            return None;
        }
        self.state = next;
        self.generation = self.generation.saturating_add(1);
        Some((self.state, self.generation))
    }

    /// Current state and capture generation, including the initial boot state.
    #[must_use]
    pub const fn current(&self) -> (HostConsoleState, u64) {
        (self.state, self.generation)
    }
}

fn state_for(observation: ConsoleObservation, previous: HostConsoleState) -> HostConsoleState {
    if !observation.broker_online {
        return HostConsoleState::Offline;
    }
    if observation.gdm_active {
        // A GDM appearance after a ready desktop is a logout/user-switch
        // completion, not a reboot. The client keeps its session open and waits
        // for the next frame generation.
        return HostConsoleState::GdmLogin;
    }
    if observation.desktop_active {
        return if observation.desktop_locked {
            HostConsoleState::SessionLocked
        } else {
            HostConsoleState::DesktopReady
        };
    }
    match previous {
        HostConsoleState::Booting | HostConsoleState::Offline => HostConsoleState::Booting,
        HostConsoleState::GdmLogin => HostConsoleState::SessionStarting,
        HostConsoleState::DesktopReady | HostConsoleState::SessionLocked => {
            HostConsoleState::SessionSwitching
        },
        HostConsoleState::SessionStarting | HostConsoleState::SessionSwitching => {
            HostConsoleState::SessionSwitching
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GDM: ConsoleObservation = ConsoleObservation {
        broker_online: true,
        gdm_active: true,
        desktop_active: false,
        desktop_locked: false,
    };
    const DESKTOP: ConsoleObservation = ConsoleObservation {
        broker_online: true,
        gdm_active: false,
        desktop_active: true,
        desktop_locked: false,
    };

    #[test]
    fn boot_to_gdm_to_desktop_is_not_offline() {
        let mut machine = ConsoleStateMachine::default();
        assert_eq!(machine.observe(GDM), Some((HostConsoleState::GdmLogin, 1)));
        assert_eq!(
            machine.observe(ConsoleObservation::switching()),
            Some((HostConsoleState::SessionStarting, 2))
        );
        assert_eq!(
            machine.observe(DESKTOP),
            Some((HostConsoleState::DesktopReady, 3))
        );
    }

    #[test]
    fn lock_unlock_and_logout_have_distinct_states() {
        let mut machine = ConsoleStateMachine::default();
        let _ = machine.observe(DESKTOP);
        assert_eq!(
            machine.observe(ConsoleObservation {
                desktop_locked: true,
                ..DESKTOP
            }),
            Some((HostConsoleState::SessionLocked, 2))
        );
        assert_eq!(
            machine.observe(DESKTOP),
            Some((HostConsoleState::DesktopReady, 3))
        );
        assert_eq!(
            machine.observe(ConsoleObservation::switching()),
            Some((HostConsoleState::SessionSwitching, 4))
        );
        assert_eq!(machine.observe(GDM), Some((HostConsoleState::GdmLogin, 5)));
    }

    #[test]
    fn broker_loss_is_offline_and_recovery_returns_to_booting() {
        let mut machine = ConsoleStateMachine::default();
        let _ = machine.observe(GDM);
        assert_eq!(
            machine.observe(ConsoleObservation {
                broker_online: false,
                ..GDM
            }),
            Some((HostConsoleState::Offline, 2))
        );
        assert_eq!(
            machine.observe(ConsoleObservation::switching()),
            Some((HostConsoleState::Booting, 3))
        );
    }

    #[test]
    fn unchanged_observation_does_not_restart_capture() {
        let mut machine = ConsoleStateMachine::default();
        let _ = machine.observe(GDM);
        assert_eq!(machine.observe(GDM), None);
        assert_eq!(machine.current(), (HostConsoleState::GdmLogin, 1));
    }
}
