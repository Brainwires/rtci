#[derive(Default, Copy, Clone, PartialEq, Debug)]
pub(crate) enum PermState {
    #[default]
    Idle = 0,
    Permitted = 1,
}

impl From<u8> for PermState {
    fn from(v: u8) -> Self {
        match v {
            0 => PermState::Idle,
            _ => PermState::Permitted,
        }
    }
}

#[derive(Default)]
pub(crate) struct Permission {
    st: PermState,
    /// When the server drops the permission unless it is refreshed first: 300 s after the last
    /// CreatePermission or ChannelBind it accepted (RFC 8656 §9). `None` until one is.
    expires_at: Option<std::time::Instant>,
}

impl Permission {
    pub(crate) fn set_state(&mut self, state: PermState) {
        self.st = state;
    }

    pub(crate) fn state(&self) -> PermState {
        self.st
    }

    /// Marks the permission installed or refreshed, to last until `expires_at`.
    pub(crate) fn permit_until(&mut self, expires_at: std::time::Instant) {
        self.st = PermState::Permitted;
        self.expires_at = Some(expires_at);
    }

    pub(crate) fn expires_at(&self) -> Option<std::time::Instant> {
        self.expires_at
    }

    /// Whether the server holds the permission at `now`, as far as the client knows.
    pub(crate) fn is_permitted(&self, now: std::time::Instant) -> bool {
        self.st == PermState::Permitted && self.expires_at.is_none_or(|at| now < at)
    }
}
