CREATE TABLE session_participants (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    role TEXT NOT NULL CHECK (role IN ('viewer', 'controller', 'admin')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    left_at TIMESTAMPTZ
);

CREATE INDEX idx_participants_session ON session_participants(session_id);
CREATE INDEX idx_participants_user ON session_participants(user_id);
