CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ,
    relay_used BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX idx_sessions_device ON sessions(device_id);
CREATE INDEX idx_sessions_started ON sessions(started_at);
