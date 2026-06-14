CREATE TABLE trusted_keys (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    can_view BOOLEAN NOT NULL DEFAULT true,
    can_control BOOLEAN NOT NULL DEFAULT false,
    can_manage_keys BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_trusted_keys_device ON trusted_keys(device_id);
