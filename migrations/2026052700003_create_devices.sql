CREATE TABLE devices (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    hostname TEXT,
    platform TEXT,
    public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_devices_org ON devices(organization_id);
CREATE INDEX idx_devices_public_key ON devices(public_key);
