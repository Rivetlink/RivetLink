CREATE TABLE device_groups (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE device_group_devices (
    device_group_id UUID NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (device_group_id, device_id)
);

CREATE INDEX idx_device_groups_org ON device_groups(organization_id);
