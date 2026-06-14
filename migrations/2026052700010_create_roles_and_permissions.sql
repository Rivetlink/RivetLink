CREATE TABLE roles (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL,
    description TEXT,
    is_system_role BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by UUID REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE user_device_group_access (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_group_id UUID NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, device_group_id)
);

CREATE INDEX idx_roles_org ON roles(organization_id);
CREATE INDEX idx_user_roles_user ON user_roles(user_id);
