//! Role-based access control: permissions catalog and role→permission mapping.
//!
//! v1 uses a hardcoded role hierarchy because the only mutating writers of
//! `user_roles` are the registration flow (owner) and the login flow
//! (operator). Once organizations can mint custom roles, this mapping moves
//! into the database and the lookups become dynamic.

use std::collections::HashSet;

/// Coarse-grained permissions exposed to handlers via [`AuthUser::require`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// Read the list of devices in the org.
    DevicesList,
    /// Register a new device (consumes an enrollment slot).
    DevicesRegister,
    /// Read active sessions.
    SessionsList,
    /// Initiate a new session against any device in the org.
    SessionsCreate,
    /// Read the audit log (sensitive — security info).
    AuditRead,
    /// Manage organization settings (delete devices, invite users, etc.).
    OrgAdmin,
}

impl Permission {
    /// Stable string slug used for serialization and DB rows.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DevicesList => "devices:list",
            Self::DevicesRegister => "devices:register",
            Self::SessionsList => "sessions:list",
            Self::SessionsCreate => "sessions:create",
            Self::AuditRead => "audit:read",
            Self::OrgAdmin => "org:admin",
        }
    }
}

/// Collapse a user's roles into the set of permissions they hold.
pub fn permissions_for_roles<S: AsRef<str>>(roles: &[S]) -> HashSet<Permission> {
    let mut perms = HashSet::new();
    for role in roles {
        match role.as_ref() {
            "owner" => {
                // Owners can do everything.
                perms.insert(Permission::DevicesList);
                perms.insert(Permission::DevicesRegister);
                perms.insert(Permission::SessionsList);
                perms.insert(Permission::SessionsCreate);
                perms.insert(Permission::AuditRead);
                perms.insert(Permission::OrgAdmin);
            },
            "admin" => {
                perms.insert(Permission::DevicesList);
                perms.insert(Permission::DevicesRegister);
                perms.insert(Permission::SessionsList);
                perms.insert(Permission::SessionsCreate);
                perms.insert(Permission::AuditRead);
            },
            "operator" => {
                perms.insert(Permission::DevicesList);
                perms.insert(Permission::DevicesRegister);
                perms.insert(Permission::SessionsList);
                perms.insert(Permission::SessionsCreate);
            },
            "viewer" => {
                perms.insert(Permission::DevicesList);
                perms.insert(Permission::SessionsList);
            },
            _ => {
                // Unknown roles get no permissions — fail closed.
            },
        }
    }
    perms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_has_all_permissions() {
        let perms = permissions_for_roles(&["owner"]);
        assert!(perms.contains(&Permission::OrgAdmin));
        assert!(perms.contains(&Permission::AuditRead));
        assert!(perms.contains(&Permission::DevicesRegister));
    }

    #[test]
    fn operator_cannot_read_audit_log() {
        let perms = permissions_for_roles(&["operator"]);
        assert!(perms.contains(&Permission::SessionsCreate));
        assert!(!perms.contains(&Permission::AuditRead));
        assert!(!perms.contains(&Permission::OrgAdmin));
    }

    #[test]
    fn viewer_is_read_only() {
        let perms = permissions_for_roles(&["viewer"]);
        assert!(perms.contains(&Permission::DevicesList));
        assert!(perms.contains(&Permission::SessionsList));
        assert!(!perms.contains(&Permission::SessionsCreate));
        assert!(!perms.contains(&Permission::DevicesRegister));
    }

    #[test]
    fn unknown_role_grants_nothing() {
        let perms = permissions_for_roles(&["space-pirate"]);
        assert!(perms.is_empty());
    }

    #[test]
    fn multiple_roles_union_permissions() {
        let perms = permissions_for_roles(&["viewer", "admin"]);
        assert!(!perms.contains(&Permission::OrgAdmin));
        assert!(perms.contains(&Permission::AuditRead));
        assert!(perms.contains(&Permission::DevicesList));
    }

    #[test]
    fn permission_slugs_are_stable() {
        assert_eq!(Permission::DevicesList.as_str(), "devices:list");
        assert_eq!(Permission::OrgAdmin.as_str(), "org:admin");
    }
}
