//! The credential-resolution contract, the caller identity, and tenant scoping.
//!
//! The skeleton never parses a token itself and never trusts claims inside one. It asks the app's
//! [`CredentialResolver`] on **every** request and turns a rejection into a 401 with no detail.
//! That is the whole point: a door that only verifies a signature (a JWT, an HMAC, a session
//! cookie) has shipped once in this fleet and was a real hole — the token's claims are not a
//! credential until the live row behind them still exists, is active, and still owns the workspace.

use async_trait::async_trait;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::tool::ToolError;

/// How much a caller may do. Ordered: a higher role includes the lower ones.
///
/// * `ReadOnly` — a key issued for assistants that must not change anything.
/// * `Workspace` — the customer's own key: read and write inside their own workspace.
/// * `Admin` — the operator running the software. May call the explicit cross-workspace tools,
///   which are the only tools allowed to use [`Scope::unscoped`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    ReadOnly,
    Workspace,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::ReadOnly => "read_only",
            Role::Workspace => "workspace",
            Role::Admin => "admin",
        }
    }

    /// True when this role satisfies the tool's minimum.
    pub fn can(self, minimum: Role) -> bool {
        self >= minimum
    }
}

/// One authenticated caller, resolved by the app from a bearer token.
///
/// `subject` is the audit identity: a consumer name or a key prefix — never the secret itself.
#[derive(Debug, Clone)]
pub struct Caller {
    pub subject: String,
    pub role: Role,
    /// Every workspace this caller owns in this app. The token is the tenancy boundary: tools take
    /// no tenant argument, so this list is the ONLY thing that decides what a call can see.
    pub tenants: Vec<Uuid>,
    /// The caller's own workspace, for the operator who both runs the software and uses it.
    pub home: Option<Uuid>,
}

impl Caller {
    pub fn new(subject: impl Into<String>, role: Role) -> Self {
        Self {
            subject: subject.into(),
            role,
            tenants: Vec::new(),
            home: None,
        }
    }

    pub fn with_tenant(mut self, id: Uuid) -> Self {
        if !self.tenants.contains(&id) {
            self.tenants.push(id);
        }
        self
    }

    pub fn with_tenants(mut self, ids: impl IntoIterator<Item = Uuid>) -> Self {
        for id in ids {
            self = self.with_tenant(id);
        }
        self
    }

    pub fn with_home(mut self, id: Uuid) -> Self {
        self.home = Some(id);
        self.with_tenant(id)
    }

    /// The scope every tool call starts from.
    ///
    /// The home workspace (if any) is first, so a tool that writes without an explicit target
    /// writes where the operator actually lives.
    pub fn scope(&self) -> Scope {
        let mut ids = Vec::with_capacity(self.tenants.len() + 1);
        if let Some(home) = self.home {
            ids.push(home);
        }
        for id in &self.tenants {
            if !ids.contains(id) {
                ids.push(*id);
            }
        }
        Scope {
            ids,
            unscoped: false,
        }
    }

    /// Reject a resolver's output that could never be a legitimate caller. Fail closed: a door that
    /// starts up with a caller carrying no workspace answers `count: 0` forever and nobody notices.
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.subject.trim().is_empty() {
            return Err(AuthError::Invalid);
        }
        if self.role != Role::Admin && self.tenants.is_empty() {
            return Err(AuthError::Invalid);
        }
        Ok(())
    }
}

/// Why a credential was rejected. The reason is audited; it is never sent to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No `Authorization: Bearer` header at all.
    Missing,
    /// Unknown token, wrong shape, or no matching live row.
    Invalid,
    /// The row exists but its liveness predicate says no (`is_active = false`, `revoked_at` set).
    Revoked,
    /// Expired by its own timestamp.
    Expired,
    /// The credential is genuine and live, but its role may not reach this door AT ALL — an
    /// **admin-only** door handed a customer key. Authenticated, not authorised: the transport
    /// answers 403, never 401 (the caller was recognised) and never a tool list.
    ///
    /// Use this only for a property of the CALLER's own credential (its role, or the operator
    /// authority of the user who minted it). A row the caller may not see is `NotFound`, not this.
    Forbidden,
    /// The app could not decide (database down, misconfiguration). Still a 401 to the caller.
    Unavailable(String),
}

impl AuthError {
    pub fn audit_reason(&self) -> String {
        match self {
            AuthError::Missing => "missing".into(),
            AuthError::Invalid => "invalid".into(),
            AuthError::Revoked => "revoked".into(),
            AuthError::Expired => "expired".into(),
            AuthError::Forbidden => {
                "forbidden: live credential without the role this door requires".into()
            }
            AuthError::Unavailable(why) => format!("unavailable: {why}"),
        }
    }
}

/// The app's credential resolver. **Implement the live checks here, not above.**
///
/// Required checks, every call, in this order:
///
/// 1. `Authorization: Bearer <plaintext>` parsed by the transport; `<plaintext>` handed to you.
/// 2. `sha256_hex(plaintext) == key_hash` — or, for a session-backed door, the app's canonical
///    session lookup (Redis blacklist, `user_session_state`, password-change stamp included).
/// 3. the credential row's liveness predicate (`is_active`, `revoked_at IS NULL`, expiry).
/// 4. the workspace row it points at still exists.
/// 5. map it to the workspace ids the tools filter on — for apps whose key table carries a
///    `tenant_id` that is NOT the id the data uses, resolve the real join here.
///
/// A signature-only implementation is the defect this contract exists to prevent.
#[async_trait]
pub trait CredentialResolver: Send + Sync + 'static {
    async fn resolve(&self, bearer: &str) -> Result<Caller, AuthError>;
}

/// The fleet's key hash: `sha256_hex(plaintext)`, lowercase hex, no salt, no pepper.
///
/// If your app stores bcrypt or argon2, its keys cannot authenticate an MCP bearer: re-hashing at
/// request time cannot compare against a salted hash without the plaintext. Migrate the key store
/// (keep the sealed copy for reveal) before promising the door.
pub fn hash_token(plaintext: &str) -> String {
    let mut h = Sha256::new();
    h.update(plaintext.as_bytes());
    hex::encode(h.finalize())
}

/// Constant-time byte comparison for bearer material (no length-dependent early exit on content).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The set of workspace ids one call may touch.
///
/// Constructed from a [`Caller`]; the only way to widen it is [`Scope::unscoped`], which an
/// admin-only tool must call deliberately (and which the registry makes visible in the audit line).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    ids: Vec<Uuid>,
    unscoped: bool,
}

impl Scope {
    /// The caller's own workspaces.
    pub fn for_caller(caller: &Caller) -> Self {
        caller.scope()
    }

    /// Every workspace — admin-only tools that exist to inspect tenants. Never derive this from an
    /// empty list: an empty list is "this caller owns nothing", not "show everything".
    pub fn unscoped() -> Self {
        Self {
            ids: Vec::new(),
            unscoped: true,
        }
    }

    pub fn ids(&self) -> &[Uuid] {
        &self.ids
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn is_unscoped(&self) -> bool {
        self.unscoped
    }

    pub fn contains(&self, workspace: Uuid) -> bool {
        self.unscoped || self.ids.contains(&workspace)
    }

    /// **The 404, not 403, rule lives here.** A row that belongs to another workspace must answer
    /// "not found": a refusal that distinguishes "exists but yours" from "does not exist" confirms
    /// the row exists, which is exactly the leak tenancy is meant to stop.
    pub fn require(&self, workspace: Uuid) -> Result<(), ToolError> {
        if self.contains(workspace) {
            Ok(())
        } else {
            Err(ToolError::NotFound)
        }
    }

    /// The `and …` clause to paste into a fixed statement, with `$param` as the bind index.
    ///
    /// Bind [`Scope::as_text_array`] (`$param::text[]`). Using this in the WHERE clause — not a
    /// check above the query — is what makes the guarantee structural.
    pub fn sql_filter(&self, column: &str, param: usize) -> String {
        if self.unscoped {
            // An unscoped scope must still be explicit in the SQL so a reader sees it.
            "and true".to_string()
        } else if self.ids.is_empty() {
            // No ids owned: match nothing. Never widen to "all".
            "and false".to_string()
        } else {
            format!("and {column}::text = any(${param}::text[])")
        }
    }

    /// The value to bind against [`Scope::sql_filter`].
    pub fn as_text_array(&self) -> Vec<String> {
        self.ids.iter().map(|u| u.to_string()).collect()
    }
}

/// A cheap alias used by ports that build the id list themselves.
pub type ScopeIds = Vec<Uuid>;

#[cfg(test)]
mod tests {
    use super::*;

    fn a() -> Uuid {
        Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
    }
    fn b() -> Uuid {
        Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()
    }

    #[test]
    fn hash_matches_known_sha256() {
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn foreign_workspace_is_not_found_not_forbidden() {
        let scope = Scope::for_caller(&Caller::new("k", Role::Workspace).with_tenant(a()));
        let err = scope.require(b()).unwrap_err();
        assert!(matches!(err, ToolError::NotFound));
        assert_eq!(err.code(), "not_found");
    }

    #[test]
    fn empty_scope_matches_nothing_and_is_not_unscoped() {
        let scope = Scope::for_caller(&Caller::new("k", Role::Admin));
        assert_eq!(scope.sql_filter("t.tenant_id", 3), "and false");
        assert!(!scope.contains(a()));
        assert_ne!(scope, Scope::unscoped());
        assert_eq!(Scope::unscoped().sql_filter("t.tenant_id", 3), "and true");
    }

    #[test]
    fn home_is_first_so_writes_land_there() {
        let caller = Caller::new("ops", Role::Admin)
            .with_tenant(b())
            .with_home(a());
        assert_eq!(caller.scope().ids(), &[a(), b()]);
    }

    #[test]
    fn caller_validation_fails_closed() {
        assert!(Caller::new("", Role::Admin).validate().is_err());
        assert!(Caller::new("k", Role::Workspace).validate().is_err());
        assert!(Caller::new("k", Role::Workspace)
            .with_tenant(a())
            .validate()
            .is_ok());
        assert!(Caller::new("ops", Role::Admin).validate().is_ok());
    }

    #[test]
    fn roles_are_ordered() {
        assert!(Role::Admin.can(Role::Workspace));
        assert!(Role::Workspace.can(Role::ReadOnly));
        assert!(!Role::ReadOnly.can(Role::Workspace));
    }
}
