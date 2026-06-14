-- Refresh token store with rotation chain and theft detection.
--
-- Each refresh token has a unique `jti` (JWT ID) and belongs to a `family_id`
-- shared by all tokens descended from the original login. On rotation, the
-- old token is marked `revoked_at` and `replaced_by_jti` points to the new
-- token. If a revoked token is ever presented again, the entire family is
-- revoked (token theft).

CREATE TABLE refresh_tokens (
    jti UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by_jti UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at) WHERE revoked_at IS NULL;
