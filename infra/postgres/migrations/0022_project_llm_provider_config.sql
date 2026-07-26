-- Per-project BYOK: lets a project override the platform-wide default LLM
-- provider (env-configured) with its own provider/model/API key for the
-- Remediation Agent. One row per project — PK on project_id, same 1:1
-- shape as `projects.gate_id` (0007). The API key is never stored in
-- plaintext: `api_key_cipher`/`api_key_nonce` are AES-256-GCM ciphertext
-- and nonce, sealed with the server-side YUNQ_SECRETS_KEY (see
-- infra/postgres/src/llm_config.rs), so a leaked database dump alone
-- cannot recover a tenant's key.
CREATE TABLE IF NOT EXISTS project_llm_provider_config (
    project_id      BIGINT      PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    provider        TEXT        NOT NULL, -- 'openai_compatible' | 'anthropic'
    base_url        TEXT        NULL,
    model           TEXT        NOT NULL,
    api_key_cipher  BYTEA       NOT NULL,
    api_key_nonce   BYTEA       NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
