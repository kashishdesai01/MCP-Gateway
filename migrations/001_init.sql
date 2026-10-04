CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL,
  name TEXT NOT NULL, UNIQUE (issuer, subject)
);
CREATE TABLE IF NOT EXISTS connectors (
  id UUID PRIMARY KEY, owner_id UUID NOT NULL REFERENCES users(id), name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('fixture', 'github')),
  endpoint TEXT NOT NULL, credential TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT true,
  UNIQUE(owner_id, name)
);
CREATE TABLE IF NOT EXISTS delegations (
  id UUID PRIMARY KEY, owner_id UUID NOT NULL REFERENCES users(id), agent_name TEXT NOT NULL,
  issuer TEXT NOT NULL, subject TEXT NOT NULL, client_id TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  read_private BOOLEAN NOT NULL DEFAULT false, read_untrusted BOOLEAN NOT NULL DEFAULT false,
  active_operation UUID, policy_version INT NOT NULL DEFAULT 1,
  agent_policy TEXT NOT NULL, owner_policy TEXT NOT NULL,
  UNIQUE(issuer, subject, client_id)
);
CREATE TABLE IF NOT EXISTS delegation_connectors (
  delegation_id UUID NOT NULL REFERENCES delegations(id), connector_id UUID NOT NULL REFERENCES connectors(id),
  PRIMARY KEY(delegation_id, connector_id)
);
CREATE TABLE IF NOT EXISTS policy_versions (
  delegation_id UUID NOT NULL REFERENCES delegations(id), version INT NOT NULL,
  agent_policy TEXT NOT NULL, owner_policy TEXT NOT NULL, changed_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(delegation_id, version)
);
CREATE TABLE IF NOT EXISTS tool_pins (
  connector_id UUID NOT NULL REFERENCES connectors(id), tool_name TEXT NOT NULL,
  approved_hash TEXT NOT NULL, definition JSONB NOT NULL,
  approved_by UUID NOT NULL REFERENCES users(id), approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(connector_id, tool_name)
);
CREATE TABLE IF NOT EXISTS operations (
  id UUID PRIMARY KEY, delegation_id UUID NOT NULL REFERENCES delegations(id),
  connector_id UUID NOT NULL REFERENCES connectors(id), tool_name TEXT NOT NULL,
  args_digest TEXT NOT NULL, pin_hash TEXT NOT NULL,
  policy_version INT NOT NULL, state TEXT NOT NULL CHECK(state IN ('dispatching','succeeded','failed','unknown')),
  result_envelope TEXT, reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deadline TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '35 seconds')
);
CREATE INDEX IF NOT EXISTS operations_recovery ON operations(state, deadline);
CREATE TABLE IF NOT EXISTS audit_heads (
  delegation_id UUID PRIMARY KEY REFERENCES delegations(id), seq BIGINT NOT NULL DEFAULT 0, hash TEXT NOT NULL DEFAULT 'genesis'
);
CREATE TABLE IF NOT EXISTS audit_events (
  delegation_id UUID NOT NULL REFERENCES delegations(id), seq BIGINT NOT NULL,
  event JSONB NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL,
  PRIMARY KEY(delegation_id, seq)
);
