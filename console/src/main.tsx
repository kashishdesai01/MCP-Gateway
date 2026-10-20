import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

type Delegation = {
  id: string;
  agent_name: string;
  enabled: boolean;
  read_private: boolean;
  read_untrusted: boolean;
  active_operation: string | null;
  agent_policy: string;
  owner_policy: string;
  policy_version: number;
};
type Connector = { id: string; name: string; kind: string; enabled: boolean };
type Pin = { connector_id: string; tool_name: string; approved_hash: string; definition: unknown };
type Event = {
  delegation_id: string;
  seq: string;
  hash: string;
  event: { kind: string; tool?: string; reason?: string; operationId?: string; state?: string };
};
type Operation = { id: string; tool_name: string; state: string; created_at: string };
type State = {
  delegations: Delegation[];
  connectors: Connector[];
  pins: Pin[];
  events: Event[];
  operations: Operation[];
};
type AuthConfig = { issuer: string; clientId: string; resource: string; demo: boolean };
const encode = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

function App() {
  const [token, setToken] = useState('');
  const [state, setState] = useState<State | null>(null);
  const [page, setPage] = useState('Overview');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [auth, setAuth] = useState<AuthConfig | null>(null);
  const [busy, setBusy] = useState(false);
  const [policy, setPolicy] = useState('');
  const [ownerPolicy, setOwnerPolicy] = useState('');
  const [tool, setTool] = useState('list_issues');
  const [repo, setRepo] = useState('demo/public');
  const [body, setBody] = useState('A legitimate support update.');
  const [output, setOutput] = useState('');
  const [operationId, setOperationId] = useState(crypto.randomUUID());
  const [preview, setPreview] = useState<{ pin: Pin; hash: string; definition: unknown } | null>(
    null,
  );
  const [filter, setFilter] = useState('');
  async function api<T>(url: string, method = 'GET', data?: unknown, access = token): Promise<T> {
    const response = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${access}`,
        ...(data ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(data ? { body: JSON.stringify(data) } : {}),
    });
    if (!response.ok)
      throw new Error((await response.json().catch(() => ({ error: response.statusText }))).error);
    return response.status === 204 ? (undefined as T) : response.json();
  }
  async function refresh(access = token) {
    const next = await api<State>('/admin/v1/state', 'GET', undefined, access);
    setState(next);
  }
  async function action(fn: () => Promise<void>) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await fn();
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    void fetch('/auth/config')
      .then((r) => r.json())
      .then(async (c: AuthConfig) => {
        setAuth(c);
        const query = new URLSearchParams(location.search);
        if (!query.has('code')) return;
        const pending = JSON.parse(sessionStorage.getItem('oauth') ?? 'null') as {
          state: string;
          verifier: string;
        } | null;
        sessionStorage.removeItem('oauth');
        if (
          !pending ||
          pending.state !== query.get('state') ||
          (query.has('iss') && query.get('iss') !== c.issuer)
        )
          throw new Error('OAuth response validation failed');
        const discovery = await fetch(`${c.issuer}/.well-known/openid-configuration`).then((r) =>
          r.json(),
        );
        if (
          discovery.issuer !== c.issuer ||
          new URL(discovery.token_endpoint).origin !== new URL(c.issuer).origin
        )
          throw new Error('Unexpected OAuth issuer');
        const response = await fetch(discovery.token_endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: c.clientId,
            code: query.get('code')!,
            redirect_uri: location.origin + '/',
            code_verifier: pending.verifier,
            resource: c.resource,
          }),
        });
        if (!response.ok) throw new Error('OAuth token exchange failed');
        const { access_token } = await response.json();
        history.replaceState({}, '', '/');
        setToken(access_token);
        await refresh(access_token);
      })
      .catch((e) => setError(String(e.message)));
  }, []);
  useEffect(() => {
    const d = state?.delegations[0];
    if (d) {
      setPolicy(d.agent_policy);
      setOwnerPolicy(d.owner_policy);
    }
  }, [state?.delegations[0]?.policy_version]);
  async function login() {
    if (!auth) return;
    if (auth.demo) {
      const { token: access } = await api<{ token: string }>('/demo/login', 'POST', {});
      setToken(access);
      await refresh(access);
      return;
    }
    const discovery = await fetch(`${auth.issuer}/.well-known/openid-configuration`).then((r) =>
      r.json(),
    );
    if (
      discovery.issuer !== auth.issuer ||
      new URL(discovery.authorization_endpoint).origin !== new URL(auth.issuer).origin
    )
      throw new Error('Unexpected OAuth issuer');
    const verifier = encode(crypto.getRandomValues(new Uint8Array(32)));
    const nonce = crypto.randomUUID();
    sessionStorage.setItem('oauth', JSON.stringify({ state: nonce, verifier }));
    const challenge = encode(
      new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))),
    );
    const url = new URL(discovery.authorization_endpoint);
    url.search = new URLSearchParams({
      client_id: auth.clientId,
      redirect_uri: location.origin + '/',
      response_type: 'code',
      scope: 'openid mcp:tools',
      state: nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      resource: auth.resource,
    }).toString();
    location.assign(url);
  }
  const d = state?.delegations[0];
  async function callTool() {
    const [owner, name] = repo.split('/');
    const args = {
      operationId,
      owner,
      repo: name,
      ...(tool === 'get_file_contents' ? { path: 'salary.csv' } : {}),
      ...(tool === 'create_issue' ? { title: 'Support update', body } : {}),
    };
    const response = await fetch('/mcp', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2026-07-28',
        'Mcp-Method': 'tools/call',
        'Mcp-Name': `github__${tool}`,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: operationId,
        method: 'tools/call',
        params: {
          name: `github__${tool}`,
          arguments: args,
          _meta: {
            'io.modelcontextprotocol/protocolVersion': '2026-07-28',
            'io.modelcontextprotocol/clientCapabilities': {},
          },
        },
      }),
    });
    setOutput(JSON.stringify(await response.json(), null, 2));
    await refresh();
  }
  return (
    <div className="shell">
      <aside>
        <a className="brand" href="/" aria-label="Scoped home">
          <span className="brand-mark">s</span>scoped<span className="brand-dot">.</span>
        </a>
        <div className="workspace">
          <span className="workspace-icon">G</span>
          <div>
            Gateway workspace<small>{auth?.demo ? 'Local demonstration' : 'Governed access'}</small>
          </div>
        </div>
        <p className="nav-label">CONTROL PLANE</p>
        <nav>
          {['Overview', 'Agents', 'Policies', 'Tool approvals', 'Audit trail', 'Workbench'].map(
            (name, i) => (
              <button
                className={page === name ? 'nav active' : 'nav'}
                aria-label={name}
                onClick={() => setPage(name)}
                key={name}
              >
                <span className="nav-icon" aria-hidden="true">
                  {['◫', '◉', '≋', '◇', '≡', '⌘'][i]}
                </span>
                <span className="nav-text">{name}</span>
              </button>
            ),
          )}
        </nav>
        <div className="aside-bottom">
          <span className="status-dot" /> Enforcement enabled
          <small>Explicit access. Durable decisions.</small>
        </div>
      </aside>
      <main>
        <header>
          <span>
            Workspace <b>/</b> {page}
          </span>
          <div>
            <span className="env">{auth?.demo ? '● LOCAL / SYNTHETIC' : '● CONNECTED'}</span>
            {token && <button onClick={() => void action(() => refresh())}>Refresh</button>}
          </div>
        </header>
        <div className="content">
          <div className="heading">
            <div>
              <p className="eyebrow">AGENT ACCESS, UNDER CONTROL</p>
              <h1>{page === 'Overview' ? 'Every tool call. Accounted for.' : page}</h1>
              <p className="subtitle">
                {page === 'Overview'
                  ? 'A clear view of who can act, what they can reach, and why.'
                  : 'Inspect and manage the boundaries of delegated access.'}
              </p>
            </div>
            <span className="version">MCP / 2026-07-28</span>
          </div>
          {error && (
            <div role="alert" className="alert error">
              {error}
            </div>
          )}
          {notice && (
            <div role="status" className="alert">
              {notice}
            </div>
          )}
          {!token ? (
            <section className="welcome">
              <div className="shield">◇</div>
              <h2>Know what your agents can do.</h2>
              <p>
                Policies before execution. Persistent data-flow boundaries.
                <br />A verifiable record of every dispatched call.
              </p>
              <button
                className="primary"
                disabled={!auth || busy}
                onClick={() => void action(login)}
              >
                {auth?.demo ? 'Open demo workspace' : 'Sign in with your organization'}{' '}
                <span>↗</span>
              </button>
              <small>
                {auth?.demo
                  ? 'Uses synthetic repositories and a local signing key. No external accounts required.'
                  : 'OAuth authorization code flow with PKCE.'}
              </small>
            </section>
          ) : (
            state && (
              <>
                {page === 'Overview' && (
                  <>
                    <div className="stats">
                      <Stat
                        label="Active delegations"
                        value={state.delegations.filter((x) => x.enabled).length}
                        foot="Individually revocable"
                      />
                      <Stat
                        label="Approved tools"
                        value={state.pins.length}
                        foot="Pinned definitions"
                      />
                      <Stat
                        label="Dispatched calls"
                        value={state.operations.length}
                        foot="Latest 100 operations"
                      />
                      <Stat
                        label="Blocked decisions"
                        value={state.events.filter((x) => x.event.kind === 'denied').length}
                        foot="Within latest 100 audit events"
                      />
                    </div>
                    <div className="overview-grid">
                      <section>
                        <div className="section-heading">
                          <h2>Access boundaries</h2>
                          <span className="tag green">Enforced</span>
                        </div>
                        <div className="boundary">
                          <span>01</span>
                          <div>
                            <h3>Identity & delegation</h3>
                            <p>User subject and client identity resolve to an explicit grant.</p>
                          </div>
                          <b>↗</b>
                        </div>
                        <div className="boundary">
                          <span>02</span>
                          <div>
                            <h3>Policy before execution</h3>
                            <p>Agent permissions intersect with the owner’s entitlements.</p>
                          </div>
                          <b>↗</b>
                        </div>
                        <div className="boundary">
                          <span>03</span>
                          <div>
                            <h3>Private stays private</h3>
                            <p>Private-read taint blocks external writes across token refresh.</p>
                          </div>
                          <b>↗</b>
                        </div>
                      </section>
                      <section className="flow-card">
                        <p className="eyebrow">THE REQUEST PATH</p>
                        <div className="flow-node">
                          Agent <span>Authenticated principal</span>
                        </div>
                        <div className="flow-line">↓</div>
                        <div className="flow-node gateway-node">
                          Scoped gateway <span>Policy · pins · flow control · audit</span>
                        </div>
                        <div className="flow-line">↓</div>
                        <div className="flow-node">
                          Approved upstream <span>Gateway-held credentials</span>
                        </div>
                        <p className="flow-note">
                          No dispatch without a durable authorization record.
                        </p>
                      </section>
                    </div>
                  </>
                )}
                {(page === 'Agents' || page === 'Overview') && (
                  <section>
                    <div className="section-heading">
                      <h2>Agent delegations</h2>
                      <span className="muted">Persistent security state</span>
                    </div>
                    <table>
                      <thead>
                        <tr>
                          <th>AGENT</th>
                          <th>STATUS</th>
                          <th>DATA EXPOSURE</th>
                          <th>POLICY</th>
                          <th>ACTION</th>
                        </tr>
                      </thead>
                      <tbody>
                        {state.delegations.map((agent) => (
                          <tr key={agent.id}>
                            <td>
                              <strong>{agent.agent_name}</strong>
                              <small className="mono">{agent.id.slice(0, 18)}…</small>
                            </td>
                            <td>
                              <span className={'tag ' + (agent.enabled ? 'green' : 'gray')}>
                                {agent.enabled ? 'Active' : 'Revoked'}
                              </span>
                            </td>
                            <td>
                              <span className={'tag ' + (agent.read_private ? 'amber' : 'gray')}>
                                {agent.read_private ? 'Private read' : 'No private read'}
                              </span>{' '}
                              {agent.read_untrusted && (
                                <span className="tag gray">Untrusted read</span>
                              )}
                            </td>
                            <td>v{agent.policy_version}</td>
                            <td>
                              <button
                                disabled={!agent.enabled || busy}
                                onClick={() =>
                                  void action(async () => {
                                    await api(`/admin/v1/delegations/${agent.id}`, 'PATCH', {
                                      enabled: false,
                                    });
                                    await refresh();
                                    setNotice(
                                      'Delegation revoked. Previously admitted calls may still finish.',
                                    );
                                  })
                                }
                              >
                                Revoke
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </section>
                )}
                {page === 'Policies' && d && (
                  <section>
                    <div className="section-heading">
                      <h2>Delegated policy intersection</h2>
                      <span className="tag gray">Version {d.policy_version}</span>
                    </div>
                    <p className="muted">
                      Both policies must allow. The private-to-external-write guardrail remains
                      mandatory.
                    </p>
                    <div className="policy-grid">
                      <label>
                        Agent policy
                        <textarea
                          value={policy}
                          onChange={(e) => setPolicy(e.target.value)}
                          rows={12}
                        />
                      </label>
                      <label>
                        Owner entitlement
                        <textarea
                          value={ownerPolicy}
                          onChange={(e) => setOwnerPolicy(e.target.value)}
                          rows={12}
                        />
                      </label>
                    </div>
                    <button
                      className="primary"
                      disabled={busy}
                      onClick={() =>
                        void action(async () => {
                          await api(`/admin/v1/delegations/${d.id}/policy`, 'PUT', {
                            version: d.policy_version,
                            agentPolicy: policy,
                            ownerPolicy,
                          });
                          await refresh();
                          setNotice('Validated policies saved as a new version.');
                        })
                      }
                    >
                      Validate & save version
                    </button>
                    <div className="simulator">
                      <h3>Test a decision</h3>
                      <label>
                        Tool
                        <select value={tool} onChange={(e) => setTool(e.target.value)}>
                          {['list_issues', 'get_file_contents', 'create_issue'].map((t) => (
                            <option key={t}>{t}</option>
                          ))}
                        </select>
                      </label>
                      <label>
                        Repository
                        <input value={repo} onChange={(e) => setRepo(e.target.value)} />
                      </label>
                      <button
                        disabled={busy}
                        onClick={() =>
                          void action(async () => {
                            const result = await api('/admin/v1/simulate', 'POST', {
                              delegationId: d.id,
                              tool,
                              repo,
                            });
                            setOutput(JSON.stringify(result, null, 2));
                          })
                        }
                      >
                        Simulate
                      </button>
                      <pre>{output || 'No simulation run yet.'}</pre>
                    </div>
                  </section>
                )}
                {page === 'Tool approvals' && (
                  <section>
                    <div className="section-heading">
                      <h2>Pinned tool definitions</h2>
                      <span className="muted">Approval binds the exact definition hash</span>
                    </div>
                    {state.pins.map((pin) => (
                      <div className="pin" key={pin.connector_id + pin.tool_name}>
                        <div>
                          <strong>{pin.tool_name}</strong>
                          <small className="mono">SHA-256 {pin.approved_hash.slice(0, 24)}…</small>
                        </div>
                        <button
                          disabled={busy}
                          onClick={() =>
                            void action(async () => {
                              const fresh = await api<{ hash: string; definition: unknown }>(
                                `/admin/v1/connectors/${pin.connector_id}/tools/${pin.tool_name}`,
                              );
                              setPreview({ pin, ...fresh });
                            })
                          }
                        >
                          Inspect upstream
                        </button>
                      </div>
                    ))}
                    {preview && (
                      <div className="definition-preview">
                        <h3>
                          {preview.hash === preview.pin.approved_hash
                            ? 'Definition matches approval'
                            : 'Definition changed'}
                        </h3>
                        <div className="policy-grid">
                          <div>
                            <h4>Approved</h4>
                            <pre>{JSON.stringify(preview.pin.definition, null, 2)}</pre>
                          </div>
                          <div>
                            <h4>Current upstream</h4>
                            <pre>{JSON.stringify(preview.definition, null, 2)}</pre>
                          </div>
                        </div>
                        <button
                          className="primary"
                          disabled={busy || preview.hash === preview.pin.approved_hash}
                          onClick={() =>
                            void action(async () => {
                              await api(
                                `/admin/v1/connectors/${preview.pin.connector_id}/tools/${preview.pin.tool_name}`,
                                'PUT',
                                { expectedHash: preview.hash },
                              );
                              setPreview(null);
                              await refresh();
                              setNotice('Definition approved.');
                            })
                          }
                        >
                          Approve this exact definition
                        </button>
                      </div>
                    )}
                  </section>
                )}
                {page === 'Audit trail' && (
                  <>
                    <section>
                      <div className="section-heading">
                        <h2>Decision ledger</h2>
                        <button
                          disabled={busy || !d}
                          onClick={() =>
                            void action(async () => {
                              setNotice(
                                JSON.stringify(await api(`/admin/v1/delegations/${d!.id}/verify`)),
                              );
                            })
                          }
                        >
                          Verify hash chain
                        </button>
                      </div>
                      <label>
                        Filter events
                        <input
                          placeholder="Tool, decision, or reason"
                          value={filter}
                          onChange={(e) => setFilter(e.target.value)}
                        />
                      </label>
                      <div className="events">
                        {state.events
                          .filter((e) =>
                            JSON.stringify(e.event).toLowerCase().includes(filter.toLowerCase()),
                          )
                          .map((e) => (
                            <details key={e.delegation_id + e.seq}>
                              <summary>
                                <span className="event-seq">#{e.seq}</span>
                                <span
                                  className={
                                    'tag ' + (e.event.kind === 'denied' ? 'amber' : 'green')
                                  }
                                >
                                  {e.event.kind.replaceAll('_', ' ')}
                                </span>
                                <strong>{e.event.tool || e.event.state || 'Control event'}</strong>
                                <span className="mono muted">{e.hash.slice(0, 12)}</span>
                              </summary>
                              <pre>{JSON.stringify(e.event, null, 2)}</pre>
                            </details>
                          ))}
                        {!state.events.length && (
                          <p className="empty">
                            No events yet. Make a call in the workbench to create the first record.
                          </p>
                        )}
                      </div>
                    </section>
                    <section>
                      <h2>Operation outcomes</h2>
                      <p className="muted">
                        Unknown outcomes are preserved and never automatically redispatched.
                      </p>
                      {state.operations.map((o) => (
                        <div className="pin" key={o.id}>
                          <strong>{o.tool_name}</strong>
                          <span className={'tag ' + (o.state === 'unknown' ? 'amber' : 'green')}>
                            {o.state}
                          </span>
                          <span className="mono muted">{o.id.slice(0, 18)}…</span>
                        </div>
                      ))}
                    </section>
                  </>
                )}
                {page === 'Workbench' && (
                  <section>
                    <div className="section-heading">
                      <h2>Call an approved tool</h2>
                      <span className="tag gray">Same MCP enforcement path</span>
                    </div>
                    <p className="muted">
                      Try a public read, then a private file read, then a public write. Private
                      exposure persists for this delegation.
                    </p>
                    <div className="workbench-grid">
                      <div>
                        <label>
                          Tool
                          <select
                            value={tool}
                            onChange={(e) => {
                              setTool(e.target.value);
                              setOperationId(crypto.randomUUID());
                            }}
                          >
                            {['list_issues', 'get_file_contents', 'create_issue'].map((t) => (
                              <option key={t}>{t}</option>
                            ))}
                          </select>
                        </label>
                        <label>
                          Repository
                          <input
                            value={repo}
                            onChange={(e) => {
                              setRepo(e.target.value);
                              setOperationId(crypto.randomUUID());
                            }}
                          />
                        </label>
                        {tool === 'create_issue' && (
                          <label>
                            Issue body
                            <textarea
                              rows={5}
                              value={body}
                              onChange={(e) => {
                                setBody(e.target.value);
                                setOperationId(crypto.randomUUID());
                              }}
                            />
                          </label>
                        )}
                        <label>
                          Operation identity
                          <input className="mono" value={operationId} readOnly />
                        </label>
                        <div className="button-row">
                          <button
                            className="primary"
                            disabled={busy}
                            onClick={() => void action(callTool)}
                          >
                            Execute call ↗
                          </button>
                          <button
                            disabled={busy}
                            onClick={() => setOperationId(crypto.randomUUID())}
                          >
                            New operation
                          </button>
                        </div>
                        <p className="small-note">
                          Execute again with the same identity to retry safely. Never assign a new
                          identity to an uncertain write.
                        </p>
                      </div>
                      <pre className="output">
                        {output || 'Tool results and enforcement decisions appear here.'}
                      </pre>
                    </div>
                  </section>
                )}
                <footer>
                  <span>Scoped MCP Gateway</span>
                  <span>
                    {auth?.demo
                      ? 'Real MCP protocol · Synthetic fixture data'
                      : 'Policies and operational boundaries are documented in the runbook.'}
                  </span>
                </footer>
              </>
            )
          )}
        </div>
      </main>
    </div>
  );
}
function Stat({ label, value, foot }: { label: string; value: number; foot: string }) {
  return (
    <div className="stat">
      <p>{label}</p>
      <strong>{String(value).padStart(2, '0')}</strong>
      <small>{foot}</small>
    </div>
  );
}
createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
