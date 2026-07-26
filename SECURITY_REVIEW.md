# Letta Security Review Report

**Date:** 2026-07-26
**Scope:** Areas 1-8 as specified in the review request
**Excludes:** Already-known issues (unauthenticated-by-default, broken auth_token.py, callback_url SSRF in async messages, default Postgres credentials)

---

## Finding 1: Server Password Printed to stdout/logs in Plaintext

**File:** `letta/server/rest_api/app.py`, line 290
**Severity:** Medium

### Vulnerable Code
```python
# Line 290
print(f"▶ Using secure mode with password: {random_password}")
```

### Description
When secure mode is enabled via `LETTA_SERVER_SECURE=true` or `--secure`, the server password (either auto-generated or from `LETTA_SERVER_PASSWORD` env var) is printed in plaintext to stdout. In containerized deployments, stdout is typically captured by container logging drivers (Docker, Kubernetes), centralized logging systems (CloudWatch, Stackdriver, Datadog), and container orchestration dashboards.

### Exploitation
An attacker with read access to container logs, log aggregation systems, or CI/CD pipeline output can extract the authentication password and gain full API access. This is particularly dangerous because:
1. Log access often has broader permissions than application access
2. Logs are frequently retained for extended periods
3. Log systems often lack the same access controls as the application

### Impact
Complete authentication bypass for anyone with log access.

---

## Finding 2: CORS Configuration Allows Credential-Bearing Cross-Origin Requests from Localhost Origins

**Files:** `letta/settings.py`, lines 158-168; `letta/server/rest_api/app.py`, lines 293-299
**Severity:** Medium

### Vulnerable Code
```python
# settings.py lines 158-168
cors_origins = [
    "http://letta.localhost",
    "http://localhost:8283",
    "http://localhost:8083",
    "http://localhost:3000",
    "http://localhost:4200",
]
if env_cors_origins:
    cors_origins.extend(env_cors_origins.split(","))

# app.py lines 287, 293-299
settings.cors_origins.append("https://app.letta.com")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Description
The CORS configuration combines `allow_credentials=True` with `allow_headers=["*"]` and multiple localhost origins. While localhost origins are common in development, the `ACCEPTABLE_ORIGINS` environment variable allows arbitrary origin injection via comma-separated values with no validation. If an operator sets `ACCEPTABLE_ORIGINS=*` (a common mistake), Starlette's `CORSMiddleware` will reflect any `Origin` header verbatim when `allow_credentials=True`, enabling credential theft from any malicious website.

Additionally, `allow_headers=["*"]` permits any custom header including `user_id`, which is the mechanism used for actor impersonation (see Finding 3).

### Exploitation
1. Operator sets `ACCEPTABLE_ORIGINS=*` or includes an attacker-controlled domain
2. Attacker hosts a page that makes credentialed fetch requests to the Letta server
3. The browser sends cookies/auth headers, and the response is readable by the attacker's page
4. Combined with Finding 3, the attacker can also set the `user_id` header to impersonate any user

### Impact
Cross-origin data exfiltration and state manipulation when CORS is misconfigured by operator.

---

## Finding 3: User Identity Spoofing via Unauthenticated `user_id` Header

**Files:** All routers under `letta/server/rest_api/routers/v1/`; `letta/services/user_manager.py`, lines 208-216
**Severity:** High

### Vulnerable Code
```python
# Example from agents.py line 688
actor_id: str | None = Header(None, alias="user_id"),

# user_manager.py lines 208-216
async def get_actor_or_default_async(self, actor_id: Optional[str] = None):
    """Fetch the user or default user asynchronously."""
    target_id = actor_id or self.DEFAULT_USER_ID
    try:
        return await self.get_actor_by_id_async(target_id)
    except NoResultFound:
        user = await self.create_default_actor_async(org_id=DEFAULT_ORG_ID)
        return user
```

### Description
Every API endpoint extracts the acting user identity from the `user_id` HTTP header with no cryptographic verification. The header is directly trusted and used to look up the actor. Any caller can set `user_id` to any existing user's ID to act as that user. This is distinct from the "unauthenticated-by-default" known issue — even in deployments that add external authentication (e.g., API gateway), the `user_id` header is never validated against the authenticated identity, creating a privilege escalation vector.

The nginx reverse proxy in the default Docker Compose setup does not strip or override the `user_id` header, so upstream headers from clients pass through unmodified.

### Exploitation
```bash
curl -H "user_id: <victim-user-id>" https://letta-server/v1/agents/
```
This returns all agents belonging to the victim user. All CRUD operations on agents, tools, sources, messages, and memory can be performed as any user.

### Impact
Complete horizontal privilege escalation. Any authenticated user can impersonate any other user in a multi-tenant deployment.

---

## Finding 4: nginx Reverse Proxy Missing WebSocket Upgrade Headers and Request Size Limits

**File:** `nginx.conf`, lines 1-28
**Severity:** Medium

### Vulnerable Code
```nginx
location / {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    resolver 127.0.0.11; # docker dns
    proxy_pass $api_target;
}
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

### Description
The nginx configuration has several issues:

1. **Unused WebSocket upgrade map:** The `map $http_upgrade $connection_upgrade` block is defined but never referenced in the `location` block. The `proxy_set_header Upgrade` and `proxy_set_header Connection` directives are missing, as is `proxy_http_version 1.1`. This means WebSocket connections will fail through nginx, but more importantly, the `map` directive suggests WebSocket support was intended but incompletely implemented.

2. **No `client_max_body_size`:** There is no request body size limit. The default nginx limit is 1MB, which is reasonable, but since `proxy_pass` with a variable (`$api_target`) disables buffering, large uploads go directly to the backend with no nginx-level protection.

3. **No `proxy_buffering` or timeout configuration:** Missing `proxy_read_timeout`, `proxy_connect_timeout`, and `proxy_send_timeout` mean default 60s timeouts apply, but for a service that does LLM inference (which can take minutes), this creates a mismatch.

4. **`X-Forwarded-For` uses `$remote_addr` not `$proxy_add_x_forwarded_for`:** This overwrites any existing `X-Forwarded-For` header rather than appending. While this prevents header spoofing (good), it means the real client IP is lost if there's another proxy in front of nginx.

### Impact
Incomplete reverse proxy hardening that could lead to DoS through unbounded request sizes.

---

## Finding 5: Docker Container Runs as Root with Exposed PostgreSQL Port

**File:** `Dockerfile`, lines 72-74, 88; `compose.yaml`, lines 17, 29-30
**Severity:** Medium

### Vulnerable Code
```dockerfile
# Dockerfile line 88
EXPOSE 8283 5432 4317 4318
```
```yaml
# compose.yaml lines 17, 29-30
ports:
  - "${LETTA_PG_PORT:-5432}:5432"
# ...
ports:
  - "8083:8083"
  - "8283:8283"
```

### Description
1. **No `USER` directive in Dockerfile:** The container runs all processes (Python server, PostgreSQL, OpenTelemetry collector) as root. If an attacker achieves code execution through a tool (which is a feature — tools execute arbitrary Python code), they run as root inside the container.

2. **PostgreSQL port exposed to host:** Port 5432 is mapped to the host in `compose.yaml`, making the database directly accessible from outside the Docker network. Combined with the known default credentials, this allows direct database access bypassing all application-level access controls.

3. **Multiple services in one container:** The Dockerfile runs PostgreSQL, the Letta server, and the OpenTelemetry collector in a single container. This violates container isolation principles and means a compromise of any service gives access to all others.

4. **Exposed debug/telemetry ports:** Ports 4317 and 4318 (OTLP gRPC and HTTP) are exposed, allowing external injection of telemetry data.

### Exploitation
An attacker on the host network can connect directly to PostgreSQL:
```bash
psql -h localhost -U letta -d letta  # password: letta
```
This provides direct read/write access to all data, including agent configurations, memories, API keys, and tool source code.

### Impact
Direct database access bypassing all application controls; root-level container escape risk.

---

## Finding 6: Arbitrary Code Execution via `/v1/tools/run` Endpoint

**File:** `letta/server/rest_api/routers/v1/tools.py`, lines 217-251
**Severity:** High (by design, but lacks safeguards)

### Vulnerable Code
```python
@router.post("/run", response_model=ToolReturnMessage, operation_id="run_tool_from_source")
async def run_tool_from_source(
    server: SyncServer = Depends(get_letta_server),
    request: ToolRunFromSource = Body(...),
    actor_id: Optional[str] = Header(None, alias="user_id"),
):
    """
    Attempt to build a tool from source, then run it on the provided arguments
    """
    actor = await server.user_manager.get_actor_or_default_async(actor_id=actor_id)
    return await server.run_tool_from_source(
        tool_source=request.source_code,
        tool_source_type=request.source_type,
        tool_args=request.args,
        tool_env_vars=request.env_vars,
        ...
    )
```

### Description
This endpoint accepts arbitrary Python source code and executes it on the server. While this is a documented feature (tool creation/execution), there are no guardrails:

1. **No code sandboxing in default local mode:** The `ToolExecutionSandbox` (legacy) uses `exec()` in the server process (`tool_execution_sandbox.py` line 282). The newer `AsyncToolSandboxLocal` runs code in a subprocess but with no seccomp, no namespace isolation, and as root (in Docker).

2. **No rate limiting:** An attacker can submit unlimited code execution requests.

3. **No resource limits:** No CPU, memory, or disk constraints on executed code (beyond a configurable timeout).

4. **Environment variables passed to execution:** The `env_vars` parameter allows the caller to inject environment variables into the execution context.

Combined with the lack of authentication (known issue) and user impersonation (Finding 3), any network-reachable attacker can execute arbitrary code on the server.

### Exploitation
```bash
curl -X POST http://letta:8283/v1/tools/run \
  -H "Content-Type: application/json" \
  -d '{"source_code":"import os\ndef exploit():\n    return os.popen(\"cat /etc/shadow\").read()\n", "name":"exploit", "args":{}}'
```

### Impact
Full remote code execution on the server, running as root in default Docker deployment.

---

## Finding 7: `curl | bash` Pattern in Dockerfile with User-Controllable Version

**File:** `Dockerfile`, lines 48, 54
**Severity:** Medium

### Vulnerable Code
```dockerfile
ARG NODE_VERSION=22

RUN apt-get update && \
    apt-get install -y curl python3 python3-venv && \
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - && \
```

### Description
The Dockerfile uses the `curl | bash` anti-pattern to install Node.js. The `NODE_VERSION` build argument is user-controllable via `--build-arg NODE_VERSION=...`. While the default value (22) is safe, a supply chain attacker who compromises the NodeSource distribution server could inject malicious code that executes during the Docker build. The version is not pinned to a specific hash or checksum.

### Exploitation
1. Supply chain attack on `deb.nodesource.com`
2. Build-time injection via `--build-arg NODE_VERSION=../../../malicious/path`

### Impact
Build-time compromise of the Docker image.

---

## Finding 8: `docker-compose-vllm.yaml` Uses `ipc: host`

**File:** `docker-compose-vllm.yaml`, line 35
**Severity:** Low-Medium

### Vulnerable Code
```yaml
ipc: host
```

### Description
The vLLM service container runs with `ipc: host`, which shares the host's IPC namespace (shared memory, semaphores, message queues) with the container. This weakens container isolation and could allow cross-container attacks if the host runs other services using shared memory for security-sensitive operations.

### Impact
Reduced container isolation; potential for cross-container/host IPC-based attacks.

---

## Finding 9: No Rate Limiting on Any Endpoint

**Files:** `letta/server/rest_api/app.py` (entire file); all routers
**Severity:** Medium

### Description
There is zero rate limiting implemented anywhere in the application. No middleware, no per-endpoint decorators, no third-party rate limiting library (like slowapi). The grep for `rate_limit|throttl|RateLimiter|slowapi` across the codebase returned only LLM provider rate limit error handling, not application-level rate limiting.

Critical operations that lack rate limiting:
1. **`POST /v1/tools/run`** — Arbitrary code execution with no limits
2. **`POST /v1/tools/`** — Tool creation (writes to DB)
3. **`POST /v1/agents/{id}/messages`** — Agent messaging (triggers LLM calls = $$$)
4. **`POST /v1/agents/{id}/messages/async`** — Background job creation
5. **`POST /v1/sources/{id}/upload`** — File upload
6. **`POST /v1/auth`** — Authentication endpoint (brute-forceable)

### Exploitation
- **Credential brute-force:** The `/v1/auth` endpoint can be brute-forced without any lockout or throttling
- **Financial DoS:** Unlimited agent message sends trigger paid LLM API calls, potentially running up large bills
- **Resource exhaustion:** Unlimited async job creation and tool execution can exhaust server resources

### Impact
Brute-force attacks on auth, financial damage via LLM API abuse, and resource exhaustion.

---

## Finding 10: `LettaAsyncRequest.callback_url` is Unvalidated Plain String (SSRF Variant)

**File:** `letta/schemas/letta_request.py`, line 43
**Severity:** Note (supplements known SSRF issue)

### Vulnerable Code
```python
class LettaAsyncRequest(LettaRequest):
    callback_url: Optional[str] = Field(None, description="Optional callback URL to POST to when the job completes")
```

### Description
While the `CreateBatch.callback_url` field uses Pydantic's `HttpUrl` type for validation, the `LettaAsyncRequest.callback_url` uses a plain `Optional[str]`. This means there is no URL scheme validation — an attacker can supply `file:///etc/passwd`, `gopher://`, or internal network addresses like `http://169.254.169.254/latest/meta-data/` (cloud metadata endpoint).

This is noted as supplementary to the known SSRF issue, but the inconsistency between `HttpUrl` (in `CreateBatch`) and bare `str` (in `LettaAsyncRequest`) suggests incomplete remediation.

### Impact
SSRF to internal services, cloud metadata endpoints, or other protocol handlers.

---

## Summary Table

| # | Finding | Severity | Area |
|---|---------|----------|------|
| 1 | Password printed to stdout | Medium | Auth Middleware |
| 2 | CORS allows credential-bearing requests with injectable origins | Medium | CORS |
| 3 | User identity spoofing via `user_id` header | High | Auth Middleware |
| 4 | nginx missing WebSocket headers, size limits | Medium | nginx |
| 5 | Container runs as root, exposes DB port | Medium | Docker |
| 6 | Unrestricted code execution via `/tools/run` | High | Rate Limiting / Design |
| 7 | `curl \| bash` with controllable version in Dockerfile | Medium | Docker |
| 8 | vLLM container uses `ipc: host` | Low-Medium | Docker |
| 9 | No rate limiting on any endpoint | Medium | Rate Limiting |
| 10 | `callback_url` inconsistent validation (SSRF supplement) | Note | Webhooks |
