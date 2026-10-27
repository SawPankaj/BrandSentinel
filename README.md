# BrandSentinel

BrandSentinel is a self-hosted brand governance workspace for source-backed content reviews. It includes authenticated accounts, workspace boundaries, role-controlled review decisions, encrypted content storage, searchable brand knowledge, document extraction, version history, and a server-generated activity record.

## Project layout

- `frontend/` — browser UI, styles, and deterministic client-side interaction helpers
- `backend/` — authenticated HTTP service, security helpers, dependencies, and runtime data directory
- `tests/` — JavaScript and Python automated checks
- Project root — launch scripts, Docker configuration, documentation, and changelog

## Start locally (Windows PowerShell)

Requires Python 3.10 or newer. The PowerShell launcher installs packages listed in `backend/requirements.txt` if needed.

1. Run `.\run.ps1 -SetupAdmin` (or `python backend/server.py setup-admin`) once to create the initial administrator. The password must be at least 12 characters.
2. Run `.\run.ps1` and open <http://127.0.0.1:8765>.
3. Sign in with the initial administrator credentials. Use **Team** to add users; provide the initial password to each user using your organization's secure channel.

The local server binds to loopback by default. Persistent data lives in `backend/data/`. The generated development encryption key is stored separately at `backend/data/development.key`; back up the database and key together. Losing the key makes encrypted content unrecoverable. Never commit or share the `backend/data/` directory.

## Deploy with Docker Compose

This build is intended to run behind a trusted TLS reverse proxy. Configure a long random 32-byte URL-safe Base64 key and the public host name before starting:

```powershell
$env:BRANDSENTINEL_MASTER_KEY = & python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))"
$env:BRANDSENTINEL_ALLOWED_HOSTS = 'brands.example.com'
docker compose up --build -d
docker compose exec app python server.py setup-admin
```

The service listens on container port 8765 and publishes it only on host loopback (`127.0.0.1:8765`), so a host-based reverse proxy can connect without exposing the app directly. Configure the reverse proxy to terminate HTTPS, forward the original `Host`, overwrite `X-Real-IP` with the connecting client address, and route only the configured host to the container. Persist `/app/backend/data`; protect and back up `BRANDSENTINEL_MASTER_KEY` independently. Set `BRANDSENTINEL_ENV=production` (already set in Compose); the service refuses startup without the master key, allowed host list, and trusted proxy setting, and uses Secure, HttpOnly, SameSite cookies.

## Included product workflows

- Authenticated login, account lockout, session expiry, CSRF protection, server-derived workspace and role, and workspace switching
- Workspace administrators can create workspaces and add workspace members with the roles Administrator, Brand manager, Content creator, Legal reviewer, and Regional lead
- Review submission, resubmission, source-backed checks, comments, decisions, escalation, reviewer clearance, approval locking, and version history
- Brand knowledge rules/facts, confirmed source imports, PDF/DOCX/PPTX/TXT/Markdown/HTML extraction, insights and activity export
- SQLite tenant partitioning, AES-GCM encryption of workspace state and content versions, PBKDF2 password hashes, session-token hashing, and server-derived activity events (append-only through the product API; database operators can still alter records)
- Responsive UI with keyboard focus styles and reduced-motion support

Checks are deterministic and provide evidence for human decisions. No AI provider, SSO/SCIM, email delivery, external drive integration, OCR, image/logo analysis, automatic publishing, billing, or multi-region database replication is included. HTML checks cover a limited set of measurable accessibility signals and do not certify WCAG conformance. These boundaries should be resolved and independently assessed for a regulated or high-volume enterprise launch. The current build is suitable for a self-hosted private beta/pilot after deployment-specific security review; this repository does not claim a third-party penetration test or SOC 2/ISO certification.

## Verify

Run from this folder:

```powershell
& 'C:/Users/mrpan/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe' --test tests/core.test.js tests/structure.test.js
& 'C:/Users/mrpan/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe' -m unittest discover -s tests -p '*_test.py' -v
```
