# CyberShield backend

Runnable FastAPI service for the incident response dashboard. It stores data in SQLite by default and exposes the versioned API under `/api/v1`. Evidence is **metadata only**; the service never accepts or stores evidence files.

## Setup

Requires Python 3.10+.

```bash
cd "/home/saksham/Documents/VisualPrograms/CYBERSHIELD—INCIDENTRESPONSE&INVESTIGATIONDASHBOARD/backend"
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env`, generate a fresh signing secret, and configure the frontend origins. `JWT_SECRET` is required; startup refuses missing or weak values (under 32 characters, low character diversity, or low entropy).

```dotenv
DATABASE_URL=sqlite:///./cybershield.db
# Generate with: python -c "import secrets; print(secrets.token_urlsafe(48))"
JWT_SECRET=<generated-random-secret>
JWT_EXPIRE_MINUTES=60
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
```

`CORS_ORIGINS` is a comma-separated list of exact origins and matches the key in `.env.example`. Never commit a populated `.env`.

## Create accounts and seed demo incidents

There are deliberately **no default/demo credentials**. Create an account and enter its password interactively (minimum 12 characters):

```bash
python -m app.cli create-user --username admin --email admin@example.com --role admin
python -m app.cli create-user --username analyst --email analyst@example.com --role analyst
python -m app.cli create-user --username viewer --email viewer@example.com --role viewer
```

Change a password explicitly:

```bash
python -m app.cli set-password --username admin
```

Add safe, synthetic incident records (repeatable and idempotent):

```bash
python -m app.cli seed-demo
```

The seed command creates six explicitly simulated scenarios covering repeated failed logins, suspicious outbound network activity, endpoint malware detection, phishing, a web application vulnerability, and unusual privilege escalation. Cases use varied workflow statuses, synthetic analyst assignments and dates, and only RFC 5737 documentation IP ranges. Re-running it does not duplicate those cases. No users or passwords are created by the seed command.

## Run and test

```bash
alembic upgrade head
uvicorn app.main:app --reload
PYTHONPATH=. pytest -q
```

Run the migration before account/seed CLI commands, which use the migrated schema.

Interactive OpenAPI docs are at `http://127.0.0.1:8000/docs`; health check is `/health`.

## API overview

Every application route is prefixed with `/api/v1`. The frontend contract is: login posts JSON `{"username":"…","password":"…"}` (email is also accepted) to `/api/v1/auth/login` and receives `{"access_token":"…","token_type":"bearer","user":{...}}`; send `Authorization: Bearer <access_token>` to protected endpoints. `/api/v1/auth/me` returns the user object, `/api/v1/incidents` returns `{"items":[...],"total":N,"page":N,"page_size":N}`, and `/api/v1/import/alerts` accepts multipart field `file` and returns `{"imported":N,"skipped":N,"errors":[...]}`.

| Route | Purpose |
|---|---|
| `POST /auth/login`, `GET /auth/me`, `POST /auth/logout` | Login JSON: `{"username":"…","password":"…"}`; returns `{access_token, token_type, user}`. `/auth/me` returns the user object. |
| `GET/POST /incidents`, `GET/PATCH/DELETE /incidents/{id}` | Filtered/paginated incident management |
| `GET/POST /incidents/{id}/timeline` | Incident chronology |
| `GET/POST /evidence` | Metadata-only evidence inventory |
| `POST /evidence/{id}/verify-hash` | Compare a submitted SHA-256 string to recorded evidence metadata; accepts no file and audits the boolean result |
| `GET/POST /indicators` | Validated, deduplicated IOCs (IP, domain, URL, email, hash) |
| `GET /dashboard`, `GET /analytics` | Aggregated counts |
| `GET /audit` | Audit trail |
| `GET /reports/{id}` | Escaped printable HTML report |
| `POST /import/alerts` | `multipart/form-data` field `file`; validates and stores alerts in a separate review queue (max 2 MB / 1000 rows), returns `{imported, skipped, errors}` |
| `GET /import/alerts` | Authenticated, paginated alert review queue; filter `review_status=pending|promoted` |
| `POST /import/alerts/{id}/promote` | Analyst/admin action creating a confirmed incident, linking the source alert, and adding audit/timeline records |

Import does not create confirmed incidents. Alerts are validated and held in a distinct, idempotent review queue, retaining source ID/system/timestamp when supplied. Duplicate external IDs (per source system) and identical records are skipped. Invalid row feedback and import audit entries contain only row numbers, reason codes, and counts—not raw alert fields. A user with analyst/admin role must explicitly promote an alert before an incident and promotion timeline entry are created. Reports include escaped, incident-associated IOC values and types, and report generation is audited.

Incident workflow: `new`, `triaged`, `investigating`, `containment`, `eradication`, `recovery`, `resolved`, `closed`. Legacy `open` and `contained` values remain accepted; migration upgrades existing records to `new` and `containment`. Incident records include priority, reporter, affected asset, validated source/destination IP, detection source, tags, root cause, business impact, and containment/remediation/resolution notes. Reports visibly warn when an incident is simulated.

Incident list filters: `severity`, `status`, `category`, `assignee`, `search`, `date_from`, `date_to`, `sort_by`, `sort_order`, `page`, `page_size` (maximum 100). Date filters accept ISO dates (`YYYY-MM-DD`) and include the full `date_to` day. Sort fields are `created_at`, `severity`, and `updated_at`; sort direction is `asc` or `desc`. Defaults are `sort_by=created_at&sort_order=desc`. Roles are least-privilege: viewers can read, analysts can create/update operational records and import, and only admins can delete incidents or administer users. User administration is currently through the CLI. Logout is stateless: clients must discard their bearer token; tokens expire according to `JWT_EXPIRE_MINUTES`.

Failed logins are throttled per client IP and normalized username: after five failures in 15 minutes, further attempts return `429` with `Retry-After` until the 15-minute window elapses. Put an additional rate limiter at the trusted reverse proxy for distributed attempts. The client address comes from the ASGI connection; configure trusted proxy handling at the deployment edge rather than trusting arbitrary forwarded headers.

The report escapes all user-entered values and includes no file content. Restrict CORS origins and protect the SQLite database and signing key according to the deployment environment.
