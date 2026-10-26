# API guide

FastAPI publishes the generated OpenAPI document at `/openapi.json` and interactive documentation at `/docs` while the backend is running. Application endpoints are versioned under `/api/v1/`.

| API area | Purpose |
| --- | --- |
| Authentication | Login, current identity, logout |
| Dashboard | Database-derived summary and recent cases |
| Incidents | Search, filter, paginate, create, update, and view cases |
| Timeline | Chronological investigation events |
| Evidence | Evidence metadata and hash fields |
| Indicators | Validated IOCs and incident associations |
| Analytics | Aggregated trends and resolution metrics |
| Reports | Printable incident reports and exports |
| Audit | Read-only application history |
| Imports | Reviewable alert imports distinct from confirmed cases |

Consult the live OpenAPI schemas for exact fields and permissions. Never put secrets in free-text fields or import untrusted content without review.

Alert ingestion is a review workflow, not automatic incident confirmation: an authorized analyst imports JSON/CSV, reviews records at `GET /api/v1/import/alerts`, then explicitly promotes one record through `POST /api/v1/import/alerts/{id}/promote` to create an incident. Source alert IDs and timestamps are retained when present, and duplicate imports with an existing source ID should be handled idempotently.
