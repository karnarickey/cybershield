# Security model and limitations

CyberShield is an educational case-management project intended for synthetic cases and authorized security-alert imports. It is not a production-certified incident response service.

- Backend validation and role checks are authoritative; frontend route hiding is not authorization.
- Passwords must be hashed, and signing secrets must be configured outside source control.
- IOC strings and imported alert fields are untrusted input; the application must not automatically visit URLs or execute files.
- Evidence handling is metadata-only in the current design; do not treat a stored hash as proof of chain of custody.
- Audit events are append-only through normal application operations, but SQLite is not tamper-proof against an operator with file access.
- Do not use this project to store classified, regulated, or sensitive evidence.

For deployment use TLS, restrictive CORS, strong environment-managed secrets, patched dependencies, protected backups, access monitoring, external append-only logs, and tested restoration. A formal security review is needed before production use.
