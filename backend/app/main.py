import csv
import hashlib
import hmac
import html
import io
import json
import re
from datetime import date, datetime, time, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BeforeValidator, ValidationError
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import AuditLog, Evidence, ImportedAlert, Incident, Indicator, LoginAttempt, TimelineEvent, User
from app.schemas import (
    AuditOut, EvidenceCreate, EvidenceOut, HashVerifyOut, HashVerifyRequest, ImportedAlertOut,
    ImportedAlertPage, ImportResult, IncidentCreate, IncidentOut, IncidentUpdate, IndicatorCreate,
    IndicatorOut, LoginRequest, Page, TimelineCreate, TimelineOut, TokenOut, UserOut,
)
from app.security import create_access_token, decode_access_token, verify_password

app = FastAPI(title=get_settings().app_name, version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
bearer = HTTPBearer(auto_error=False)
LOGIN_FAILURE_LIMIT = 5
LOGIN_LOCKOUT_SECONDS = 900


def parse_iso_date(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("date must use YYYY-MM-DD format")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("date must be a valid calendar date") from exc


ISODate = Annotated[date, BeforeValidator(parse_iso_date)]


def audit(db: Session, user: User | None, action: str, resource_type: str, resource_id=None, details=""):
    db.add(AuditLog(actor_id=user.id if user else None, action=action, resource_type=resource_type,
                    resource_id=str(resource_id) if resource_id is not None else None, details=details[:1000]))


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    try:
        user_id = decode_access_token(credentials.credentials)
    except (jwt.InvalidTokenError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired access token", headers={"WWW-Authenticate": "Bearer"})
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid or inactive account")
    return user


def require_roles(*roles):
    def dependency(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return dependency


def get_incident_or_404(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


def incident_data(values: dict) -> dict:
    normalized = values.copy()
    if isinstance(normalized.get("tags"), list):
        normalized["tags"] = json.dumps(normalized["tags"])
    return normalized


@app.exception_handler(IntegrityError)
async def integrity_error_handler(_request, _exc):
    return JSONResponse(status_code=409, content={"detail": "The requested record conflicts with existing data"})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/v1/auth/login", response_model=TokenOut)
@app.post("/api/v1/auth/login/", response_model=TokenOut, include_in_schema=False)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    db.execute(delete(LoginAttempt).where(
        LoginAttempt.last_attempt_at < now - timedelta(seconds=LOGIN_LOCKOUT_SECONDS)
    ))
    client_ip = request.client.host if request.client else "unknown"
    principal = payload.username.strip().casefold()
    fingerprint = hashlib.sha256(f"{client_ip}\0{principal}".encode("utf-8")).hexdigest()
    attempt = db.get(LoginAttempt, fingerprint)
    if attempt and attempt.last_attempt_at.tzinfo is None:
        attempt.last_attempt_at = attempt.last_attempt_at.replace(tzinfo=timezone.utc)
    if attempt and attempt.failure_count >= LOGIN_FAILURE_LIMIT:
        remaining = LOGIN_LOCKOUT_SECONDS - int((now - attempt.last_attempt_at).total_seconds())
        if remaining > 0:
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts; try again later",
                headers={"Retry-After": str(remaining)},
            )
    user = db.scalar(select(User).where((User.username == payload.username) | (User.email == payload.username)))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        if attempt is None:
            attempt = LoginAttempt(fingerprint=fingerprint, failure_count=0)
            db.add(attempt)
        attempt.failure_count += 1
        attempt.last_attempt_at = now
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password", headers={"WWW-Authenticate": "Bearer"})
    if attempt:
        db.delete(attempt)
    audit(db, user, "auth.login", "user", user.id)
    db.commit()
    return TokenOut(access_token=create_access_token(user.id), user=user)


@app.get("/api/v1/auth/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@app.post("/api/v1/auth/logout", status_code=204)
def logout(user: User = Depends(current_user), db: Session = Depends(get_db)):
    # Bearer tokens are stateless; the client discards its token on logout.
    audit(db, user, "auth.logout", "user", user.id)
    db.commit()


@app.get("/api/v1/incidents", response_model=Page)
def list_incidents(
    severity: str | None = None, status_filter: str | None = Query(default=None, alias="status"),
    category: str | None = None, assignee: str | None = None, search: str | None = None,
    sort_by: str = Query(default="created_at", pattern="^(created_at|severity|updated_at)$"),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    date_from: ISODate | None = None,
    date_to: ISODate | None = None,
    page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
    _user: User = Depends(current_user), db: Session = Depends(get_db),
):
    if date_from and date_to and date_from > date_to:
        raise HTTPException(status_code=422, detail="date_from must be on or before date_to")
    query = select(Incident)
    if severity:
        query = query.where(Incident.severity == severity)
    if status_filter:
        query = query.where(Incident.status == status_filter)
    if category:
        query = query.where(Incident.category == category)
    if assignee:
        query = query.where(Incident.assignee == assignee)
    if search:
        query = query.where(Incident.title.ilike(f"%{search[:100]}%") | Incident.description.ilike(f"%{search[:100]}%"))
    if date_from:
        query = query.where(Incident.created_at >= datetime.combine(date_from, time.min, tzinfo=timezone.utc))
    if date_to:
        query = query.where(Incident.created_at < datetime.combine(date_to + timedelta(days=1), time.min, tzinfo=timezone.utc))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    sort_column = {"created_at": Incident.created_at, "severity": Incident.severity, "updated_at": Incident.updated_at}[sort_by]
    sort_expression = sort_column.asc() if sort_order == "asc" else sort_column.desc()
    id_expression = Incident.id.asc() if sort_order == "asc" else Incident.id.desc()
    items = db.scalars(query.order_by(sort_expression, id_expression).offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=items, total=total, page=page, page_size=page_size)


@app.post("/api/v1/incidents", response_model=IncidentOut, status_code=201)
def create_incident(payload: IncidentCreate, user: User = Depends(require_roles("admin", "analyst")), db: Session = Depends(get_db)):
    incident = Incident(**incident_data(payload.model_dump()), created_by_id=user.id)
    db.add(incident)
    db.flush()
    db.add(TimelineEvent(incident_id=incident.id, event_type="created", description="Incident created", actor=user.username))
    audit(db, user, "incident.create", "incident", incident.id)
    db.commit()
    db.refresh(incident)
    return incident


@app.get("/api/v1/incidents/{incident_id}", response_model=IncidentOut)
def incident_detail(incident_id: int, _user: User = Depends(current_user), db: Session = Depends(get_db)):
    return get_incident_or_404(db, incident_id)


@app.patch("/api/v1/incidents/{incident_id}", response_model=IncidentOut)
def update_incident(incident_id: int, payload: IncidentUpdate, user: User = Depends(require_roles("admin", "analyst")), db: Session = Depends(get_db)):
    incident = get_incident_or_404(db, incident_id)
    changes = payload.model_dump(exclude_unset=True)
    changes = incident_data(changes)
    for key, value in changes.items():
        setattr(incident, key, value)
    incident.updated_at = datetime.now(timezone.utc)
    if changes:
        db.add(TimelineEvent(incident_id=incident.id, event_type="updated", description="Updated: " + ", ".join(sorted(changes)), actor=user.username))
    audit(db, user, "incident.update", "incident", incident.id, ",".join(sorted(changes)))
    db.commit()
    db.refresh(incident)
    return incident


@app.delete("/api/v1/incidents/{incident_id}", status_code=204)
def delete_incident(incident_id: int, user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    incident = get_incident_or_404(db, incident_id)
    audit(db, user, "incident.delete", "incident", incident.id)
    db.delete(incident)
    db.commit()


@app.get("/api/v1/incidents/{incident_id}/timeline", response_model=list[TimelineOut])
def incident_timeline(incident_id: int, _user: User = Depends(current_user), db: Session = Depends(get_db)):
    get_incident_or_404(db, incident_id)
    return db.scalars(select(TimelineEvent).where(TimelineEvent.incident_id == incident_id).order_by(TimelineEvent.occurred_at, TimelineEvent.id)).all()


@app.post("/api/v1/incidents/{incident_id}/timeline", response_model=TimelineOut, status_code=201)
def add_timeline(incident_id: int, payload: TimelineCreate, user: User = Depends(require_roles("admin", "analyst")), db: Session = Depends(get_db)):
    get_incident_or_404(db, incident_id)
    event = TimelineEvent(incident_id=incident_id, event_type=payload.event_type, description=payload.description, actor=user.username)
    db.add(event)
    audit(db, user, "timeline.create", "incident", incident_id)
    db.commit()
    db.refresh(event)
    return event


@app.get("/api/v1/evidence", response_model=list[EvidenceOut])
def list_evidence(incident_id: int | None = None, _user: User = Depends(current_user), db: Session = Depends(get_db)):
    query = select(Evidence)
    if incident_id is not None:
        query = query.where(Evidence.incident_id == incident_id)
    return db.scalars(query.order_by(Evidence.collected_at.desc())).all()


@app.post("/api/v1/evidence", response_model=EvidenceOut, status_code=201)
def add_evidence(payload: EvidenceCreate, user: User = Depends(require_roles("admin", "analyst")), db: Session = Depends(get_db)):
    get_incident_or_404(db, payload.incident_id)
    evidence = Evidence(**payload.model_dump(), added_by_id=user.id)
    db.add(evidence)
    db.add(TimelineEvent(incident_id=payload.incident_id, event_type="evidence_added", description=f"Evidence metadata added: {payload.label}", actor=user.username))
    audit(db, user, "evidence.create", "evidence", details=payload.label)
    db.commit()
    db.refresh(evidence)
    return evidence


@app.post("/api/v1/evidence/{evidence_id}/verify-hash", response_model=HashVerifyOut)
def verify_evidence_hash(
    evidence_id: int,
    payload: HashVerifyRequest,
    user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
):
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    matches = bool(evidence.sha256 and hmac.compare_digest(evidence.sha256.lower(), payload.sha256))
    audit(
        db,
        user,
        "evidence.hash_verify",
        "evidence",
        evidence.id,
        f"recorded_hash_present={bool(evidence.sha256)};matches={matches}",
    )
    db.commit()
    return HashVerifyOut(evidence_id=evidence.id, has_recorded_hash=bool(evidence.sha256), matches=matches)


@app.get("/api/v1/indicators", response_model=list[IndicatorOut])
def list_indicators(indicator_type: str | None = None, incident_id: int | None = None, _user: User = Depends(current_user), db: Session = Depends(get_db)):
    query = select(Indicator)
    if indicator_type:
        query = query.where(Indicator.indicator_type == indicator_type)
    if incident_id is not None:
        query = query.where(Indicator.incident_id == incident_id)
    return db.scalars(query.order_by(Indicator.created_at.desc())).all()


@app.post("/api/v1/indicators", response_model=IndicatorOut, status_code=201)
def add_indicator(payload: IndicatorCreate, user: User = Depends(require_roles("admin", "analyst")), db: Session = Depends(get_db)):
    if payload.incident_id is not None:
        get_incident_or_404(db, payload.incident_id)
    existing = db.scalar(select(Indicator).where(Indicator.indicator_type == payload.indicator_type, Indicator.value == payload.value))
    if existing:
        raise HTTPException(status_code=409, detail="Indicator already exists")
    indicator = Indicator(**payload.model_dump(), created_by_id=user.id)
    db.add(indicator)
    audit(db, user, "indicator.create", "indicator", details=f"{payload.indicator_type}:{payload.value}")
    db.commit()
    db.refresh(indicator)
    return indicator


@app.get("/api/v1/dashboard")
def dashboard(_user: User = Depends(current_user), db: Session = Depends(get_db)):
    total = db.scalar(select(func.count(Incident.id))) or 0
    by_status = dict(db.execute(select(Incident.status, func.count()).group_by(Incident.status)).all())
    by_severity = dict(db.execute(select(Incident.severity, func.count()).group_by(Incident.severity)).all())
    open_count = sum(count for name, count in by_status.items() if name not in {"resolved", "closed"})
    return {"total_incidents": total, "open_incidents": open_count, "by_status": by_status, "by_severity": by_severity,
            "evidence_count": db.scalar(select(func.count(Evidence.id))) or 0,
            "indicator_count": db.scalar(select(func.count(Indicator.id))) or 0}


@app.get("/api/v1/analytics")
def analytics(_user: User = Depends(current_user), db: Session = Depends(get_db)):
    return {
        "trend": [
            {"date": str(day), "count": count}
            for day, count in db.execute(
                select(func.date(Incident.created_at), func.count())
                .group_by(func.date(Incident.created_at))
                .order_by(func.date(Incident.created_at))
            ).all()
        ],
        "severity": dict(db.execute(select(Incident.severity, func.count()).group_by(Incident.severity)).all()),
        "status": dict(db.execute(select(Incident.status, func.count()).group_by(Incident.status)).all()),
        "category": dict(db.execute(select(Incident.category, func.count()).group_by(Incident.category)).all()),
        "analyst_workload": [
            {"analyst": analyst or "Unassigned", "count": count}
            for analyst, count in db.execute(
                select(Incident.assignee, func.count()).group_by(Incident.assignee).order_by(func.count().desc())
            ).all()
        ],
        "resolution_time": None,
        "resolution_time_note": "Insufficient data: explicit resolution timestamps are not recorded yet.",
        "time_to_triage": None,
        "time_to_triage_note": "Insufficient data: explicit triage timestamps are not recorded yet.",
    }


@app.get("/api/v1/audit", response_model=list[AuditOut])
def list_audit(limit: int = Query(100, ge=1, le=500), _user: User = Depends(require_roles("admin", "analyst")), db: Session = Depends(get_db)):
    return db.scalars(select(AuditLog).order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc()).limit(limit)).all()


@app.get("/api/v1/reports/{incident_id}", response_class=HTMLResponse)
def incident_report(incident_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    incident = get_incident_or_404(db, incident_id)
    timeline = db.scalars(select(TimelineEvent).where(TimelineEvent.incident_id == incident_id).order_by(TimelineEvent.occurred_at)).all()
    evidence = db.scalars(select(Evidence).where(Evidence.incident_id == incident_id)).all()
    indicators = db.scalars(
        select(Indicator).where(Indicator.incident_id == incident_id).order_by(Indicator.indicator_type, Indicator.value)
    ).all()
    e = html.escape
    tags = IncidentOut.model_validate(incident).tags
    simulated_banner = (
        '<aside class="simulated-warning">SIMULATED / SYNTHETIC INCIDENT — NOT A REAL EVENT</aside>'
        if incident.simulated
        else ""
    )
    details = [
        ("Priority", incident.priority),
        ("Reporter", incident.reporter or "Not specified"),
        ("Affected asset", incident.affected_asset or "Not specified"),
        ("Source IP", incident.source_ip or "Not specified"),
        ("Destination IP", incident.destination_ip or "Not specified"),
        ("Detection source", incident.detection_source or "Not specified"),
        ("Tags", ", ".join(tags) or "None"),
        ("Root cause", incident.root_cause or "Not specified"),
        ("Business impact", incident.business_impact or "Not specified"),
        ("Containment notes", incident.containment_notes or "Not specified"),
        ("Remediation notes", incident.remediation_notes or "Not specified"),
        ("Resolution notes", incident.resolution_notes or "Not specified"),
    ]
    details_markup = "".join(f"<dt>{e(label)}</dt><dd>{e(value)}</dd>" for label, value in details)
    body = f"""<!doctype html><html><head><meta charset="utf-8"><title>Incident report</title>
<style>body{{font:15px Arial,sans-serif;max-width:900px;margin:2rem auto;color:#17202a}}h1{{border-bottom:2px solid #334}}dt{{font-weight:bold}}dd{{margin-bottom:.6rem}}li{{margin:.6rem 0}}.simulated-warning{{padding:1rem;border:3px solid #9b1c1c;background:#fff1f1;color:#7f1d1d;font-size:1.2rem;font-weight:bold;text-align:center;margin:1rem 0}}@media print{{body{{margin:1cm}}}}</style></head><body>
{simulated_banner}<h1>Incident #{incident.id}: {e(incident.title)}</h1><dl><dt>Status / Severity</dt><dd>{e(incident.status)} / {e(incident.severity)}</dd>
<dt>Category / Assignee</dt><dd>{e(incident.category)} / {e(incident.assignee or "Unassigned")}</dd>
<dt>Description</dt><dd>{e(incident.description)}</dd><dt>Created</dt><dd>{e(incident.created_at.isoformat())}</dd>{details_markup}</dl>
<h2>Timeline</h2><ul>{''.join(f'<li><strong>{e(t.occurred_at.isoformat())} — {e(t.event_type)}</strong>: {e(t.description)} ({e(t.actor or "system")})</li>' for t in timeline)}</ul>
<h2>Evidence metadata</h2><ul>{''.join(f'<li>{e(x.label)} — {e(x.source)}; reference: {e(x.reference or "none")}; SHA-256: {e(x.sha256 or "none")}</li>' for x in evidence)}</ul>
<h2>Associated indicators of compromise</h2><ul>{''.join(f'<li><strong>{e(x.indicator_type)}</strong>: {e(x.value)}</li>' for x in indicators) or '<li>None associated</li>'}</ul>
<footer>Generated for {e(user.username)} · {e(datetime.now(timezone.utc).isoformat())}</footer></body></html>"""
    audit(db, user, "report.view", "incident", incident.id)
    db.commit()
    return HTMLResponse(body)


def audit_import_failure(db: Session, user: User, reason: str):
    audit(db, user, "alerts.import.failed", "import", details=f"reason={reason}")
    db.commit()


def parse_alert_timestamp(row: dict) -> datetime | None:
    timestamp = next(
        (row[key] for key in ("source_timestamp", "event_timestamp", "occurred_at", "timestamp", "created_at") if row.get(key) not in (None, "")),
        None,
    )
    if timestamp is None:
        return None
    if isinstance(timestamp, (int, float)):
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    if not isinstance(timestamp, str):
        raise ValueError("invalid alert")
    parsed = datetime.fromisoformat(timestamp.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_import_row(row: dict) -> tuple[dict, str | None, str | None, datetime | None, str]:
    if not isinstance(row, dict):
        raise ValueError("invalid alert")
    source_id = next((str(row[key]).strip() for key in ("source_id", "alert_id", "id") if row.get(key) not in (None, "")), None)
    source_system = next(
        (str(row[key]).strip()[:120] for key in ("source_system", "vendor") if row.get(key) not in (None, "")),
        None,
    )
    if source_id is not None and not source_id:
        source_id = None
    if source_system == "":
        source_system = None
    source_timestamp = parse_alert_timestamp(row)
    allowed = IncidentCreate.model_fields
    values = IncidentCreate.model_validate({key: row[key] for key in allowed if key in row})
    payload = values.model_dump(mode="json")
    canonical = json.dumps(
        {"source_system": source_system, "source_id": source_id, "source_timestamp": source_timestamp.isoformat() if source_timestamp else None, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
    )
    dedupe_key = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if source_id is not None:
        dedupe_key = hashlib.sha256(f"source\0{(source_system or 'unknown').casefold()}\0{source_id}".encode("utf-8")).hexdigest()
    return payload, source_system, source_id, source_timestamp, dedupe_key


@app.post("/api/v1/import/alerts", response_model=ImportResult, status_code=200)
async def import_alerts(
    file: UploadFile = File(...),
    user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
):
    is_json = (file.filename or "").lower().endswith(".json") or file.content_type == "application/json"
    is_csv = (file.filename or "").lower().endswith(".csv") or file.content_type in {"text/csv", "application/vnd.ms-excel"}
    if not (is_json or is_csv):
        await file.close()
        audit_import_failure(db, user, "unsupported_format")
        raise HTTPException(status_code=415, detail="Only JSON and CSV imports are supported")
    raw = await file.read(2_000_001)
    await file.close()
    if len(raw) > 2_000_000:
        audit_import_failure(db, user, "file_too_large")
        raise HTTPException(status_code=413, detail="Import file exceeds 2 MB limit")
    try:
        text = raw.decode("utf-8-sig")
        rows = json.loads(text) if is_json else list(csv.DictReader(io.StringIO(text)))
        if isinstance(rows, dict):
            rows = rows.get("alerts", [])
        if not isinstance(rows, list) or len(rows) > 1000:
            raise ValueError("invalid alert batch")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        audit_import_failure(db, user, "invalid_document")
        raise HTTPException(status_code=400, detail="Invalid JSON or CSV alert import")

    accepted: dict[str, tuple] = {}
    errors: list[str] = []
    skipped = 0
    invalid_count = 0
    for index, row in enumerate(rows, start=1):
        try:
            normalized = normalize_import_row(row)
        except (ValidationError, ValueError, TypeError, OverflowError):
            skipped += 1
            invalid_count += 1
            if len(errors) < 20:
                errors.append(f"row {index}: invalid alert record")
            continue
        payload, source_system, source_id, source_timestamp, dedupe_key = normalized
        if dedupe_key in accepted or db.scalar(select(ImportedAlert.id).where(ImportedAlert.dedupe_key == dedupe_key)):
            skipped += 1
            continue
        accepted[dedupe_key] = (payload, source_system, source_id, source_timestamp)

    stored = 0
    for dedupe_key, (payload, source_system, source_id, source_timestamp) in accepted.items():
        db.add(ImportedAlert(
            dedupe_key=dedupe_key,
            source_system=source_system,
            source_id=source_id,
            source_timestamp=source_timestamp,
            title=payload["title"],
            severity=payload["severity"],
            payload_json=json.dumps(payload, sort_keys=True, separators=(",", ":")),
            review_status="pending",
            imported_by_id=user.id,
        ))
        stored += 1
    if stored == 0 and invalid_count:
        audit(
            db,
            user,
            "alerts.import.failed",
            "import",
            details=f"reason=no_valid_records;stored=0;skipped={skipped};invalid={invalid_count}",
        )
    else:
        audit(
            db,
            user,
            "alerts.import",
            "import",
            details=f"stored={stored};skipped={skipped};invalid={invalid_count}",
        )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        audit_import_failure(db, user, "concurrent_deduplication_conflict")
        raise HTTPException(status_code=409, detail="Concurrent duplicate alert import; retry safely")
    return ImportResult(imported=stored, skipped=skipped, errors=errors)


@app.get("/api/v1/import/alerts", response_model=ImportedAlertPage)
def list_imported_alerts(
    review_status: str | None = Query(default="pending", pattern="^(pending|promoted)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    _user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    query = select(ImportedAlert)
    if review_status:
        query = query.where(ImportedAlert.review_status == review_status)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    alerts = db.scalars(
        query.order_by(ImportedAlert.imported_at.desc(), ImportedAlert.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return ImportedAlertPage(items=alerts, total=total, page=page, page_size=page_size)


@app.post("/api/v1/import/alerts/{alert_id}/promote", response_model=IncidentOut, status_code=201)
def promote_imported_alert(
    alert_id: int,
    user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
):
    alert = db.get(ImportedAlert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Imported alert not found")
    if alert.promoted_incident_id is not None or alert.review_status == "promoted":
        raise HTTPException(status_code=409, detail="Imported alert has already been promoted")
    try:
        values = IncidentCreate.model_validate(json.loads(alert.payload_json))
    except (ValidationError, json.JSONDecodeError):
        raise HTTPException(status_code=409, detail="Imported alert cannot be promoted because its stored data is invalid")
    incident = Incident(**incident_data(values.model_dump()), created_by_id=user.id)
    db.add(incident)
    db.flush()
    alert.review_status = "promoted"
    alert.promoted_incident_id = incident.id
    alert.promoted_at = datetime.now(timezone.utc)
    alert.promoted_by_id = user.id
    timestamp_note = (
        f" Source timestamp: {alert.source_timestamp.isoformat()}."
        if alert.source_timestamp
        else ""
    )
    db.add(TimelineEvent(
        incident_id=incident.id,
        event_type="alert_promoted",
        description=f"Promoted from imported alert #{alert.id} after analyst review.{timestamp_note}",
        actor=user.username,
        occurred_at=alert.promoted_at,
    ))
    audit(db, user, "alerts.promote", "imported_alert", alert.id, f"incident_id={incident.id}")
    audit(db, user, "incident.create_from_alert", "incident", incident.id, f"imported_alert_id={alert.id}")
    db.commit()
    db.refresh(incident)
    return incident
