import re
from datetime import datetime
from ipaddress import ip_address
import json
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator


Role = Literal["admin", "analyst", "viewer"]
Severity = Literal["low", "medium", "high", "critical"]
IncidentStatus = Literal[
    "new", "triaged", "investigating", "containment", "eradication", "recovery", "resolved", "closed",
    "open", "contained",
]
IndicatorType = Literal["ip", "domain", "url", "email", "hash"]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UserOut(ORMModel):
    id: int
    username: str
    email: str
    role: Role
    is_active: bool


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=200)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10000)
    severity: Severity = "medium"
    status: IncidentStatus = "new"
    category: str = Field(default="security", max_length=80)
    assignee: str | None = Field(default=None, max_length=80)
    source: str | None = Field(default=None, max_length=120)
    priority: Severity = "medium"
    reporter: str | None = Field(default=None, max_length=120)
    affected_asset: str | None = Field(default=None, max_length=200)
    source_ip: str | None = Field(default=None, max_length=45)
    destination_ip: str | None = Field(default=None, max_length=45)
    detection_source: str | None = Field(default=None, max_length=200)
    tags: list[str] = Field(default_factory=list, max_length=30)
    root_cause: str = Field(default="", max_length=10000)
    business_impact: str = Field(default="", max_length=10000)
    containment_notes: str = Field(default="", max_length=10000)
    remediation_notes: str = Field(default="", max_length=10000)
    resolution_notes: str = Field(default="", max_length=10000)
    simulated: bool = False

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def valid_optional_ip(cls, value):
        if value is None or not value.strip():
            return None
        return str(ip_address(value.strip()))

    @field_validator("tags")
    @classmethod
    def clean_tags(cls, value):
        if isinstance(value, str):
            value = [tag.strip() for tag in value.split(",") if tag.strip()]
        normalized = [tag.strip() for tag in value]
        if any(not tag or len(tag) > 60 for tag in normalized):
            raise ValueError("tags must be non-empty strings of at most 60 characters")
        if len({tag.casefold() for tag in normalized}) != len(normalized):
            raise ValueError("tags must be unique")
        return normalized


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10000)
    severity: Severity | None = None
    status: IncidentStatus | None = None
    category: str | None = Field(default=None, max_length=80)
    assignee: str | None = Field(default=None, max_length=80)
    source: str | None = Field(default=None, max_length=120)
    priority: Severity | None = None
    reporter: str | None = Field(default=None, max_length=120)
    affected_asset: str | None = Field(default=None, max_length=200)
    source_ip: str | None = Field(default=None, max_length=45)
    destination_ip: str | None = Field(default=None, max_length=45)
    detection_source: str | None = Field(default=None, max_length=200)
    tags: list[str] | None = Field(default=None, max_length=30)
    root_cause: str | None = Field(default=None, max_length=10000)
    business_impact: str | None = Field(default=None, max_length=10000)
    containment_notes: str | None = Field(default=None, max_length=10000)
    remediation_notes: str | None = Field(default=None, max_length=10000)
    resolution_notes: str | None = Field(default=None, max_length=10000)
    simulated: bool | None = None

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def valid_optional_ip(cls, value):
        if value is None or not value.strip():
            return None
        return str(ip_address(value.strip()))

    @field_validator("tags")
    @classmethod
    def clean_optional_tags(cls, value):
        if value is None:
            return value
        if isinstance(value, str):
            value = [tag.strip() for tag in value.split(",") if tag.strip()]
        return IncidentCreate.clean_tags(value)


class IncidentOut(ORMModel):
    id: int
    title: str
    description: str
    severity: str
    status: str
    category: str
    assignee: str | None
    source: str | None
    priority: str
    reporter: str | None
    affected_asset: str | None
    source_ip: str | None
    destination_ip: str | None
    detection_source: str | None
    tags: list[str]
    root_cause: str
    business_impact: str
    containment_notes: str
    remediation_notes: str
    resolution_notes: str
    simulated: bool
    created_at: datetime
    updated_at: datetime
    created_by_id: int | None

    @field_validator("tags", mode="before")
    @classmethod
    def decode_tags(cls, value):
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, list) else []
            except json.JSONDecodeError:
                return []
        return value


class Page(BaseModel):
    items: list[IncidentOut]
    total: int
    page: int
    page_size: int


class TimelineCreate(BaseModel):
    event_type: str = Field(min_length=1, max_length=60)
    description: str = Field(min_length=1, max_length=5000)


class TimelineOut(ORMModel):
    id: int
    incident_id: int
    event_type: str
    description: str
    actor: str | None
    occurred_at: datetime


class EvidenceCreate(BaseModel):
    incident_id: int
    label: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    source: str = Field(min_length=1, max_length=200)
    reference: str | None = Field(default=None, max_length=500)
    sha256: str | None = None

    @field_validator("sha256")
    @classmethod
    def valid_sha256(cls, value):
        if value is not None and not re.fullmatch(r"[a-fA-F0-9]{64}", value):
            raise ValueError("sha256 must contain exactly 64 hexadecimal characters")
        return value.lower() if value else value


class EvidenceOut(ORMModel):
    id: int
    incident_id: int
    label: str
    description: str
    source: str
    reference: str | None
    sha256: str | None
    collected_at: datetime
    added_by_id: int | None


class HashVerifyRequest(BaseModel):
    sha256: str

    @field_validator("sha256")
    @classmethod
    def valid_sha256(cls, value):
        if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
            raise ValueError("sha256 must contain exactly 64 hexadecimal characters")
        return value.lower()


class HashVerifyOut(BaseModel):
    evidence_id: int
    has_recorded_hash: bool
    matches: bool


class IndicatorCreate(BaseModel):
    indicator_type: IndicatorType
    value: str = Field(min_length=1, max_length=253)
    confidence: int = Field(default=50, ge=0, le=100)
    notes: str = Field(default="", max_length=5000)
    incident_id: int | None = None

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value, info):
        kind = info.data.get("indicator_type")
        value = value.strip()
        if kind == "ip":
            return str(ip_address(value))
        if kind == "hash":
            if not re.fullmatch(r"(?i)(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})", value):
                raise ValueError("hash must be a 32, 40, 64, or 128 character hexadecimal digest")
            return value.lower()
        if kind == "domain":
            candidate = value.rstrip(".").lower()
            if len(candidate) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", candidate):
                raise ValueError("invalid domain name")
            return candidate
        if kind == "email":
            candidate = value.lower()
            if len(candidate) > 254 or not re.fullmatch(
                r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
                candidate,
            ):
                raise ValueError("invalid email address")
            return candidate
        if kind == "url":
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or any(c in value for c in "\r\n"):
                raise ValueError("URL indicators must be absolute HTTP(S) URLs")
            return value
        return value


class IndicatorOut(ORMModel):
    id: int
    indicator_type: str
    value: str
    confidence: int
    notes: str
    incident_id: int | None
    created_at: datetime
    created_by_id: int | None


class AuditOut(ORMModel):
    id: int
    actor_id: int | None
    action: str
    resource_type: str
    resource_id: str | None
    details: str
    occurred_at: datetime


class ImportResult(BaseModel):
    imported: int
    skipped: int
    errors: list[str]


class ImportedAlertOut(ORMModel):
    id: int
    source_system: str | None
    source_id: str | None
    source_timestamp: datetime | None
    title: str
    severity: str
    payload: dict = Field(validation_alias="payload_json")
    review_status: str
    imported_at: datetime
    imported_by_id: int | None
    promoted_incident_id: int | None
    promoted_at: datetime | None
    promoted_by_id: int | None

    @field_validator("payload", mode="before")
    @classmethod
    def decode_payload(cls, value):
        if isinstance(value, str):
            return json.loads(value)
        return value


class ImportedAlertPage(BaseModel):
    items: list[ImportedAlertOut]
    total: int
    page: int
    page_size: int
