import argparse
import getpass
import json
import sys
from datetime import datetime, timezone

from sqlalchemy import select

from app.database import SessionLocal
from app.models import Incident, TimelineEvent, User
from app.security import hash_password


def create_user(username: str, email: str, role: str) -> None:
    password = getpass.getpass("Password (min. 12 characters): ")
    confirm = getpass.getpass("Confirm password: ")
    if len(password) < 12 or password != confirm:
        raise SystemExit("Password must be at least 12 characters and both entries must match.")
    with SessionLocal() as db:
        if db.scalar(select(User).where((User.username == username) | (User.email == email))):
            raise SystemExit("Username or email already exists.")
        db.add(User(username=username, email=email, role=role, password_hash=hash_password(password)))
        db.commit()
    print(f"Created {role} account {username!r}.")


def set_password(username: str) -> None:
    password = getpass.getpass("New password (min. 12 characters): ")
    confirm = getpass.getpass("Confirm password: ")
    if len(password) < 12 or password != confirm:
        raise SystemExit("Password must be at least 12 characters and both entries must match.")
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))
        if user is None:
            raise SystemExit(f"Account {username!r} was not found.")
        user.password_hash = hash_password(password)
        db.commit()
    print(f"Updated password for {username!r}.")


def seed_demo() -> None:
    examples = [
        {
            "title": "Synthetic repeated failed logins",
            "description": "Training simulation generated repeated authentication failures against a lab account.",
            "severity": "medium", "priority": "medium", "status": "triaged", "category": "authentication",
            "assignee": "analyst.alex", "reporter": "synthetic.user01", "affected_asset": "WS-TRAIN-001",
            "source_ip": "192.0.2.21", "destination_ip": "203.0.113.18",
            "detection_source": "synthetic identity monitor", "tags": ["synthetic", "authentication"],
            "root_cause": "A scripted test generated repeated failed sign-ins.",
            "business_impact": "No real accounts or business systems were affected.",
            "containment_notes": "Test account protected by the lab lockout policy.",
            "remediation_notes": "Sign-in detection threshold reviewed.",
            "resolution_notes": "Exercise closed after analyst review.",
            "created_at": datetime(2026, 8, 12, 9, 15, tzinfo=timezone.utc),
        },
        {
            "title": "Synthetic endpoint malware detection",
            "description": "Benign lab alert representing a simulated malware execution.",
            "severity": "critical", "priority": "critical", "status": "containment", "category": "malware",
            "assignee": "analyst.jordan", "reporter": "synthetic.edr", "affected_asset": "LAB-ENDPOINT-02",
            "source_ip": "198.51.100.44", "destination_ip": "203.0.113.44",
            "detection_source": "synthetic EDR rule", "tags": ["synthetic", "endpoint"],
            "root_cause": "Benign test artifact triggered the lab detection.",
            "business_impact": "No production workload or data was affected.",
            "containment_notes": "Lab endpoint isolated for the exercise.",
            "remediation_notes": "Test artifact removed from the lab snapshot.",
            "resolution_notes": "",
            "created_at": datetime(2026, 8, 26, 14, 30, tzinfo=timezone.utc),
        },
        {
            "title": "Synthetic phishing credential theft",
            "description": "Training simulation: a user submitted credentials to a mock landing page.",
            "severity": "high", "priority": "high", "status": "investigating", "category": "phishing",
            "assignee": "analyst.alex", "reporter": "synthetic.soc", "affected_asset": "LAB-FILESERVER-03",
            "source_ip": "192.0.2.63", "destination_ip": "198.51.100.90",
            "detection_source": "synthetic email gateway", "tags": ["synthetic", "credential-theft"],
            "root_cause": "Simulated credential capture through a training link.",
            "business_impact": "No real accounts or business systems were affected.",
            "containment_notes": "Mock message quarantined by simulation.",
            "remediation_notes": "Training follow-up assigned.",
            "resolution_notes": "",
            "created_at": datetime(2026, 9, 4, 11, 0, tzinfo=timezone.utc),
        },
        {
            "title": "Synthetic web application vulnerability",
            "description": "A lab-only web application scan detected a deliberately vulnerable test endpoint.",
            "severity": "high", "priority": "high", "status": "eradication", "category": "web-application",
            "assignee": "analyst.morgan", "reporter": "synthetic.audit", "affected_asset": "LAB-DATASTORE-01",
            "source_ip": "203.0.113.71", "destination_ip": "192.0.2.71",
            "detection_source": "synthetic web application scanner", "tags": ["synthetic", "web-app"],
            "root_cause": "An intentionally vulnerable endpoint was deployed in a closed lab.",
            "business_impact": "No production application or customer data was involved.",
            "containment_notes": "Lab endpoint isolated from external networks.",
            "remediation_notes": "Test application patched and scan re-run.",
            "resolution_notes": "",
            "created_at": datetime(2026, 9, 18, 8, 45, tzinfo=timezone.utc),
        },
        {
            "title": "Synthetic privilege escalation",
            "description": "An exercise-only test account triggered a simulated unusual privilege change.",
            "severity": "high", "priority": "high", "status": "recovery", "category": "privilege-escalation",
            "assignee": "analyst.jordan", "reporter": "synthetic.network", "affected_asset": "LAB-WEB-04",
            "source_ip": "198.51.100.120", "destination_ip": "203.0.113.120",
            "detection_source": "synthetic identity and access monitor", "tags": ["synthetic", "privilege"],
            "root_cause": "A lab test account received an unexpected role in the exercise.",
            "business_impact": "No production permissions or resources were affected.",
            "containment_notes": "Test account role reverted in the lab.",
            "remediation_notes": "Role assignment rule reviewed.",
            "resolution_notes": "",
            "created_at": datetime(2026, 10, 2, 16, 20, tzinfo=timezone.utc),
        },
        {
            "title": "Synthetic suspicious outbound network activity",
            "description": "Simulated outbound connection alert using documentation-range addresses.",
            "severity": "high", "priority": "high", "status": "resolved", "category": "network",
            "assignee": "analyst.morgan", "reporter": "synthetic.dlp", "affected_asset": "LAB-ANALYTICS-05",
            "source_ip": "192.0.2.150", "destination_ip": "198.51.100.150",
            "detection_source": "synthetic network monitor", "tags": ["synthetic", "outbound-network"],
            "root_cause": "Controlled lab traffic matched an outbound monitoring rule.",
            "business_impact": "No real or sensitive data left the lab.",
            "containment_notes": "Simulated connection blocked at the lab boundary.",
            "remediation_notes": "Detection tuning recorded for review.",
            "resolution_notes": "Exercise completed with no production impact.",
            "created_at": datetime(2026, 10, 20, 10, 5, tzinfo=timezone.utc),
        },
    ]
    with SessionLocal() as db:
        existing = set(db.scalars(select(Incident.title)).all())
        added = 0
        for example in examples:
            if example["title"] in existing:
                continue
            values = example.copy()
            created_at = values.pop("created_at")
            values["tags"] = json.dumps(values["tags"])
            incident = Incident(**values, source="synthetic demo data", simulated=True, created_at=created_at, updated_at=created_at)
            db.add(incident)
            db.flush()
            db.add(TimelineEvent(
                incident_id=incident.id,
                event_type="created",
                description="Synthetic seed incident created",
                actor="seed",
                occurred_at=created_at,
            ))
            added += 1
        db.commit()
    print(f"Added {added} of 6 synthetic incident scenarios. No demo account or password was created.")


def main():
    parser = argparse.ArgumentParser(description="CyberShield backend administration")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-user", help="Create an account with an interactively-entered password")
    create.add_argument("--username", required=True)
    create.add_argument("--email", required=True)
    create.add_argument("--role", choices=("admin", "analyst", "viewer"), default="analyst")
    reset = commands.add_parser("set-password", help="Set/reset a user's password interactively")
    reset.add_argument("--username", required=True)
    commands.add_parser("seed-demo", help="Insert synthetic demo incidents (idempotent)")
    args = parser.parse_args()
    try:
        if args.command == "create-user":
            create_user(args.username, args.email, args.role)
        elif args.command == "set-password":
            set_password(args.username)
        else:
            seed_demo()
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
