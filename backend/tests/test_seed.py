from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app import cli
from app.database import Base, make_engine
from app.models import Incident


def test_seed_inserts_six_simulated_cases_once(monkeypatch):
    engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(cli, "SessionLocal", TestSession)

    cli.seed_demo()
    with TestSession() as db:
        cases = db.scalars(select(Incident).order_by(Incident.created_at)).all()
        assert len(cases) == 6
        assert all(case.simulated for case in cases)
        assert {case.status for case in cases} == {
            "triaged", "containment", "investigating", "eradication", "recovery", "resolved",
        }
        assert {case.category for case in cases} == {
            "authentication", "malware", "phishing", "web-application", "privilege-escalation", "network",
        }
        titles = {case.title for case in cases}
        assert any("repeated failed logins" in title for title in titles)
        assert any("outbound network" in title for title in titles)
        assert any("endpoint malware detection" in title for title in titles)
        assert any("phishing" in title for title in titles)
        assert any("web application vulnerability" in title for title in titles)
        assert any("privilege escalation" in title for title in titles)
        assert {case.assignee for case in cases} == {
            "analyst.alex", "analyst.jordan", "analyst.morgan",
        }
        assert cases[0].created_at < cases[-1].created_at
        for case in cases:
            assert case.source_ip and case.source_ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))
            assert case.destination_ip and case.destination_ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))

    cli.seed_demo()
    with TestSession() as db:
        assert len(db.scalars(select(Incident)).all()) == 6
    engine.dispose()
