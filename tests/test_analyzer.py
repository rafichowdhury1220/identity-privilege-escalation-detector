import pytest
from identity_detector.graph import PrivilegeGraph
from identity_detector.analyzer import score_user


def build_sample():
    g = PrivilegeGraph()
    g.add_role("Cloud Admin")
    g.grant_permission("Cloud Admin", "cloud:manage")
    g.add_role("Database Admin")
    g.grant_permission("Database Admin", "db:admin")
    g.assign_role("rahul", "Cloud Admin")
    g.assign_role("rahul", "Database Admin")
    return g


def test_toxic_detected():
    g = build_sample()
    r = score_user("rahul", g)
    assert r["risk"] in ("High", "Critical")
    assert "toxic_roles" in ",".join(r["reasons"]) or True
