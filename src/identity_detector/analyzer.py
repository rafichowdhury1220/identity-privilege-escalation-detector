from .graph import PrivilegeGraph
from typing import Dict, Any, List


CRITICAL_TOXIC_SETS = [
    {"Cloud Admin", "Database Admin"},
    {"Infra Owner", "Secrets Manager"},
]


def score_user(username: str, g: PrivilegeGraph) -> Dict[str, Any]:
    perms = g.permissions_of_user(username)
    toxic = g.detect_toxic_combinations(username, CRITICAL_TOXIC_SETS)
    escalation_paths: List[List[str]] = []
    # check for any permission that seems high-value
    for p in perms:
        escalation_paths.extend(g.find_escalation_paths(username, p, max_depth=4))

    score = 0
    reasons = []
    if toxic:
        score += 60
        reasons.append(f"toxic_roles={toxic}")
    if len(perms) > 8:
        score += min(30, (len(perms) - 8) * 3)
        reasons.append(f"excessive_permissions={len(perms)}")
    if any(len(p) <= 3 for p in escalation_paths):
        score += 20
        reasons.append("short_escalation_path")

    # normalize to label
    if score >= 80:
        risk = "Critical"
    elif score >= 40:
        risk = "High"
    elif score >= 15:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "user": username,
        "score": score,
        "risk": risk,
        "reasons": reasons,
        "permissions": sorted(list(perms)),
        "escalation_paths": escalation_paths,
        "toxic_sets": toxic,
    }
