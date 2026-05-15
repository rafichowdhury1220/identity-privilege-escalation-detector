import click
import yaml
from .graph import PrivilegeGraph
from .analyzer import score_user


def load_from_dict(data: dict) -> PrivilegeGraph:
    g = PrivilegeGraph()
    for role in data.get("roles", []):
        g.add_role(role["name"])
        for perm in role.get("permissions", []):
            g.grant_permission(role["name"], perm)
        for parent in role.get("inherits", []):
            g.role_inherits(role["name"], parent)

    for user in data.get("users", []):
        g.add_user(user["name"])
        for r in user.get("roles", []):
            g.assign_role(user["name"], r)

    return g


@click.group()
def cli():
    """Identity Privilege Escalation Detector CLI"""


@cli.command()
@click.argument("file", type=click.Path(exists=True))
def analyze(file):
    """Analyze a YAML file containing users/roles/permissions"""
    with open(file, "r") as f:
        data = yaml.safe_load(f)
    g = load_from_dict(data)
    for u in data.get("users", []):
        r = score_user(u["name"], g)
        click.echo(f"User: {r['user']} | Risk: {r['risk']} | Score: {r['score']}")
        click.echo(f"  Reasons: {r['reasons']}")
        click.echo(f"  Roles: {', '.join(g.roles_of_user(r['user']))}")
        click.echo(f"  Permissions({len(r['permissions'])}): {', '.join(r['permissions'])}")
        if r["escalation_paths"]:
            click.echo("  Escalation paths:")
            for p in r["escalation_paths"][:5]:
                click.echo(f"    - {' -> '.join(p)}")


if __name__ == "__main__":
    cli()
