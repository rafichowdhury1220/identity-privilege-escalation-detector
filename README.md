# Identity Privilege Escalation Detector

This small Python project demonstrates architecture and IAM thinking for recruiters and engineering reviewers. It models users, roles and permissions as a privilege graph and implements lightweight detection for:

- Privilege escalation paths
- Toxic role combinations
- Excessive permissions

Why this shows architecture thinking

- Clear separation of concerns: `graph` models data, `analyzer` scores risk, `cli` wires inputs.
- Uses a graph model to reason about reachability and escalation.
- Configurable detection rules and readable outputs for security workflows.

Quickstart

Install deps:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run analyzer on sample data:

```bash
python -m src.identity_detector.cli samples/example.yaml
```

Project layout

- `src/identity_detector/graph.py` — privilege graph model
- `src/identity_detector/analyzer.py` — scoring and detections
- `src/identity_detector/cli.py` — command-line interface
- `samples/example.yaml` — sample dataset
- `tests/` — unit tests showing expected behavior

Next steps (ideas to impress recruiters)

- Add more detectors (time-based access, resource sensitivity scoring)
- Integrate with GitHub API to import org roles and repo permissions
- Add visualization (graph rendering) and dashboards
