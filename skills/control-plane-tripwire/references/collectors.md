# Read-only collectors

Every command here reads. None of them change state. If your credentials allow writes, Tripwire still only issues reads; prefer a token scoped to read access.

## GitHub branch protection

```bash
gh api repos/OWNER/REPO/branches/BRANCH/protection
```

| Control id pattern | JSON path |
| --- | --- |
| `gh.<branch>.required_reviews` | `.required_pull_request_reviews.required_approving_review_count` |
| `gh.<branch>.enforce_admins` | `.enforce_admins.enabled` |
| `gh.<branch>.required_status_checks` | `.required_status_checks.contexts` |
| `gh.<branch>.allow_force_pushes` | `.allow_force_pushes.enabled` |

Change events: `gh api orgs/ORG/audit-log -f phrase='action:protected_branch'` (Enterprise) or your SIEM export.

Rulesets: `gh api repos/OWNER/REPO/rulesets` then `gh api repos/OWNER/REPO/rulesets/ID`.

## Alert routing

Export notification policies or routing rules from your observability or paging tool as JSON, then map each critical route to a control id such as `alerts.sev1.route`. Examples: Grafana `GET /api/v1/provisioning/policies`, PagerDuty service integrations, Datadog monitor `message` handles. Use the vendor's read endpoint or a config export.

## Audit sinks

Read the sink configuration (enabled flag, destination, retention days) from the cloud provider or log platform. Typical controls: `audit.sink.enabled`, `audit.sink.retention_days`, `audit.sink.destination`.

## Agent policy

Read the agent runtime's permission or approval config, for example a settings file that sets which actions need human approval. Typical controls: `agent.policy.require_human_approval_prod`, `agent.policy.allowed_tools`, `agent.policy.monitor_sampling_rate`.

## Infrastructure as code

If controls are managed in Terraform or similar, compare the committed desired state with the live read. A difference between the two is itself evidence and should be listed as a change with no event unless your pipeline logged it.

## Paste-in route

If nothing is connected, ask the person to paste exports. Mark the source as `pasted` in the report so readers know it was not read live.
