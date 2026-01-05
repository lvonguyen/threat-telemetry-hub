# Threat Telemetry Hub Technical Runbooks

## Overview

This directory contains operational runbooks for Threat Telemetry Hub. Each runbook provides step-by-step procedures for common operational tasks and incident response.

## Runbook Index

| Runbook | Description | Priority |
|---------|-------------|----------|
| [01-deployment.md](./01-deployment.md) | Deployment procedures | High |
| [02-incident-response.md](./02-incident-response.md) | Incident handling | Critical |
| [03-collector-management.md](./03-collector-management.md) | Managing data collectors | High |
| [04-pipeline-troubleshooting.md](./04-pipeline-troubleshooting.md) | Data pipeline issues | High |
| [05-ai-analysis-issues.md](./05-ai-analysis-issues.md) | AI provider issues | Medium |
| [06-ticketing-integration.md](./06-ticketing-integration.md) | ServiceNow/Archer issues | Medium |

## Quick Reference

### Common Commands

```bash
# Check overall health
curl -s http://localhost:8080/health | jq .

# View collector status
curl -s http://localhost:8080/api/v1/collectors | jq .

# Check pipeline metrics
curl -s http://localhost:9090/metrics | grep threat_telemetry

# View recent events
curl -s http://localhost:8080/api/v1/events?limit=10 | jq .
```

### Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `events_ingested_total` | Events received | <100/min = warn |
| `pipeline_latency_seconds` | E2E latency | >30s = critical |
| `queue_depth` | Pending events | >10000 = warn |
| `collector_status` | Collector health | 0 = critical |

## Contact Points

| Role | Contact | Hours |
|------|---------|-------|
| On-Call Engineer | PagerDuty | 24/7 |
| Security Team | security@company.com | 24/7 |
| Platform Team | platform@company.com | Business hours |

