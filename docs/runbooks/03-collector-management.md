# Runbook: Collector Management

## Overview

This runbook covers managing data collectors including EDR (CrowdStrike, SentinelOne), SIEM (Splunk), cloud providers, and DLP systems.

## Prerequisites

- [ ] Access to collector configuration
- [ ] API credentials for each source system
- [ ] kubectl access to production cluster

## Collector Types

| Collector | Sources | Protocol | Auth |
|-----------|---------|----------|------|
| EDR | CrowdStrike, SentinelOne | REST API | OAuth2 |
| SIEM | Splunk | HEC, REST | Token |
| Cloud | AWS, Azure, GCP | SDK | OIDC/WIF |
| DLP | Digital Guardian | REST API | API Key |

## Adding a New Collector

### Step 1: Configure Credentials

```yaml
# config.yaml
ingestion:
  collectors:
    crowdstrike:
      enabled: true
      client_id: ${CROWDSTRIKE_CLIENT_ID}
      client_secret: ${CROWDSTRIKE_CLIENT_SECRET}
      base_url: https://api.crowdstrike.com
      poll_interval: 60s
```

### Step 2: Create Kubernetes Secret

```bash
kubectl create secret generic collector-creds -n threat-telemetry \
  --from-literal=CROWDSTRIKE_CLIENT_ID=$CLIENT_ID \
  --from-literal=CROWDSTRIKE_CLIENT_SECRET=$CLIENT_SECRET
```

### Step 3: Restart Collector

```bash
kubectl rollout restart deployment/threat-telemetry-hub -n threat-telemetry
```

### Step 4: Verify Data Flow

```bash
# Check collector status
curl -s http://localhost:8080/api/v1/collectors/crowdstrike | jq .

# Verify events are flowing
curl -s http://localhost:8080/api/v1/events?source=crowdstrike&limit=5 | jq .
```

## Troubleshooting Collectors

### CrowdStrike Issues

**Symptom**: No events from CrowdStrike

**Diagnosis**:
```bash
# Check collector logs
kubectl logs -n threat-telemetry -l app=threat-telemetry-hub | grep crowdstrike

# Test API connectivity
curl -X POST https://api.crowdstrike.com/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET"
```

**Common Issues**:
| Issue | Cause | Fix |
|-------|-------|-----|
| 401 Unauthorized | Invalid credentials | Regenerate OAuth client |
| 403 Forbidden | Missing API scope | Add required scopes in Falcon console |
| 429 Rate Limited | Too many requests | Increase poll interval |
| Connection timeout | Network issue | Check firewall rules |

### SentinelOne Issues

**Symptom**: SentinelOne collector unhealthy

**Diagnosis**:
```bash
# Check API token
curl -H "Authorization: ApiToken $TOKEN" \
  https://usea1-partners.sentinelone.net/web/api/v2.1/system/status
```

**Common Issues**:
| Issue | Cause | Fix |
|-------|-------|-----|
| 401 Unauthorized | Expired token | Generate new API token |
| Site not found | Wrong site ID | Verify site ID in console |
| No data | Wrong account scope | Check token has correct scope |

### Splunk HEC Issues

**Symptom**: Events not appearing in Splunk

**Diagnosis**:
```bash
# Test HEC endpoint
curl -k https://splunk:8088/services/collector/health

# Send test event
curl -k https://splunk:8088/services/collector/event \
  -H "Authorization: Splunk $HEC_TOKEN" \
  -d '{"event": "test"}'
```

**Common Issues**:
| Issue | Cause | Fix |
|-------|-------|-----|
| 403 Token disabled | HEC token inactive | Enable token in Splunk |
| 400 Invalid data | Wrong data format | Check JSON structure |
| Connection refused | HEC port blocked | Open port 8088 |

## Collector Maintenance

### Rotating Credentials

1. Generate new credentials in source system
2. Update Kubernetes secret:
```bash
kubectl create secret generic collector-creds -n threat-telemetry \
  --from-literal=CROWDSTRIKE_CLIENT_SECRET=$NEW_SECRET \
  --dry-run=client -o yaml | kubectl apply -f -
```
3. Rolling restart:
```bash
kubectl rollout restart deployment/threat-telemetry-hub -n threat-telemetry
```
4. Verify collectors healthy

### Pausing a Collector

```yaml
# Update config
ingestion:
  collectors:
    crowdstrike:
      enabled: false  # Pause collector
```

### Backfilling Historical Data

```bash
# Trigger backfill for specific time range
curl -X POST http://localhost:8080/api/v1/collectors/crowdstrike/backfill \
  -H "Content-Type: application/json" \
  -d '{
    "start_time": "2026-01-01T00:00:00Z",
    "end_time": "2026-01-05T00:00:00Z"
  }'
```

## Monitoring Collectors

### Key Metrics

```promql
# Events per collector
sum(rate(threat_telemetry_hub_events_ingested_total[5m])) by (source)

# Collector errors
sum(rate(threat_telemetry_hub_collector_errors_total[5m])) by (collector)

# Last successful poll
threat_telemetry_hub_collector_last_poll_timestamp
```

### Alerting Rules

```yaml
groups:
  - name: collectors
    rules:
      - alert: CollectorDown
        expr: threat_telemetry_hub_collector_status == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Collector {{ $labels.collector }} is down"
      
      - alert: NoEventsReceived
        expr: rate(threat_telemetry_hub_events_ingested_total[10m]) == 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "No events from {{ $labels.source }} for 10 minutes"
```

## Escalation

| Condition | Action |
|-----------|--------|
| All collectors down | Page on-call immediately |
| Single collector down >15m | Page on-call |
| Rate limiting | Increase poll interval, notify |
| Credential expired | Generate new, rotate |

