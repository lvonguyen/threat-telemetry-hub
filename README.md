# Threat Telemetry Hub

**AI-Powered Security Telemetry Aggregation and Enrichment Platform**

Threat Telemetry Hub aggregates, normalizes, and enriches security telemetry from multiple sources (EDR, SIEM, cloud logs) to provide unified visibility and AI-powered contextual risk analysis.

## Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Threat Telemetry Hub                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
│  │  CrowdStrike │  │ SentinelOne  │  │   Defender   │  EDR Sources      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                   │
│         │                 │                 │                            │
│         ▼                 ▼                 ▼                            │
│  ┌─────────────────────────────────────────────────────────┐            │
│  │                    Ingestion Layer                       │            │
│  │  • API connectors for each source                       │            │
│  │  • Rate limiting and backpressure                       │            │
│  │  • Raw event buffering                                   │            │
│  └─────────────────────────┬───────────────────────────────┘            │
│                            │                                             │
│                            ▼                                             │
│  ┌─────────────────────────────────────────────────────────┐            │
│  │                  Normalization Layer                     │            │
│  │  • OCSF (Open Cybersecurity Schema Framework)           │            │
│  │  • ECS (Elastic Common Schema)                          │            │
│  │  • Custom field mapping                                  │            │
│  └─────────────────────────┬───────────────────────────────┘            │
│                            │                                             │
│                            ▼                                             │
│  ┌─────────────────────────────────────────────────────────┐            │
│  │                   AI Analysis Layer                      │            │
│  │  • Claude Opus 4.5 contextual risk scoring              │            │
│  │  • Attack chain correlation                              │            │
│  │  • Anomaly detection                                     │            │
│  │  • Natural language threat summaries                    │            │
│  └─────────────────────────┬───────────────────────────────┘            │
│                            │                                             │
│                            ▼                                             │
│  ┌─────────────────────────────────────────────────────────┐            │
│  │                  Enrichment Layer                        │            │
│  │  • Threat intel (threatforge integration)               │            │
│  │  • Identity context (Entra ID, Okta)                    │            │
│  │  • Asset context (CMDB)                                  │            │
│  │  • Geolocation                                           │            │
│  └─────────────────────────┬───────────────────────────────┘            │
│                            │                                             │
│                            ▼                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
│  │   Splunk     │  │ Elasticsearch│  │   REST API   │  Outputs          │
│  └──────────────┘  └──────────────┘  └──────────────┘                   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Key Features

### Multi-Source Ingestion
- **EDR**: CrowdStrike Falcon, SentinelOne, Microsoft Defender, Carbon Black
- **SIEM**: Splunk, Microsoft Sentinel, Elasticsearch
- **Cloud**: AWS CloudTrail, Azure Activity Logs, GCP Audit Logs

### Schema Normalization
- **OCSF**: Open Cybersecurity Schema Framework for vendor-neutral events
- **ECS**: Elastic Common Schema for Elasticsearch compatibility

### AI-Powered Analysis (Claude Opus 4.5)
- **Contextual Risk Scoring**: AI analyzes raw events before normalization to identify hidden risks
- **Attack Chain Correlation**: Identifies related events across sources
- **Natural Language Summaries**: Human-readable threat descriptions
- **Anomaly Detection**: Behavioral baselines and deviation alerts

### Enrichment
- Threat intelligence from threatforge
- Identity context from Entra ID/Okta
- Asset context from CMDB
- Geolocation and reputation data

## Quick Start

```bash
# Clone repository
git clone https://github.com/lvonguyen/threat-telemetry-hub.git
cd threat-telemetry-hub

# Configure
cp configs/config.example.yaml configs/config.yaml
# Edit config.yaml with your API keys

# Run
go run cmd/hub/main.go

# API available at http://localhost:8080
```

## Configuration

```yaml
# configs/config.yaml
server:
  port: 8080
  
ai:
  provider: anthropic
  model: claude-opus-4-5-20250514
  api_key_env: ANTHROPIC_API_KEY
  
ingestion:
  edr:
    crowdstrike:
      enabled: true
      api_url: https://api.crowdstrike.com
      client_id_env: CS_CLIENT_ID
      client_secret_env: CS_CLIENT_SECRET
    sentinelone:
      enabled: true
      api_url: https://usea1.sentinelone.net
      api_token_env: S1_API_TOKEN
      
  siem:
    splunk:
      enabled: true
      hec_url: https://splunk.example.com:8088
      hec_token_env: SPLUNK_HEC_TOKEN
      
normalization:
  default_schema: ocsf
  
enrichment:
  threatforge:
    enabled: true
    api_url: http://threatforge:8080
  identity:
    entra_id:
      enabled: true
      tenant_id_env: AZURE_TENANT_ID
```

## Architecture

See [docs/HLD.md](docs/HLD.md) for detailed architecture documentation.

## Author

**Liem Vo-Nguyen**
- LinkedIn: [linkedin.com/in/liemvonguyen](https://linkedin.com/in/liemvonguyen)
- Email: liem@vonguyen.io

## License

MIT License

