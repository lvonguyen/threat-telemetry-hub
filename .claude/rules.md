# Threat Telemetry Hub - Claude Project Rules

## Project Overview

Threat Telemetry Hub is an AI-powered security telemetry aggregation platform that ingests, normalizes, and enriches security events from multiple sources (EDR, SIEM, cloud logs, DLP).

## Code Conventions

### Go Style
- Use interfaces for provider abstraction (`Provider`, `Collector`, `EnrichmentSource`)
- Error handling: wrap with context (`fmt.Errorf("fetching events from %s: %w", source, err)`)
- Structured logging with `zap`
- Configuration via YAML + environment variables for secrets

### Project Structure
```
threat-telemetry-hub/
├── cmd/hub/main.go           # Entry point
├── internal/
│   ├── ai/                   # AI providers (Anthropic, OpenAI)
│   ├── config/               # Configuration
│   ├── ingestion/            # Data collectors
│   ├── normalization/        # Schema normalization (OCSF, ECS)
│   ├── enrichment/           # Enrichment sources
│   └── correlation/          # Event correlation
├── configs/
├── docs/
└── web/frontend/
```

### AI Integration
- Support both Anthropic Claude and OpenAI for flexibility
- Use provider interface pattern for easy switching
- Default to Claude Opus 4.5 for risk analysis
- AI analyzes raw events BEFORE normalization to capture context

## Documentation Standards

### Symbol Standards (No Emoji)
| Instead of | Use |
|------------|-----|
| Emoji checkmarks | `[x]` or `(done)` |
| Emoji warnings | `[!]` or `(warning)` |
| Emoji X marks | `[ ]` or `(no)` |

### Required Documentation
- README.md with architecture diagram
- docs/HLD.md - High-Level Design
- docs/DR-BC.md - Disaster Recovery & Business Continuity
- configs/config.example.yaml - Documented example config

## Security Guidelines

- Never store credentials in code or config files
- Use environment variables for all secrets
- Support OIDC/Workload Identity for cloud auth
- All API keys loaded via `*_ENV` config patterns

## Integration Patterns

### COTS DLP Integration
This tool aggregates from COTS DLP tools (Digital Guardian, Proofpoint, Purview, Netskope), NOT replaces them.

### EDR Integration
Ingests from CrowdStrike, SentinelOne, Defender, Carbon Black - normalizes to common schema.

### Schema Normalization
- OCSF (Open Cybersecurity Schema Framework) - default
- ECS (Elastic Common Schema) - for Elasticsearch compatibility

## Author

**Liem Vo-Nguyen**
- LinkedIn: linkedin.com/in/liemvonguyen

