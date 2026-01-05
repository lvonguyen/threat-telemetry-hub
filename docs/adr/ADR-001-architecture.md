# ADR-001: Architecture Pattern Selection

## Status

Accepted

## Date

2026-01-05

## Context

We need to design an architecture for Threat Telemetry Hub that:
- Ingests high-volume security events from multiple sources (EDR, SIEM, cloud)
- Normalizes events to a common schema
- Applies AI-powered analysis for contextual risk
- Correlates events across sources
- Outputs to ticketing and notification systems

### Requirements

- Handle 10,000+ events per second peak
- Sub-minute end-to-end latency for critical events
- Support for multiple collector types
- Pluggable enrichment and output providers
- High availability and fault tolerance

## Decision

We will implement a **streaming pipeline architecture** with the following stages:

1. **Ingestion** - Collectors pull from sources
2. **Normalization** - Transform to common schema
3. **AI Analysis** - Add contextual risk scoring
4. **Enrichment** - Add threat intel, asset context
5. **Correlation** - Group related events
6. **Output** - Send to ticketing, SIEM, alerts

## Architecture Diagram

```
+---------------+    +--------------+    +----------+
| EDR Collector |--->|              |    |          |
+---------------+    | Ingestion    |--->| Norm-    |
| SIEM Collector|--->| Manager      |    | alization|
+---------------+    +--------------+    +----+-----+
| Cloud Collect |                             |
+---------------+                             v
                                       +------+------+
                                       | AI Analysis |
                                       | (Opus 4.5)  |
                                       +------+------+
                                              |
        +----------------+--------------------+
        |                |                    |
        v                v                    v
+-------+----+   +-------+------+    +-------+------+
| Enrichment |   | Correlation  |    | Output       |
| (TI, Assets)|   | Engine       |    | (SNOW,Archer)|
+------------+   +--------------+    +--------------+
```

## Rationale

### Why Streaming vs Batch

| Factor | Streaming | Batch |
|--------|-----------|-------|
| Latency | Sub-second | Minutes to hours |
| Alerting | Real-time | Delayed |
| Resource usage | Continuous | Bursty |
| Complexity | Higher | Lower |

**Decision**: Streaming for real-time threat detection, with batch for historical analysis.

### Why In-Process vs Message Queue

For initial version, we use in-process channels rather than external message queue:
- Simpler deployment
- Lower latency
- Sufficient for initial scale

**Future**: Add Kafka/NATS when horizontal scaling required.

### AI Integration Point

AI analysis is placed after normalization because:
- Consistent input format for prompts
- Reduced token usage (normalized vs raw)
- Batch efficiency (analyze multiple events together)

## Components

### Ingestion Manager
- Manages collector lifecycle
- Handles credential rotation
- Implements rate limiting per source

### Normalizer
- Maps source-specific schemas to common format
- Validates required fields
- Handles schema evolution

### AI Analyzer
- Primary: Anthropic Claude Opus 4.5
- Fallback: OpenAI GPT-4
- Caches responses for similar events

### Enricher
- Threat intelligence (MISP, VirusTotal)
- Asset context (CMDB integration)
- GeoIP for network events

### Correlator
- Time-window correlation
- Entity linking (IP, hostname, user)
- Attack chain detection

### Output Manager
- Prioritized output queue
- Retry with backoff
- Deduplication

## Consequences

### Positive
- Real-time threat detection
- Extensible plugin architecture
- Clear separation of concerns
- AI-powered analysis

### Negative
- More complex than batch processing
- In-memory queues require careful sizing
- AI costs scale with event volume

### Mitigations
- Add backpressure handling
- Cache AI responses
- Implement graceful degradation

## Related Decisions

- ADR-002: AI Provider Selection
- ADR-003: Event Schema Design
- ADR-004: Output Provider Interface

