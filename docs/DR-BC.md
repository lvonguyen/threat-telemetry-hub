# Threat Telemetry Hub - Disaster Recovery & Business Continuity

**Version:** 1.0
**Author:** Liem Vo-Nguyen
**Last Updated:** January 2026

---

## Executive Summary

This document outlines the Disaster Recovery (DR) and Business Continuity (BC) strategy for Threat Telemetry Hub across AWS, Azure, and GCP deployments. The architecture is designed to avoid vendor lock-in while maintaining enterprise-grade resilience.

---

## Recovery Objectives

| Metric | Target | Description |
|--------|--------|-------------|
| **RTO** (Recovery Time Objective) | 4 hours | Maximum acceptable downtime |
| **RPO** (Recovery Point Objective) | 15 minutes | Maximum acceptable data loss |
| **MTTR** (Mean Time to Recovery) | 2 hours | Average time to restore service |

---

## Service Criticality Classification

| Component | Criticality | RTO | RPO | Notes |
|-----------|-------------|-----|-----|-------|
| Ingestion Pipeline | Critical | 1 hour | 5 min | Events are buffered in source systems |
| AI Analysis Engine | High | 2 hours | 15 min | Can process backlog on recovery |
| Normalization Layer | Critical | 1 hour | 5 min | Core processing function |
| Enrichment Services | Medium | 4 hours | 30 min | Degraded mode acceptable |
| Correlation Engine | High | 2 hours | 15 min | State can be rebuilt |
| Web Dashboard | Low | 8 hours | N/A | Read-only, can use CLI |
| API Gateway | Critical | 1 hour | N/A | Stateless, fast recovery |

---

## Multi-Cloud DR Architecture

### Option 1: AWS Primary

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        AWS Primary (us-west-2)                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
│  │     EKS      │  │     RDS      │  │      S3      │                   │
│  │  (3 nodes)   │  │  (Multi-AZ)  │  │  (Versioned) │                   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                   │
│         │                 │                 │                            │
│         └─────────────────┼─────────────────┘                            │
│                           │                                              │
│                    Cross-Region Replication                              │
│                           │                                              │
└───────────────────────────┼──────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      AWS DR (us-east-1)                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
│  │  EKS (Cold)  │  │  RDS Replica │  │   S3 Copy    │                   │
│  │  (0 nodes)   │  │  (Read-only) │  │  (Replicated)│                   │
│  └──────────────┘  └──────────────┘  └──────────────┘                   │
│                                                                          │
│  * Nodes scaled to 0 in standby                                         │
│  * RDS promoted on failover                                              │
│  * S3 becomes primary bucket                                             │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**AWS DR Components:**
- EKS: Cluster exists but scaled to 0 nodes (cost: ~$75/mo for control plane)
- RDS: Read replica with automated promotion
- S3: Cross-region replication enabled
- Route 53: Health checks with automatic failover
- Secrets Manager: Multi-region secrets replication

---

### Option 2: Azure Primary

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Azure Primary (West US 2)                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
│  │     AKS      │  │ Azure SQL    │  │    Blob      │                   │
│  │  (3 nodes)   │  │  (HA config) │  │    (GRS)     │                   │
│  └──────────────┘  └──────────────┘  └──────────────┘                   │
│                                                                          │
│              Azure Site Recovery / Geo-Replication                       │
│                                                                          │
└───────────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       Azure DR (East US)                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
│  │  AKS (Cold)  │  │ SQL Replica  │  │  Blob (GRS)  │                   │
│  │  (0 nodes)   │  │ (Failover)   │  │  (Secondary) │                   │
│  └──────────────┘  └──────────────┘  └──────────────┘                   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Azure DR Components:**
- AKS: Cluster with 0 nodes in standby
- Azure SQL: Geo-replication with automatic failover groups
- Blob Storage: GRS (Geo-Redundant Storage)
- Traffic Manager: Global load balancing with health probes
- Key Vault: Geo-replication for secrets

---

### Option 3: GCP Primary

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       GCP Primary (us-west1)                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
│  │     GKE      │  │  Cloud SQL   │  │     GCS      │                   │
│  │  (3 nodes)   │  │  (HA config) │  │  (Dual-reg)  │                   │
│  └──────────────┘  └──────────────┘  └──────────────┘                   │
│                                                                          │
└───────────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        GCP DR (us-east1)                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
│  │  GKE (Cold)  │  │ SQL Replica  │  │  GCS (Dual)  │                   │
│  │  (0 nodes)   │  │  (Regional)  │  │  (Replicated)│                   │
│  └──────────────┘  └──────────────┘  └──────────────┘                   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**GCP DR Components:**
- GKE: Autopilot cluster scaled to 0
- Cloud SQL: Regional HA with cross-region replica
- GCS: Dual-region or multi-region bucket
- Cloud DNS: Global load balancing
- Secret Manager: Automatic replication

---

### Option 4: Cross-Cloud DR (Recommended for Vendor Lock-in Avoidance)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       Primary (Any Cloud)                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────┐           │
│  │              Kubernetes (EKS/AKS/GKE)                    │           │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │           │
│  │  │ Hub Service │  │    Redis    │  │  Postgres   │      │           │
│  │  └─────────────┘  └─────────────┘  └─────────────┘      │           │
│  └──────────────────────────────────────────────────────────┘           │
│                                                                          │
│  External Backup: S3/GCS/Blob (cross-cloud)                             │
│  Velero for K8s backup/restore                                           │
│                                                                          │
└───────────────────────────────────────────────────────────────────────────┘
                            │
                    Velero Backup + DB Dump
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    DR (Different Cloud)                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────┐           │
│  │              Kubernetes (Different Provider)             │           │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │           │
│  │  │ Hub Service │  │    Redis    │  │  Postgres   │      │           │
│  │  │  (Standby)  │  │  (Standby)  │  │  (Restored) │      │           │
│  │  └─────────────┘  └─────────────┘  └─────────────┘      │           │
│  └──────────────────────────────────────────────────────────┘           │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Cross-Cloud DR Strategy:**
- Velero: Kubernetes cluster backup to cloud-agnostic storage
- PostgreSQL: pg_dump to object storage, restore to any cloud
- Redis: RDB snapshots to object storage
- Container images: Multi-cloud registry (e.g., GHCR, or replicate to each cloud)
- Terraform: Same IaC works across clouds with provider switch

---

## Backup Strategy

### Database Backups

| Database | Method | Frequency | Retention | Location |
|----------|--------|-----------|-----------|----------|
| PostgreSQL | Automated snapshots | Every 15 min | 7 days | Same region |
| PostgreSQL | Daily full backup | Daily 2 AM | 30 days | Cross-region |
| PostgreSQL | Weekly archive | Weekly | 1 year | Cross-cloud |
| Redis | RDB snapshot | Every 15 min | 24 hours | Same region |

### Application Backups

| Component | Method | Frequency | Retention |
|-----------|--------|-----------|-----------|
| Kubernetes state | Velero | Every 6 hours | 7 days |
| Configuration | GitOps (ArgoCD) | Real-time | Infinite (Git) |
| Secrets | Vault/Secret Manager | Real-time | 30 days |

---

## Failover Procedures

### Automated Failover (RTO: 15-30 minutes)

**Trigger Conditions:**
- Primary region health check fails for 3 consecutive checks (5 min)
- Database connection failure for 5+ minutes
- Kubernetes API unavailable for 5+ minutes

**Automated Steps:**
1. DNS/Load balancer switches traffic to DR region
2. Database replica promoted to primary
3. K8s pods scaled up in DR region
4. Notification sent to on-call team

### Manual Failover (RTO: 2-4 hours)

**When to Use:**
- Planned maintenance
- Partial failures
- Security incident requiring isolation

**Procedure:**
1. Notify stakeholders of planned failover
2. Stop ingestion in primary (graceful drain)
3. Verify DR database is synchronized
4. Promote DR database to primary
5. Scale up DR Kubernetes cluster
6. Update DNS/load balancer
7. Verify service health
8. Resume ingestion
9. Document in incident log

### Rollback Procedure

1. Verify primary region is healthy
2. Stop writes to DR database
3. Sync any DR-only data back to primary
4. Scale down DR region
5. Update DNS/load balancer to primary
6. Verify service health
7. Scale to 0 in DR region

---

## Quarterly DR Testing Protocol

### Test Schedule

| Quarter | Test Type | Scope | Duration |
|---------|-----------|-------|----------|
| Q1 | Tabletop exercise | Full | 2 hours |
| Q2 | Partial failover | Database only | 4 hours |
| Q3 | Full failover | Complete DR | 8 hours |
| Q4 | Chaos engineering | Random failures | 4 hours |

### Q1: Tabletop Exercise

**Participants:** Engineering, Security, Operations, Leadership

**Agenda:**
1. Review DR documentation (30 min)
2. Walk through failover scenarios (45 min)
3. Identify gaps and update procedures (30 min)
4. Action items and ownership (15 min)

**Success Criteria:**
- [ ] All participants understand their roles
- [ ] Documentation is current and accurate
- [ ] Contact lists are up to date
- [ ] Runbooks are accessible

### Q2: Database Failover Test

**Scope:** Database replication and promotion only

**Steps:**
1. Schedule maintenance window (4 hours)
2. Notify stakeholders
3. Trigger database failover
4. Verify data integrity
5. Run application smoke tests
6. Fail back to primary
7. Document results

**Success Criteria:**
- [ ] RPO met (< 15 min data loss)
- [ ] Failover completed within 30 minutes
- [ ] All data integrity checks pass
- [ ] Application functions correctly

### Q3: Full Failover Test

**Scope:** Complete region failover

**Steps:**
1. Schedule maintenance window (8 hours)
2. Notify all stakeholders
3. Execute full failover procedure
4. Verify all services operational
5. Run full test suite
6. Operate from DR for 2+ hours
7. Execute rollback procedure
8. Verify primary region operational
9. Document lessons learned

**Success Criteria:**
- [ ] RTO met (< 4 hours)
- [ ] RPO met (< 15 min data loss)
- [ ] All services operational in DR
- [ ] Rollback successful
- [ ] No data loss during test

### Q4: Chaos Engineering

**Scope:** Random failure injection

**Tools:** Chaos Monkey, Litmus, Gremlin

**Scenarios:**
1. Random pod termination
2. Network partition simulation
3. Database connection pool exhaustion
4. Memory/CPU stress
5. DNS resolution failure

**Success Criteria:**
- [ ] System self-heals from failures
- [ ] Alerts fire appropriately
- [ ] No data loss
- [ ] Recovery within defined thresholds

---

## SLA Definitions

### Uptime SLA

| Tier | Uptime | Monthly Downtime |
|------|--------|------------------|
| Gold | 99.9% | 43.8 minutes |
| Silver | 99.5% | 3.65 hours |
| Bronze | 99.0% | 7.3 hours |

**Threat Telemetry Hub Target:** Gold (99.9%)

### Acceptable Downtime Windows

| Window Type | Frequency | Duration | Notice |
|-------------|-----------|----------|--------|
| Planned maintenance | Monthly | 2 hours | 7 days |
| Emergency patch | As needed | 1 hour | 4 hours |
| DR test | Quarterly | 4 hours | 14 days |

---

## Communication Plan

### Escalation Matrix

| Severity | Response Time | Notification |
|----------|---------------|--------------|
| Critical (P1) | 15 minutes | PagerDuty -> Phone |
| High (P2) | 30 minutes | PagerDuty -> Slack |
| Medium (P3) | 2 hours | Email + Slack |
| Low (P4) | Next business day | Email |

### Stakeholder Communication

| Event | Audience | Channel | Template |
|-------|----------|---------|----------|
| Failover started | Engineering, Ops | Slack #incidents | DR-001 |
| Failover complete | All stakeholders | Email | DR-002 |
| Service restored | All stakeholders | Email + Slack | DR-003 |
| Post-mortem | Engineering, Leadership | Meeting + Doc | DR-004 |

---

## Cost Analysis

### DR Infrastructure Costs (Monthly)

| Component | AWS | Azure | GCP |
|-----------|-----|-------|-----|
| K8s control plane (standby) | $75 | $0* | $75 |
| Database replica | $150 | $140 | $130 |
| Storage replication | $25 | $25 | $20 |
| Network egress | $50 | $50 | $40 |
| **Total DR Overhead** | **$300** | **$215** | **$265** |

*Azure AKS control plane is free

### Cross-Cloud DR Additional Costs

| Item | Monthly Cost |
|------|--------------|
| Velero storage | $50 |
| Cross-cloud egress | $100 |
| Secondary container registry | $20 |
| **Total** | **$170** |

---

## Appendix

### A. Runbook Links

- [Failover Runbook](runbooks/failover.md)
- [Rollback Runbook](runbooks/rollback.md)
- [Database Promotion](runbooks/database-promotion.md)
- [Verification Checklist](runbooks/verification.md)

### B. Contact List

| Role | Name | Phone | Email |
|------|------|-------|-------|
| Primary On-Call | TBD | TBD | TBD |
| Secondary On-Call | TBD | TBD | TBD |
| Engineering Lead | TBD | TBD | TBD |
| Cloud Provider Support | N/A | See portal | See portal |

### C. Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | Jan 2026 | Liem Vo-Nguyen | Initial release |

---

## Author

**Liem Vo-Nguyen**
- LinkedIn: linkedin.com/in/liemvonguyen
- Email: liem@vonguyen.io

