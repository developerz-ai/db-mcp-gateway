# Benchmarks

Performance measurements and resource utilization for db-mcp-gateway across various deployment scenarios and query patterns.

---

## 🚧 Performance Status

**Note:** db-mcp-gateway is currently in **Phase 0 (skeleton)** - these are target benchmarks based on architectural design and Rust implementation. Actual measurements will be added as the implementation progresses.

---

## 📊 Gateway Overhead Benchmarks

### Query Latency Overhead
**Target:** <5ms additional latency vs direct database connection

**Methodology:** Measure time from gateway receiving MCP request to returning first byte, subtract pure database query time.

**Expected Results:**
```
Operation                    | Direct DB | Gateway Overhead | Target
-----------------------------|-----------|------------------|--------
Simple SELECT (1 row)        | 2ms       | <3ms             | <5ms total
Complex SELECT (1000 rows)   | 15ms      | <5ms             | <20ms total
Schema metadata              | 8ms       | <4ms             | <12ms total
Explain query                | 5ms       | <3ms             | <8ms total
```

**Architecture Factors:**
- Rust implementation with zero-cost abstractions
- Async I/O via tokio for concurrent query handling
- Prepared statements with connection pooling
- JWT validation cached per connection

---

### Concurrent Query Capacity
**Target:** 100+ simultaneous queries without performance degradation

**Methodology:** Run N concurrent queries through gateway, measure 95th percentile latency.

**Expected Results:**
```
Concurrent Queries | p50 Latency | p95 Latency | p99 Latency | Target p95
-------------------|-------------|-------------|-------------|------------
10 queries          | 8ms         | 12ms        | 18ms        | <15ms
25 queries          | 10ms        | 18ms        | 28ms        | <25ms
50 queries          | 12ms        | 25ms        | 45ms        | <35ms
100 queries         | 15ms        | 35ms        | 65ms        | <50ms
200 queries         | 20ms        | 55ms        | 120ms       | <80ms
```

**Scaling Factors:**
- Connection pooling to target databases
- Stateless gateway design enables horizontal scaling
- Postgres state database handles concurrent audit writes
- Load balancer health checks for auto-scaling decisions

---

## 🗄️ Database-Specific Performance

### PostgreSQL Performance
**Target:** <10ms gateway overhead for PostgreSQL queries

**Expected Results:**
```
Query Type              | Gateway Overhead | Total Latency | Notes
------------------------|------------------|---------------|------------------
SELECT single row       | 3ms              | +DB time      | Indexed lookups
SELECT 1000 rows       | 5ms              | +DB time      | Row limit applied
JOIN across 3 tables   | 6ms              | +DB time      | No query rewriting
Aggregate (COUNT/SUM)  | 4ms              | +DB time      | Standard aggregates
Schema introspection    | 5ms              | +DB time      | Cached metadata
```

**PostgreSQL Optimizations:**
- Prepared statements with connection pooling
- `statement_timeout` enforcement at both layers
- Read-only role enforcement without query rewriting

---

### MySQL Performance
**Target:** <12ms gateway overhead for MySQL queries

**Expected Results:**
```
Query Type              | Gateway Overhead | Total Latency | Notes
------------------------|------------------|---------------|------------------
SELECT single row       | 4ms              | +DB time      | Slightly higher than PG
SELECT 1000 rows       | 6ms              | +DB time      | Row limit applied
Schema introspection    | 6ms              | +DB time      | MySQL metadata queries
```

**MySQL-Specific Considerations:**
- Different wire protocol adds minimal overhead
- MySQL timeout enforcement via `max_execution_time`
- Read-only enforcement via ` TRANSACTION_READ_ONLY` 

---

### MongoDB Performance
**Target:** <15ms gateway overhead for MongoDB queries

**Expected Results:**
```
Query Type              | Gateway Overhead | Total Latency | Notes
------------------------|------------------|---------------|------------------
Find single document    | 5ms              | +DB time      | BSON processing overhead
Find 1000 documents    | 8ms              | +DB time      | Cursor management
Aggregation pipeline    | 7ms              | +DB time      | Pipeline pass-through
Collection introspection| 6ms             | +DB time      | List collections
```

**MongoDB-Specific Considerations:**
- BSON document processing overhead
- Cursor management for large result sets
- Read-only enforcement via database user permissions
- No MongoDB `explain` equivalent (uses native `explain`)

---

## 💻 Resource Utilization

### Gateway Container Resources
**Target:** <512MB RAM, <1 CPU core for moderate load (50 concurrent queries)

**Expected Resource Usage:**
```
Load Level              | CPU Usage | RAM Usage | Connections (per DB)
------------------------|-----------|-----------|----------------------
Idle                   | 1%        | 128MB     | 1 (maintenance)
10 concurrent queries  | 15%       | 256MB     | 5-10
50 concurrent queries  | 45%       | 384MB     | 20-30
100 concurrent queries | 85%       | 512MB     | 50-100
```

**Memory Breakdown:**
- Base Rust runtime: 80MB
- Connection pools (10 connections × 3 databases): 150MB
- JWT cache (1000 tokens): 20MB
- Query metadata cache: 50MB
- Audit log buffer: 50MB
- Overhead: 162MB

---

### State Database Resources
**Target:** <2 CPU cores, <4GB RAM for production workload

**Expected State DB Load:**
```
Operation               | Frequency | CPU Impact | Disk I/O   | Storage Growth
------------------------|-----------|------------|------------|----------------
Session lookups         | 1/query   | Low        | Random read| ~100KB/day
Audit log writes        | 1/query   | Low        | Sequential | ~50MB/day (1000 queries/day)
Health checks           | 10/sec    | Minimal    | Minimal    | Negligible
Log exports             | On-demand | Burst      | Sequential | N/A (archival)
```

**Storage Estimates:**
- Audit log: ~50KB per query (SQL + metadata)
- 1,000 queries/day = ~50MB/day = ~1.5GB/month
- Hot retention (30 days): ~45GB
- Cold retention (1 year): ~550GB (compressed in S3/GCS)

---

## 🚀 Scaling Performance

### Horizontal Scaling
**Target:** Linear performance improvement with additional gateway instances

**Expected Results:**
```
Gateway Instances | Queries/Second | p95 Latency | CPU Efficiency
------------------|----------------|-------------|-----------------
1 instance        | 200 qps        | 35ms        | 85%
2 instances       | 380 qps        | 35ms        | 82%
3 instances       | 550 qps        | 38ms        | 80%
4 instances       | 700 qps        | 40ms        | 78%
```

**Scaling Considerations:**
- Stateless gateway design enables horizontal scaling
- Load balancer health checks direct traffic away from unhealthy instances
- Shared state database coordinates across instances
- No session affinity required (JWT tokens stateless)

---

### Database Connection Pooling
**Target:** 10 connections per database per gateway instance (configurable)

**Pool Efficiency:**
```
Connections per DB | Pool Efficiency | Max Throughput | Idle Connection Cost
-------------------|-----------------|-----------------|---------------------
5 connections      | 95%             | 150 qps         | Minimal
10 connections     | 98%             | 300 qps         | Low
20 connections     | 99%             | 500 qps         | Moderate
```

**Pool Configuration:**
- Min connections: 2 (always warm)
- Max connections: 10 (per gateway instance)
- Connection timeout: 30 seconds
- Idle connection timeout: 600 seconds

---

## 🔒 Security Feature Overhead

### JWT Validation Performance
**Target:** <1ms per token validation

**Expected Results:**
```
Operation              | Time    | Cache Hit Rate
------------------------|---------|----------------
Fresh token validation  | 0.8ms   | N/A
Cached token lookup    | 0.1ms   | 95%+
Group membership check | 0.2ms   | 98%+
Permission evaluation  | 0.3ms   | 99%+
```

**Caching Strategy:**
- JWT validation cached per token (8-hour lifetime)
- Group memberships cached per user (1-hour TTL)
- Permission grants cached in memory (refresh on config change)

---

### Audit Log Performance
**Target:** <5ms per audit log write

**Expected Results:**
```
Operation              | Time    | Backend      | Throughput
------------------------|---------|--------------|------------
Single audit write      | 3ms     | Postgres     | 300 writes/sec
Batch audit write (10)  | 8ms     | Postgres     | 1000 writes/sec
Async export to S3      | 50ms    | Background   | Non-blocking
SIEM export (OTLP)      | 20ms    | Async        | Non-blocking
```

**Audit Optimization:**
- Append-only writes for maximum throughput
- Async export to cloud storage (query doesn't wait)
- Batch writes when possible (high-load scenarios)
- Hot data in Postgres, cold data in cloud storage

---

## 📈 Performance vs. Alternative Solutions

### vs Direct Database Access
**Trade-off:** Security and compliance vs minimal latency

```
Approach               | Latency | Security | Audit | Compliance
-----------------------|---------|----------|-------|------------
Direct DB access       | 0ms     | ❌       | ❌    | ❌
db-mcp-gateway         | +5ms    | ✅       | ✅    | ✅
```

**Analysis:** 5ms overhead for enterprise-grade security and complete audit compliance

---

### vs Custom MCP Implementations
**Trade-off:** Maintenance burden vs optimized performance

```
Approach               | Latency | Maintenance | Features | Security
-----------------------|---------|-------------|----------|----------
Custom MCP wrapper     | 2ms     | High        | Limited  | Ad-hoc
db-mcp-gateway         | 5ms     | Low         | Complete | Production
```

**Analysis:** 3ms additional overhead for maintained, feature-complete, production-ready solution

---

### vs ProxySQL (for MySQL)
**Trade-off:** General-purpose vs AI-agent-optimized

```
Approach               | Latency | AI Attribution | MCP Interface | Config
-----------------------|---------|----------------|----------------|--------
ProxySQL               | 2ms     | ❌            | ❌             | Complex
db-mcp-gateway         | 5ms     | ✅            | ✅             | YAML
```

**Analysis:** Purpose-built for AI agents with user attribution and MCP protocol

---

## 🎯 Performance Targets Summary

**Primary Goals:**
- **Gateway Overhead:** <5ms per query
- **Concurrent Capacity:** 100+ simultaneous queries
- **Resource Efficiency:** <512MB RAM, <1 CPU core per 50 concurrent queries
- **Horizontal Scaling:** Linear performance improvement

**Enterprise Features:**
- **JWT Validation:** <1ms with 95%+ cache hit rate
- **Audit Logging:** <5ms synchronous write, async archiving
- **Multi-Database:** <15ms overhead for MongoDB, <10ms for PostgreSQL

**Production Readiness:**
- **Health Check Response:** <100ms
- **Config Reload:** <1 second without query interruption
- **Graceful Degradation:** Continue serving queries if state DB is slow

---

## 🧪 Benchmarking Methodology

**How to Reproduce:**

When implementation is complete, benchmarks will use:

```bash
# Gateway overhead benchmark
./benchmarks/gateway_overhead.sh \
  --queries 1000 \
  --concurrent 50 \
  --database postgresql

# Database-specific benchmarks
./benchmarks/database_comparison.sh \
  --databases postgresql,mongodb \
  --query-types simple,complex,schema

# Resource utilization
./benchmarks/resource_usage.sh \
  --duration 300 \
  --load-level 100
```

**Testing Environment:**
- Database: PostgreSQL 14+, MySQL 8+, MongoDB 5+
- Gateway: Single Docker container, 1 CPU core, 1GB RAM
- Network: Local Docker network (no network latency)
- Measurements: Median, p95, p99 latencies

**Status:** Benchmarks will be populated as implementation progresses through Phase 1 and Phase 2 milestones.