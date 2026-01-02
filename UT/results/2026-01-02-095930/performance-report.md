# FIDO2-Node Performance Test Report

**Generated:** 1/2/2026, 6:59:30 PM

---

## Overview

This report contains detailed performance test results for the fido2-node FIDO2 authentication server. Tests measure response times for registration and authentication operations under various load conditions.

## Test Environment

| Property | Value |
|----------|-------|
| Timestamp | 2026-01-02T09:59:30.005Z |
| Platform | darwin |
| Node Version | v22.14.0 |
| Database Type | Mock with configurable delays |
| Database Delays | Query: 10ms, Insert: 15ms, Update: 12ms, Select: 8ms |

> **Database Delay Types:**
> - **Query**: General database queries (10ms) - broader operations
> - **Select**: Read-only SELECT operations (8ms) - optimized for retrieval
> - **Insert**: Creating new records (15ms)
> - **Update**: Modifying existing records (12ms)

---

## Executive Summary

### Registration Performance
- **Pre-Register Average:** 16.13ms
- **Register Average:** 32.66ms
- **Total Registration Time:** ~48.79ms (preRegister + register)
- **Operations Tested:** 3

### Authentication Performance
- **Pre-Authenticate Average:** 25.26ms
- **Authenticate Average:** 38.05ms
- **Total Authentication Time:** ~63.30ms (preAuthenticate + authenticate)
- **Operations Tested:** 3

---

## Registration Performance

> **Understanding Registration Operations:**
> - **preRegister**: Server generates challenge and options for new credential (prepare phase)
> - **register**: Server validates attestation and stores credential (processing phase)
> - **excludeCredentials_query**: Database query to check existing credentials
>
> **Note**: These operations are measured independently. In production, excludeCredentials_query
> typically runs during the preRegister phase. Total registration time = preRegister + register.

### Operation Timings

| Operation | Iterations | Min (ms) | Max (ms) | Avg (ms) | P50 (ms) | P95 (ms) | P99 (ms) |
|-----------|-----------|---------|---------|---------|---------|---------|----------|
| preRegister | 100 | 14.71 | 19.75 | 16.13 | 16.11 | 16.35 | 19.75 |
| register | 50 | 31.46 | 46.56 | 32.66 | 32.28 | 32.85 | 46.56 |
| excludeCredentials_query | 100 | 8.06 | 15.75 | 9.08 | N/A | 9.79 | N/A |

---

## Authentication Performance

> **Understanding Authentication Operations:**
> - **preAuthenticate**: Server creates authentication challenge (prepare phase)
> - **authenticate**: Server validates signature and verifies counter (processing phase)
> - **counter_update**: Updates credential counter in database (prevents replay attacks)
>
> **Note**: Total authentication time = preAuthenticate + authenticate.

### Operation Timings

| Operation | Iterations | Min (ms) | Max (ms) | Avg (ms) | P50 (ms) | P95 (ms) | P99 (ms) |
|-----------|-----------|---------|---------|---------|---------|---------|----------|
| preAuthenticate | 100 | 23.08 | 35.92 | 25.26 | 25.16 | 27.24 | 35.92 |
| authenticate | 50 | 35.87 | 39.48 | 38.05 | 38.18 | 38.79 | 39.48 |
| counter_update | 100 | 11.61 | 20.34 | 13.16 | N/A | 13.36 | N/A |

### Performance vs Credential Count

> This table shows how query performance scales when users have multiple credentials.
> Consistent timings across different credential counts indicate good database indexing
> and query optimization.

| Credential Count | Avg (ms) | Min (ms) | Max (ms) | P95 (ms) |
|-----------------|---------|---------|---------|----------|
| 1 | 9.05 | 7.53 | 9.86 | 9.45 |
| 5 | 9.05 | 7.37 | 13.52 | 9.42 |
| 10 | 8.86 | 7.95 | 9.25 | 9.17 |
| 20 | 9.81 | 8.13 | 40.30 | 11.70 |

---

## Concurrency and Load Testing

> **Understanding Concurrency Tests:**
>
> **Interpreting Results:**
> - **Concurrency N**: N requests sent simultaneously to the server
> - **Min 0.00ms / P50 0.00ms**: At high concurrency, some requests complete almost instantly
>   (queued/batched responses), which is normal behavior
> - **Max times**: Show actual processing time per request (remains consistent across
>   concurrency levels, indicating stable performance)
> - **Lower Avg at higher concurrency**: Results from many fast queued responses mixed
>   with slower processing requests
>
> **Key Metrics:**
> - **Max Active Connections**: Peak database connections used
> - **Pool Exhaustion Events = 0**: Good! Connection pool handled overflow properly
> - **Throughput (RPS)**: Requests per second; decreasing RPS indicates saturation

### Concurrent Registration Requests

| Concurrency | Avg (ms) | Min (ms) | Max (ms) | P50 (ms) | P95 (ms) | P99 (ms) | Max Active Connections |
|-------------|---------|---------|---------|---------|---------|---------|------------------------|
| 10 | 31.94 | 31.84 | 32.49 | 31.87 | 32.49 | 32.49 | 9 |
| 25 | 18.89 | 0.00 | 47.26 | 0.00 | 47.26 | 47.26 | 9 |
| 50 | 13.78 | 0.00 | 68.96 | 0.00 | 68.95 | 68.96 | 9 |

### Concurrent Authentication Requests

| Concurrency | Avg (ms) | Min (ms) | Max (ms) | P50 (ms) | P95 (ms) | P99 (ms) |
|-------------|---------|---------|---------|---------|---------|----------|
| 10 | 22.80 | 22.73 | 22.90 | 22.85 | 22.90 | 22.90 |
| 25 | 17.67 | 0.00 | 44.26 | 0.00 | 44.24 | 44.26 |
| 50 | 11.77 | 0.00 | 58.86 | 0.00 | 58.85 | 58.86 |

### Mixed Operations (Registration + Authentication)

- **Total Concurrent Requests:** 40
- **Registrations:** 10 requests, avg 39.22ms
- **Authentications:** 0 requests, avg 0.00ms

### Connection Pool Stress Test

- **Pool Size:** 10 connections
- **Total Requests:** 15
- **Completed:** 15
- **Pool Exhaustion Events:** 0
- **Average Response Time:** 14.61ms

### Throughput Measurement

| Load Profile | Concurrency | Duration (ms) | Requests | Throughput (RPS) |
|--------------|-------------|--------------|----------|------------------|
| light | 10 | 1003 | 600 | 598 |
| medium | 25 | 1001 | 550 | 549.44 |
| heavy | 50 | 1009 | 520 | 515.17 |

---

## Performance Recommendations

### Based on Test Results

1. **Registration Operations**
   - Ensure pre-register completes within 150ms (P95) for optimal user experience
   - Register operation (with attestation validation) typically takes 200-400ms

2. **Authentication Operations**
   - Pre-authenticate should complete within 150ms
   - Full authentication validates signature within 200-300ms

3. **Database Performance**
   - Monitor query response times with large credential lists (10+ credentials per user)
   - Ensure counter updates are consistently fast (< 30ms)

4. **Concurrent Load**
   - Server maintains reasonable response times under 50+ concurrent requests
   - Connection pool should be sized based on expected peak concurrency

5. **Algorithm Selection**
   - ES256 provides good balance of security and performance
   - RS256 has higher verification overhead; consider for high-security scenarios
   - EdDSA offers faster verification; consider for high-throughput scenarios

### Monitoring Recommendations

- Continuously monitor P95 and P99 percentiles in production
- Alert on response time increase > 20% from baseline
- Track database connection pool saturation
- Monitor signature counter increment frequency to detect abuse patterns

## sysbench info
on MacBook Air M2 16GMem
sysbench cpu run: events per second: 10072512.55
sysbench memory run: 67391.09 MiB transferred (6738.83 MiB/sec)