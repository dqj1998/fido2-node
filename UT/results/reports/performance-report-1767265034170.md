# FIDO2-Node Performance Test Report

**Generated:** 1/1/2026, 7:57:14 PM

---

## Overview

This report contains detailed performance test results for the fido2-node FIDO2 authentication server. Tests measure response times for registration and authentication operations under various load conditions.

## Test Environment

| Property | Value |
|----------|-------|
| Timestamp | 2026-01-01T10:57:14.147Z |
| Platform | darwin |
| Node Version | v22.14.0 |
| Database Type | Mock with configurable delays |
| Database Delays | Query: 10ms, Insert: 15ms, Update: 12ms, Select: 8ms |

---

## Executive Summary

### Registration Performance
- **Pre-Register Average:** 16.06ms
- **Register Average:** 34.45ms
- **Operations Tested:** 3

### Authentication Performance
- **Pre-Authenticate Average:** 25.21ms
- **Authenticate Average:** 38.26ms
- **Operations Tested:** 3

---

## Registration Performance

### Operation Timings

| Operation | Iterations | Min (ms) | Max (ms) | Avg (ms) | P50 (ms) | P95 (ms) | P99 (ms) |
|-----------|-----------|---------|---------|---------|---------|---------|----------|
| preRegister | 100 | 15.22 | 16.84 | 16.06 | 16.12 | 16.32 | 16.84 |
| register | 50 | 30.83 | 85.30 | 34.45 | 32.31 | 58.93 | 85.30 |
| excludeCredentials_query | 100 | 7.93 | 9.37 | 9.03 | N/A | 9.25 | N/A |

---

## Authentication Performance

### Operation Timings

| Operation | Iterations | Min (ms) | Max (ms) | Avg (ms) | P50 (ms) | P95 (ms) | P99 (ms) |
|-----------|-----------|---------|---------|---------|---------|---------|----------|
| preAuthenticate | 100 | 24.06 | 26.77 | 25.21 | 25.37 | 26.19 | 26.77 |
| authenticate | 50 | 37.01 | 39.21 | 38.26 | 38.33 | 39.00 | 39.21 |
| counter_update | 100 | 12.10 | 16.38 | 13.12 | N/A | 13.41 | N/A |

### Performance vs Credential Count

| Credential Count | Avg (ms) | Min (ms) | Max (ms) | P95 (ms) |
|-----------------|---------|---------|---------|----------|
| 1 | 9.04 | 7.71 | 11.56 | 9.38 |
| 5 | 9.01 | 7.22 | 10.82 | 9.23 |
| 10 | 9.05 | 8.04 | 9.92 | 9.33 |
| 20 | 9.10 | 8.24 | 10.07 | 9.43 |

---

## Concurrency and Load Testing

### Concurrent Registration Requests

| Concurrency | Avg (ms) | Min (ms) | Max (ms) | P50 (ms) | P95 (ms) | P99 (ms) | Max Active Connections |
|-------------|---------|---------|---------|---------|---------|---------|------------------------|
| 10 | 32.37 | 32.34 | 32.45 | 32.35 | 32.45 | 32.45 | 9 |
| 25 | 12.88 | 0.00 | 32.23 | 0.00 | 32.23 | 32.23 | 9 |
| 50 | 6.41 | 0.00 | 32.07 | 0.00 | 32.07 | 32.07 | 9 |

### Concurrent Authentication Requests

| Concurrency | Avg (ms) | Min (ms) | Max (ms) | P50 (ms) | P95 (ms) | P99 (ms) |
|-------------|---------|---------|---------|---------|---------|----------|
| 10 | 22.41 | 22.32 | 22.55 | 22.46 | 22.55 | 22.55 |
| 25 | 8.84 | 0.00 | 22.14 | 0.00 | 22.12 | 22.14 |
| 50 | 5.19 | 0.00 | 26.06 | 0.00 | 26.04 | 26.06 |

### Mixed Operations (Registration + Authentication)

- **Total Concurrent Requests:** 40
- **Registrations:** 10 requests, avg 24.38ms
- **Authentications:** 0 requests, avg 0.00ms

### Connection Pool Stress Test

- **Pool Size:** 10 connections
- **Total Requests:** 15
- **Completed:** 15
- **Pool Exhaustion Events:** 0
- **Average Response Time:** 14.41ms

### Throughput Measurement

| Load Profile | Concurrency | Duration (ms) | Requests | Throughput (RPS) |
|--------------|-------------|--------------|----------|------------------|
| light | 10 | 1001 | 600 | 599.24 |
| medium | 25 | 1002 | 590 | 588.64 |
| heavy | 50 | 1002 | 450 | 449.11 |

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
