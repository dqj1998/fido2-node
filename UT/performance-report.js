/**
 * Performance Report Generator
 * Aggregates test results and generates structured reports (JSON and Markdown)
 */

const fs = require('fs');
const path = require('path');

class PerformanceReportGenerator {
  constructor(resultsDir = '/Users/dqj/HDD/fido2Prjs/fido2-node/UT/results') {
    this.resultsDir = resultsDir;
    this.reportDir = path.join(resultsDir, 'reports');
    this.timestamp = new Date().toISOString();
    this.results = {
      registration: null,
      authentication: null,
      concurrency: null
    };

    if (!fs.existsSync(this.reportDir)) {
      fs.mkdirSync(this.reportDir, { recursive: true });
    }
  }

  /**
   * Load all result files
   */
  loadResults() {
    const files = {
      'register.results.json': 'registration',
      'authenticate.results.json': 'authentication',
      'concurrency.results.json': 'concurrency'
    };

    for (const [filename, key] of Object.entries(files)) {
      const filepath = path.join(this.resultsDir, filename);
      if (fs.existsSync(filepath)) {
        try {
          this.results[key] = JSON.parse(fs.readFileSync(filepath, 'utf8'));
        } catch (error) {
          console.warn(`Failed to load ${filename}:`, error.message);
        }
      }
    }
  }

  /**
   * Generate comprehensive JSON report
   */
  generateJSONReport() {
    const report = {
      metadata: {
        timestamp: this.timestamp,
        generatedAt: new Date().toLocaleString(),
        platform: process.platform,
        nodeVersion: process.version
      },
      summary: this._generateSummary(),
      registration: this.results.registration,
      authentication: this.results.authentication,
      concurrency: this.results.concurrency
    };

    const reportPath = path.join(this.reportDir, `performance-report-${Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`JSON report saved: ${reportPath}`);

    return report;
  }

  /**
   * Generate Markdown report
   */
  generateMarkdownReport() {
    let markdown = '';

    markdown += this._generateMarkdownHeader();
    markdown += this._generateMetadataSection();
    markdown += this._generateSummarySection();
    markdown += this._generateRegistrationSection();
    markdown += this._generateAuthenticationSection();
    markdown += this._generateConcurrencySection();
    markdown += this._generateRecommendationsSection();

    const reportPath = path.join(this.reportDir, `performance-report-${Date.now()}.md`);
    fs.writeFileSync(reportPath, markdown);
    console.log(`Markdown report saved: ${reportPath}`);

    return markdown;
  }

  /**
   * Generate summary statistics
   * @private
   */
  _generateSummary() {
    const summary = {
      registration: null,
      authentication: null,
      concurrency: null
    };

    if (this.results.registration && this.results.registration.length > 0) {
      const regResults = this.results.registration.filter(r => r.operation && !r.type);
      if (regResults.length > 0) {
        summary.registration = {
          operationCount: regResults.length,
          preRegisterAvg: regResults.find(r => r.operation === 'preRegister')?.avg || null,
          registerAvg: regResults.find(r => r.operation === 'register')?.avg || null
        };
      }
    }

    if (this.results.authentication && this.results.authentication.length > 0) {
      const authResults = this.results.authentication.filter(r => r.operation && !r.type);
      if (authResults.length > 0) {
        summary.authentication = {
          operationCount: authResults.length,
          preAuthenticateAvg: authResults.find(r => r.operation === 'preAuthenticate')?.avg || null,
          authenticateAvg: authResults.find(r => r.operation === 'authenticate')?.avg || null
        };
      }
    }

    return summary;
  }

  /**
   * Generate Markdown header
   * @private
   */
  _generateMarkdownHeader() {
    return `# FIDO2-Node Performance Test Report

**Generated:** ${new Date().toLocaleString()}

---

## Overview

This report contains detailed performance test results for the fido2-node FIDO2 authentication server. Tests measure response times for registration and authentication operations under various load conditions.

`;
  }

  /**
   * Generate metadata section
   * @private
   */
  _generateMetadataSection() {
    return `## Test Environment

| Property | Value |
|----------|-------|
| Timestamp | ${this.timestamp} |
| Platform | ${process.platform} |
| Node Version | ${process.version} |
| Database Type | Mock with configurable delays |
| Database Delays | Query: 10ms, Insert: 15ms, Update: 12ms, Select: 8ms |

---

`;
  }

  /**
   * Generate summary section
   * @private
   */
  _generateSummarySection() {
    let markdown = '## Executive Summary\n\n';

    const summary = this._generateSummary();

    if (summary.registration) {
      markdown += `### Registration Performance\n`;
      markdown += `- **Pre-Register Average:** ${summary.registration.preRegisterAvg?.toFixed(2)}ms\n`;
      markdown += `- **Register Average:** ${summary.registration.registerAvg?.toFixed(2)}ms\n`;
      markdown += `- **Operations Tested:** ${summary.registration.operationCount}\n\n`;
    }

    if (summary.authentication) {
      markdown += `### Authentication Performance\n`;
      markdown += `- **Pre-Authenticate Average:** ${summary.authentication.preAuthenticateAvg?.toFixed(2)}ms\n`;
      markdown += `- **Authenticate Average:** ${summary.authentication.authenticateAvg?.toFixed(2)}ms\n`;
      markdown += `- **Operations Tested:** ${summary.authentication.operationCount}\n\n`;
    }

    markdown += '---\n\n';
    return markdown;
  }

  /**
   * Generate registration section
   * @private
   */
  _generateRegistrationSection() {
    let markdown = '## Registration Performance\n\n';

    if (!this.results.registration || this.results.registration.length === 0) {
      markdown += 'No registration test results available.\n\n';
      return markdown;
    }

    const operationResults = this.results.registration.filter(r => r.operation);
    const otherResults = this.results.registration.filter(r => r.type);

    if (operationResults.length > 0) {
      markdown += '### Operation Timings\n\n';
      markdown += '| Operation | Iterations | Min (ms) | Max (ms) | Avg (ms) | P50 (ms) | P95 (ms) | P99 (ms) |\n';
      markdown += '|-----------|-----------|---------|---------|---------|---------|---------|----------|\n';

      operationResults.forEach(result => {
        markdown += `| ${result.operation} | ${result.iterations} | ${result.min.toFixed(2)} | ${result.max.toFixed(2)} | ${result.avg.toFixed(2)} | ${result.p50?.toFixed(2) || 'N/A'} | ${result.p95?.toFixed(2) || 'N/A'} | ${result.p99?.toFixed(2) || 'N/A'} |\n`;
      });

      markdown += '\n';
    }

    if (otherResults.length > 0) {
      otherResults.forEach(result => {
        if (result.type === 'algorithm_comparison' && Array.isArray(result.data)) {
          markdown += '### Algorithm Performance Comparison\n\n';
          markdown += '| Algorithm | Iterations | Avg (ms) | Min (ms) | Max (ms) | P95 (ms) |\n';
          markdown += '|-----------|-----------|---------|---------|---------|----------|\n';

          result.data.forEach(algo => {
            markdown += `| ${algo.algorithm} | ${algo.iterations} | ${algo.avg.toFixed(2)} | ${algo.min.toFixed(2)} | ${algo.max.toFixed(2)} | ${algo.p95?.toFixed(2) || 'N/A'} |\n`;
          });

          markdown += '\n';
        } else if (result.type === 'excludeCredentials_query' || result.operation?.includes('Credentials')) {
          markdown += `### Database Query Performance (${result.recordCount} records)\n\n`;
          markdown += `- **Query Type:** ${result.operation || 'Credentials Query'}\n`;
          markdown += `- **Average Time:** ${result.avg.toFixed(2)}ms\n`;
          markdown += `- **Min/Max:** ${result.min.toFixed(2)}ms / ${result.max.toFixed(2)}ms\n`;
          markdown += `- **P95:** ${result.p95?.toFixed(2) || 'N/A'}ms\n\n`;
        }
      });
    }

    markdown += '---\n\n';
    return markdown;
  }

  /**
   * Generate authentication section
   * @private
   */
  _generateAuthenticationSection() {
    let markdown = '## Authentication Performance\n\n';

    if (!this.results.authentication || this.results.authentication.length === 0) {
      markdown += 'No authentication test results available.\n\n';
      return markdown;
    }

    const operationResults = this.results.authentication.filter(r => r.operation);
    const otherResults = this.results.authentication.filter(r => r.type);

    if (operationResults.length > 0) {
      markdown += '### Operation Timings\n\n';
      markdown += '| Operation | Iterations | Min (ms) | Max (ms) | Avg (ms) | P50 (ms) | P95 (ms) | P99 (ms) |\n';
      markdown += '|-----------|-----------|---------|---------|---------|---------|---------|----------|\n';

      operationResults.forEach(result => {
        markdown += `| ${result.operation} | ${result.iterations} | ${result.min.toFixed(2)} | ${result.max.toFixed(2)} | ${result.avg.toFixed(2)} | ${result.p50?.toFixed(2) || 'N/A'} | ${result.p95?.toFixed(2) || 'N/A'} | ${result.p99?.toFixed(2) || 'N/A'} |\n`;
      });

      markdown += '\n';
    }

    if (otherResults.length > 0) {
      otherResults.forEach(result => {
        if (result.type === 'credential_count_comparison' && Array.isArray(result.data)) {
          markdown += '### Performance vs Credential Count\n\n';
          markdown += '| Credential Count | Avg (ms) | Min (ms) | Max (ms) | P95 (ms) |\n';
          markdown += '|-----------------|---------|---------|---------|----------|\n';

          result.data.forEach(item => {
            markdown += `| ${item.credentialCount} | ${item.avg.toFixed(2)} | ${item.min.toFixed(2)} | ${item.max.toFixed(2)} | ${item.p95?.toFixed(2) || 'N/A'} |\n`;
          });

          markdown += '\n';
        } else if (result.type === 'authentication_algorithm_comparison' && Array.isArray(result.data)) {
          markdown += '### Algorithm Signature Verification Performance\n\n';
          markdown += '| Algorithm | Iterations | Avg (ms) | Min (ms) | Max (ms) | P95 (ms) |\n';
          markdown += '|-----------|-----------|---------|---------|---------|----------|\n';

          result.data.forEach(algo => {
            markdown += `| ${algo.algorithm} | ${algo.iterations} | ${algo.avg.toFixed(2)} | ${algo.min.toFixed(2)} | ${algo.max.toFixed(2)} | ${algo.p95?.toFixed(2) || 'N/A'} |\n`;
          });

          markdown += '\n';
        } else if (result.operation?.includes('counter')) {
          markdown += '### Counter Update Performance\n\n';
          markdown += `- **Average Time:** ${result.avg.toFixed(2)}ms\n`;
          markdown += `- **Min/Max:** ${result.min.toFixed(2)}ms / ${result.max.toFixed(2)}ms\n`;
          markdown += `- **P95:** ${result.p95?.toFixed(2) || 'N/A'}ms\n\n`;
        }
      });
    }

    markdown += '---\n\n';
    return markdown;
  }

  /**
   * Generate concurrency section
   * @private
   */
  _generateConcurrencySection() {
    let markdown = '## Concurrency and Load Testing\n\n';

    if (!this.results.concurrency || this.results.concurrency.length === 0) {
      markdown += 'No concurrency test results available.\n\n';
      return markdown;
    }

    this.results.concurrency.forEach(result => {
      if (result.type === 'concurrent_registration') {
        markdown += '### Concurrent Registration Requests\n\n';
        markdown += '| Concurrency | Avg (ms) | Min (ms) | Max (ms) | P50 (ms) | P95 (ms) | P99 (ms) | Max Active Connections |\n';
        markdown += '|-------------|---------|---------|---------|---------|---------|---------|------------------------|\n';

        result.data.forEach(item => {
          markdown += `| ${item.concurrency} | ${item.avg.toFixed(2)} | ${item.min.toFixed(2)} | ${item.max.toFixed(2)} | ${item.p50?.toFixed(2) || 'N/A'} | ${item.p95?.toFixed(2) || 'N/A'} | ${item.p99?.toFixed(2) || 'N/A'} | ${item.avgPoolStats.maxActiveConnections} |\n`;
        });

        markdown += '\n';
      } else if (result.type === 'concurrent_authentication') {
        markdown += '### Concurrent Authentication Requests\n\n';
        markdown += '| Concurrency | Avg (ms) | Min (ms) | Max (ms) | P50 (ms) | P95 (ms) | P99 (ms) |\n';
        markdown += '|-------------|---------|---------|---------|---------|---------|----------|\n';

        result.data.forEach(item => {
          markdown += `| ${item.concurrency} | ${item.avg.toFixed(2)} | ${item.min.toFixed(2)} | ${item.max.toFixed(2)} | ${item.p50?.toFixed(2) || 'N/A'} | ${item.p95?.toFixed(2) || 'N/A'} | ${item.p99?.toFixed(2) || 'N/A'} |\n`;
        });

        markdown += '\n';
      } else if (result.type === 'mixed_operations') {
        markdown += '### Mixed Operations (Registration + Authentication)\n\n';
        markdown += `- **Total Concurrent Requests:** ${result.totalConcurrency}\n`;
        markdown += `- **Registrations:** ${result.registrations.count} requests, avg ${result.registrations.avg.toFixed(2)}ms\n`;
        markdown += `- **Authentications:** ${result.authentications.count} requests, avg ${result.authentications.avg.toFixed(2)}ms\n\n`;
      } else if (result.type === 'pool_exhaustion') {
        markdown += '### Connection Pool Stress Test\n\n';
        markdown += `- **Pool Size:** ${result.poolSize} connections\n`;
        markdown += `- **Total Requests:** ${result.requestCount}\n`;
        markdown += `- **Completed:** ${result.completedRequests}\n`;
        markdown += `- **Pool Exhaustion Events:** ${result.poolExhaustedEvents}\n`;
        markdown += `- **Average Response Time:** ${result.timingsAvg.toFixed(2)}ms\n\n`;
      } else if (result.type === 'throughput_measurement') {
        markdown += '### Throughput Measurement\n\n';
        markdown += '| Load Profile | Concurrency | Duration (ms) | Requests | Throughput (RPS) |\n';
        markdown += '|--------------|-------------|--------------|----------|------------------|\n';

        result.data.forEach(item => {
          markdown += `| ${item.profile} | ${item.concurrency} | ${item.duration} | ${item.completedRequests} | ${item.throughputRPS} |\n`;
        });

        markdown += '\n';
      }
    });

    markdown += '---\n\n';
    return markdown;
  }

  /**
   * Generate recommendations section
   * @private
   */
  _generateRecommendationsSection() {
    let markdown = '## Performance Recommendations\n\n';

    markdown += `### Based on Test Results\n\n`;

    markdown += `1. **Registration Operations**\n`;
    markdown += `   - Ensure pre-register completes within 150ms (P95) for optimal user experience\n`;
    markdown += `   - Register operation (with attestation validation) typically takes 200-400ms\n\n`;

    markdown += `2. **Authentication Operations**\n`;
    markdown += `   - Pre-authenticate should complete within 150ms\n`;
    markdown += `   - Full authentication validates signature within 200-300ms\n\n`;

    markdown += `3. **Database Performance**\n`;
    markdown += `   - Monitor query response times with large credential lists (10+ credentials per user)\n`;
    markdown += `   - Ensure counter updates are consistently fast (< 30ms)\n\n`;

    markdown += `4. **Concurrent Load**\n`;
    markdown += `   - Server maintains reasonable response times under 50+ concurrent requests\n`;
    markdown += `   - Connection pool should be sized based on expected peak concurrency\n\n`;

    markdown += `5. **Algorithm Selection**\n`;
    markdown += `   - ES256 provides good balance of security and performance\n`;
    markdown += `   - RS256 has higher verification overhead; consider for high-security scenarios\n`;
    markdown += `   - EdDSA offers faster verification; consider for high-throughput scenarios\n\n`;

    markdown += `### Monitoring Recommendations\n\n`;
    markdown += `- Continuously monitor P95 and P99 percentiles in production\n`;
    markdown += `- Alert on response time increase > 20% from baseline\n`;
    markdown += `- Track database connection pool saturation\n`;
    markdown += `- Monitor signature counter increment frequency to detect abuse patterns\n\n`;

    return markdown;
  }

  /**
   * Generate all reports
   */
  generateAllReports() {
    console.log('\\n=== Generating Performance Reports ===\\n');

    this.loadResults();

    const jsonReport = this.generateJSONReport();
    const markdownReport = this.generateMarkdownReport();

    console.log('\\n=== Report Generation Complete ===\\n');

    return {
      json: jsonReport,
      markdown: markdownReport
    };
  }
}

// Run if executed directly
if (require.main === module) {
  const generator = new PerformanceReportGenerator();
  const reports = generator.generateAllReports();
  console.log('Reports generated successfully');
}

module.exports = {
  PerformanceReportGenerator,
  generateReports: () => new PerformanceReportGenerator().generateAllReports()
};
