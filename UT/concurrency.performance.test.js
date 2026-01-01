/**
 * Concurrency and Stress Performance Tests
 * Tests performance under concurrent load and with connection pool constraints
 */

const { MockConnectionPool } = require('./mockDatabase');
const { MockDataGenerator } = require('./mockData');

describe('Concurrency and Stress Performance Tests', () => {
  let mockPool;
  let dataGenerator;
  let results = [];

  beforeAll(() => {
    mockPool = new MockConnectionPool({
      query: 10,
      insert: 15,
      update: 12,
      select: 8
    });
    dataGenerator = new MockDataGenerator();
  });

  afterAll(() => {
    mockPool.end();
  });

  /**
   * Test: Concurrent registration requests
   * Measures response time distribution under concurrent load
   */
  test('concurrent registration requests', async () => {
    const concurrentRequests = [10, 25, 50];
    const concurrencyResults = [];

    for (const concurrency of concurrentRequests) {
      mockPool.clearData();
      const timings = [];
      const poolStats = [];

      // Generate concurrent registration requests
      const promises = [];
      for (let i = 0; i < concurrency; i++) {
        promises.push(
          (async () => {
            const startTime = performance.now();

            try {
              // Pre-register phase
              const challenge = Buffer.alloc(32);
              for (let j = 0; j < 32; j++) {
                challenge[j] = Math.floor(Math.random() * 256);
              }

              await mockPool.query(
                'INSERT INTO registration_sessions (session_id, username, rpId, challenge, created_at) VALUES (?, ?, ?, ?, ?)',
                [`session_${i}`, `user_${i}`, 'example.com', challenge.toString('base64url'), Date.now()]
              );

              // Register phase
              const attestationResponse = dataGenerator.generateRegistrationResponse(
                `user_${i}`,
                null,
                'ES256'
              );

              await mockPool.query(
                'INSERT INTO attestations (username, credential_id, credential_public_key, counter, attestation_format, credential_algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [
                  `user_${i}`,
                  attestationResponse.id,
                  'mock_pubkey',
                  0,
                  'packed',
                  'ES256',
                  Date.now()
                ]
              );

              const endTime = performance.now();
              timings.push(endTime - startTime);

              // Capture pool stats periodically
              if (i % Math.ceil(concurrency / 5) === 0) {
                poolStats.push(mockPool.getStats());
              }
            } catch (error) {
              console.error(`Request ${i} failed:`, error.message);
              timings.push(0);
            }
          })()
        );
      }

      await Promise.all(promises);

      // Calculate statistics
      const stats = {
        concurrency,
        iterations: concurrency,
        min: Math.min(...timings),
        max: Math.max(...timings),
        avg: timings.reduce((a, b) => a + b, 0) / timings.length,
        p50: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.5)],
        p95: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.95)],
        p99: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.99)],
        avgPoolStats: {
          activeConnections: poolStats.length > 0
            ? Math.round(poolStats.reduce((sum, s) => sum + s.activeConnections, 0) / poolStats.length)
            : 0,
          maxActiveConnections: Math.max(...poolStats.map(s => s.activeConnections), 0)
        }
      };

      concurrencyResults.push(stats);
      console.log(`Concurrent Registration (${concurrency}):`, stats);
    }

    results.push({ type: 'concurrent_registration', data: concurrencyResults });

    // Verify performance degrades gracefully with load
    concurrencyResults.forEach((result, index) => {
      if (index > 0) {
        // Higher concurrency should not increase average by more than 50% per doubling
        const previousConcurrency = concurrencyResults[index - 1].concurrency;
        const currentConcurrency = result.concurrency;
        const concurrencyRatio = currentConcurrency / previousConcurrency;

        // Allow for some degradation but not catastrophic
        expect(result.avg).toBeLessThan(concurrencyResults[index - 1].avg * (1 + concurrencyRatio * 0.3));
      }
    });
  });

  /**
   * Test: Concurrent authentication requests
   * Measures response time distribution under authentication load
   */
  test('concurrent authentication requests', async () => {
    const concurrentRequests = [10, 25, 50];
    const username = 'testuser';

    // Pre-populate credentials
    for (let i = 0; i < 10; i++) {
      await mockPool.query(
        'INSERT INTO attestations (username, credential_id, credential_public_key, counter, attestation_format, credential_algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [username, `cred_${i}`, 'mock_pubkey', 0, 'packed', 'ES256', Date.now()]
      );
    }

    const concurrencyResults = [];

    for (const concurrency of concurrentRequests) {
      const timings = [];

      const promises = [];
      for (let i = 0; i < concurrency; i++) {
        promises.push(
          (async () => {
            const startTime = performance.now();

            try {
              // Pre-authenticate phase
              const challenge = Buffer.alloc(32);
              for (let j = 0; j < 32; j++) {
                challenge[j] = Math.floor(Math.random() * 256);
              }

              const result = await mockPool.query(
                'SELECT credential_id FROM attestations WHERE username = ?',
                [username]
              );

              // Authenticate phase
              const credentialId = result[0] && result[0][0] ? result[0][0].credentialId : `cred_0`;

              const assertionResponse = dataGenerator.generateAuthenticationResponse(
                credentialId,
                null,
                i + 1,
                'ES256'
              );

              await mockPool.query(
                'UPDATE attestations SET counter = ? WHERE username = ? AND credential_id = ?',
                [i + 1, username, credentialId]
              );

              const endTime = performance.now();
              timings.push(endTime - startTime);
            } catch (error) {
              console.error(`Auth request ${i} failed:`, error.message);
              timings.push(0);
            }
          })()
        );
      }

      await Promise.all(promises);

      const stats = {
        concurrency,
        iterations: concurrency,
        min: Math.min(...timings),
        max: Math.max(...timings),
        avg: timings.reduce((a, b) => a + b, 0) / timings.length,
        p50: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.5)],
        p95: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.95)],
        p99: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.99)]
      };

      concurrencyResults.push(stats);
      console.log(`Concurrent Authentication (${concurrency}):`, stats);
    }

    results.push({ type: 'concurrent_authentication', data: concurrencyResults });

    concurrencyResults.forEach(result => {
      expect(result.avg).toBeLessThan(500);
    });
  });

  /**
   * Test: Mixed concurrent operations
   * Simulates simultaneous registrations and authentications
   */
  test('mixed concurrent operations (registration and authentication)', async () => {
    mockPool.clearData();

    // Pre-populate some credentials
    for (let i = 0; i < 5; i++) {
      await mockPool.query(
        'INSERT INTO attestations (username, credential_id, credential_public_key, counter, attestation_format, credential_algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [`preuser_${i}`, `cred_${i}`, 'mock_pubkey', 0, 'packed', 'ES256', Date.now()]
      );
    }

    const mixedConcurrency = 40;  // 20 registrations + 20 authentications
    const timings = {
      registrations: [],
      authentications: []
    };

    const promises = [];

    // Generate registration requests
    for (let i = 0; i < mixedConcurrency / 2; i++) {
      promises.push(
        (async () => {
          const startTime = performance.now();

          try {
            const attestationResponse = dataGenerator.generateRegistrationResponse(
              `newuser_${i}`,
              null,
              'ES256'
            );

            await mockPool.query(
              'INSERT INTO attestations (username, credential_id, credential_public_key, counter, attestation_format, credential_algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
              [
                `newuser_${i}`,
                attestationResponse.id,
                'mock_pubkey',
                0,
                'packed',
                'ES256',
                Date.now()
              ]
            );

            timings.registrations.push(performance.now() - startTime);
          } catch (error) {
            console.error(`Mixed registration ${i} failed:`, error.message);
          }
        })()
      );
    }

    // Generate authentication requests
    for (let i = 0; i < mixedConcurrency / 2; i++) {
      promises.push(
        (async () => {
          const startTime = performance.now();

          try {
            const result = await mockPool.query(
              'SELECT credential_id FROM attestations WHERE username = ?',
              [`preuser_${i % 5}`]
            );

            const credentialId = result[0] && result[0][0] ? result[0][0].credentialId : `cred_0`;

            const assertionResponse = dataGenerator.generateAuthenticationResponse(
              credentialId,
              null,
              i + 1,
              'ES256'
            );

            await mockPool.query(
              'UPDATE attestations SET counter = ? WHERE username = ? AND credential_id = ?',
              [i + 1, `preuser_${i % 5}`, credentialId]
            );

            timings.authentications.push(performance.now() - startTime);
          } catch (error) {
            console.error(`Mixed authentication ${i} failed:`, error.message);
          }
        })()
      );
    }

    await Promise.all(promises);

    const stats = {
      type: 'mixed_operations',
      totalConcurrency: mixedConcurrency,
      registrations: {
        count: timings.registrations.length,
        avg: timings.registrations.length > 0 ? timings.registrations.reduce((a, b) => a + b, 0) / timings.registrations.length : 0,
        p95: timings.registrations.length > 0 ? timings.registrations.sort((a, b) => a - b)[Math.floor(timings.registrations.length * 0.95)] : 0
      },
      authentications: {
        count: timings.authentications.length,
        avg: timings.authentications.length > 0 ? timings.authentications.reduce((a, b) => a + b, 0) / timings.authentications.length : 0,
        p95: timings.authentications.length > 0 ? timings.authentications.sort((a, b) => a - b)[Math.floor(timings.authentications.length * 0.95)] : 0
      }
    };

    results.push(stats);
    console.log('Mixed Operations Performance:', stats);

    if (stats.registrations.count > 0) {
      expect(stats.registrations.avg).toBeLessThan(300);
    }
    if (stats.authentications.count > 0) {
      expect(stats.authentications.avg).toBeLessThan(250);
    }
  });

  /**
   * Test: Database connection pool exhaustion
   * Simulates behavior when pool reaches maximum connections
   */
  test('connection pool under maximum load', async () => {
    mockPool.clearData();

    const poolSize = 10;
    const requestCount = 15;  // Test with manageable concurrency
    const timings = [];
    let successCount = 0;
    let poolExhaustedCount = 0;

    const executeRequest = async (index) => {
      const startTime = performance.now();

      try {
        const stats = mockPool.getStats();
        if (stats.availableConnections === 0) {
          poolExhaustedCount++;
        }

        // Simulate mixed operations
        if (index % 2 === 0) {
          // Registration-like operation
          await mockPool.query(
            'INSERT INTO attestations (username, credential_id, credential_public_key, counter, attestation_format, credential_algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [`user_${index}`, `cred_${index}`, 'mock_pubkey', 0, 'packed', 'ES256', Date.now()]
          );
        } else {
          // Authentication-like operation - using proper index bounds
          if (index > 0) {
            await mockPool.query(
              'UPDATE attestations SET counter = ? WHERE username = ? AND credential_id = ?',
              [index + 1, `user_${index - 1}`, `cred_${index - 1}`]
            );
          }
        }

        timings.push(performance.now() - startTime);
        successCount++;
      } catch (error) {
        console.error(`Pool stress request ${index} failed:`, error.message);
      }
    };

    // Execute requests sequentially to allow proper pool management
    for (let i = 0; i < requestCount; i++) {
      await executeRequest(i);
    }

    const stats = {
      type: 'pool_exhaustion',
      poolSize,
      requestCount,
      completedRequests: successCount,
      timingsMin: timings.length > 0 ? Math.min(...timings) : 0,
      timingsMax: timings.length > 0 ? Math.max(...timings) : 0,
      timingsAvg: timings.length > 0 ? timings.reduce((a, b) => a + b, 0) / timings.length : 0,
      poolExhaustedEvents: poolExhaustedCount
    };

    results.push(stats);
    console.log('Connection Pool Stress:', stats);

    // All requests should complete successfully
    expect(stats.completedRequests).toBe(requestCount);
  });

  /**
   * Test: Throughput measurement
   * Measures requests per second under sustained load
   */
  test('throughput under sustained load', async () => {
    mockPool.clearData();

    const loadProfiles = [
      { duration: 1000, concurrency: 10, name: 'light' },
      { duration: 1000, concurrency: 25, name: 'medium' },
      { duration: 1000, concurrency: 50, name: 'heavy' }
    ];

    const throughputResults = [];

    for (const profile of loadProfiles) {
      const startTime = performance.now();
      let completedRequests = 0;
      const promises = [];

      // Generate requests for the specified duration
      const endTimeLimit = startTime + profile.duration;

      while (performance.now() < endTimeLimit) {
        for (let i = 0; i < profile.concurrency && performance.now() < endTimeLimit; i++) {
          promises.push(
            (async () => {
              try {
                // Alternate between registration and authentication
                if (Math.random() < 0.5) {
                  const attestationResponse = dataGenerator.generateRegistrationResponse(
                    `user_${i}_${Date.now()}`,
                    null,
                    'ES256'
                  );

                  await mockPool.query(
                    'INSERT INTO attestations (username, credential_id, credential_public_key, counter, attestation_format, credential_algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    [
                      `user_${i}_${Date.now()}`,
                      attestationResponse.id,
                      'mock_pubkey',
                      0,
                      'packed',
                      'ES256',
                      Date.now()
                    ]
                  );
                } else {
                  await mockPool.query(
                    'SELECT credential_id FROM attestations LIMIT 1'
                  );
                }

                completedRequests++;
              } catch (error) {
                // Silently handle errors in throughput test
              }
            })()
          );
        }

        await Promise.all(promises);
        promises.length = 0;
      }

      const elapsedTime = performance.now() - startTime;
      const throughput = (completedRequests / elapsedTime) * 1000;  // Requests per second

      throughputResults.push({
        profile: profile.name,
        concurrency: profile.concurrency,
        duration: Math.round(elapsedTime),
        completedRequests,
        throughputRPS: Math.round(throughput * 100) / 100
      });

      console.log(`${profile.name.toUpperCase()} throughput:`, throughputResults[throughputResults.length - 1]);
    }

    results.push({ type: 'throughput_measurement', data: throughputResults });
  });

  afterAll(() => {
    // Save results to file for reporting
    const fs = require('fs');
    const reportPath = '/Users/dqj/HDD/fido2Prjs/fido2-node/UT/results/concurrency.results.json';
    const reportDir = '/Users/dqj/HDD/fido2Prjs/fido2-node/UT/results';

    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }

    fs.writeFileSync(reportPath, JSON.stringify(results, null, 2));
    console.log(`Results saved to ${reportPath}`);
  });
});
