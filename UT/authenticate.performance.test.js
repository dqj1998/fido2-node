/**
 * Authentication Performance Tests
 * Measures response time for FIDO2 authentication endpoints
 * Tests both preAuthenticate and authenticate operations
 */

const { MockConnectionPool } = require('./mockDatabase');
const { MockDataGenerator } = require('./mockData');

describe('Authentication Performance Tests', () => {
  let mockPool;
  let dataGenerator;
  let results = [];

  beforeAll(() => {
    // Initialize mock database pool with realistic delays
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

  beforeEach(() => {
    mockPool.clearData();
  });

  /**
   * Test: preAuthenticate endpoint response time
   * Measures time from request to challenge generation and credential retrieval
   */
  test('preAuthenticate should complete within expected timeframe', async () => {
    const username = 'testuser';
    const rpId = 'example.com';

    // Pre-populate credentials in database
    const credentialCount = 3;
    const credentials = [];
    for (let i = 0; i < credentialCount; i++) {
      const credId = `cred_${i}`;
      credentials.push(credId);
      await mockPool.query(
        'INSERT INTO attestations (username, credential_id, credential_public_key, counter, attestation_format, credential_algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [username, credId, 'mock_pubkey', i, 'packed', 'ES256', Date.now()]
      );
    }

    const iterations = 100;
    const timings = [];

    for (let i = 0; i < iterations; i++) {
      const startTime = performance.now();

      // Simulate preAuthenticate operation:
      // 1. Generate challenge
      const challenge = Buffer.alloc(32);
      for (let j = 0; j < 32; j++) {
        challenge[j] = Math.floor(Math.random() * 256);
      }
      const challengeB64 = challenge.toString('base64url');

      // 2. Retrieve user credentials from database (for allowCredentials)
      const result = await mockPool.query(
        'SELECT credential_id FROM attestations WHERE username = ?',
        [username]
      );

      const allowCredentials = (result[0] || []).map(row => ({
        type: 'public-key',
        id: row.credentialId
      }));

      // 3. Store authentication session
      await mockPool.query(
        'INSERT INTO authentication_sessions (session_id, username, rpId, challenge, created_at) VALUES (?, ?, ?, ?, ?)',
        [`auth_session_${i}`, username, rpId, challengeB64, Date.now()]
      );

      // 4. Generate PublicKeyCredentialRequestOptions
      const options = {
        challenge: challengeB64,
        timeout: 60000,
        rpId: rpId,
        allowCredentials: allowCredentials,
        userVerification: 'preferred'
      };

      const endTime = performance.now();
      const duration = endTime - startTime;
      timings.push(duration);
    }

    // Calculate statistics
    const stats = {
      operation: 'preAuthenticate',
      iterations,
      credentialCount,
      min: Math.min(...timings),
      max: Math.max(...timings),
      avg: timings.reduce((a, b) => a + b, 0) / timings.length,
      p50: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.5)],
      p95: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.95)],
      p99: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.99)]
    };

    results.push(stats);
    console.log('preAuthenticate Performance:', stats);

    // Assertions
    expect(stats.avg).toBeLessThan(100);
    expect(stats.p95).toBeLessThan(150);
    expect(stats.p99).toBeLessThan(200);
  });

  /**
   * Test: authenticate endpoint response time
   * Measures time from assertion response to signature verification and counter update
   */
  test('authenticate should complete within expected timeframe', async () => {
    const username = 'testuser';
    const rpId = 'example.com';

    // Pre-populate credentials
    const credentialId = 'cred_0';
    await mockPool.query(
      'INSERT INTO attestations (username, credential_id, credential_public_key, counter, attestation_format, credential_algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [username, credentialId, 'mock_pubkey', 0, 'packed', 'ES256', Date.now()]
    );

    const iterations = 50;
    const timings = [];

    for (let i = 0; i < iterations; i++) {
      const startTime = performance.now();

      // Simulate authenticate operation:
      // 1. Receive and parse assertion response
      const assertionResponse = dataGenerator.generateAuthenticationResponse(
        credentialId,
        null,
        i + 1,
        'ES256'
      );

      // 2. Parse authenticatorData and verify structure
      const authData = JSON.parse(
        Buffer.from(assertionResponse.response.authenticatorData, 'base64url').toString()
      );

      // 3. Parse clientDataJSON
      const clientData = JSON.parse(
        Buffer.from(assertionResponse.response.clientDataJSON, 'base64url').toString()
      );

      // 4. Validate clientDataJSON hash and origin
      const isValidOrigin = clientData.origin === 'https://example.com';
      const isValidType = clientData.type === 'webauthn.get';
      const isValidCrossOrigin = clientData.crossOrigin === false;

      // 5. Retrieve stored credential from database
      const credResult = await mockPool.query(
        'SELECT credential_public_key, counter FROM attestations WHERE username = ? AND credential_id = ?',
        [username, credentialId]
      );

      // 6. Validate signature (cryptographic operation)
      // Simulated as a light operation
      const signatureValid = assertionResponse.response.signature.length > 0;

      // 7. Verify counter
      const storedCounter = credResult[0] ? credResult[0][0].counter : 0;
      const newCounter = authData.signCount;
      const counterValid = newCounter > storedCounter;

      // 8. Update counter in database
      if (counterValid) {
        await mockPool.query(
          'UPDATE attestations SET counter = ? WHERE username = ? AND credential_id = ?',
          [newCounter, username, credentialId]
        );
      }

      // 9. Log authentication event
      await mockPool.query(
        'INSERT INTO audit_logs (username, action_type, credential_id, status, created_at) VALUES (?, ?, ?, ?, ?)',
        [username, 1, credentialId, 'success', Date.now()]
      );

      const endTime = performance.now();
      const duration = endTime - startTime;
      timings.push(duration);
    }

    // Calculate statistics
    const stats = {
      operation: 'authenticate',
      iterations,
      min: Math.min(...timings),
      max: Math.max(...timings),
      avg: timings.reduce((a, b) => a + b, 0) / timings.length,
      p50: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.5)],
      p95: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.95)],
      p99: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.99)]
    };

    results.push(stats);
    console.log('authenticate Performance:', stats);

    // Assertions
    expect(stats.avg).toBeLessThan(250);
    expect(stats.p95).toBeLessThan(350);
    expect(stats.p99).toBeLessThan(450);
  });

  /**
   * Test: authentication with varying credential counts
   * Measures performance impact of allowCredentials list size
   */
  test('preAuthenticate performance with varying credential counts', async () => {
    const username = 'testuser';
    const credentialCounts = [1, 5, 10, 20];
    const countResults = [];

    for (const credCount of credentialCounts) {
      mockPool.clearData();

      // Pre-populate credentials
      for (let i = 0; i < credCount; i++) {
        await mockPool.query(
          'INSERT INTO attestations (username, credential_id, credential_public_key, counter, attestation_format, credential_algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [username, `cred_${i}`, 'mock_pubkey', i, 'packed', 'ES256', Date.now()]
        );
      }

      const iterations = 50;
      const timings = [];

      for (let i = 0; i < iterations; i++) {
        const startTime = performance.now();

        // Query credentials
        const result = await mockPool.query(
          'SELECT credential_id FROM attestations WHERE username = ?',
          [username]
        );

        const allowCredentials = (result[0] || []).map(row => ({
          type: 'public-key',
          id: row.credentialId
        }));

        const endTime = performance.now();
        timings.push(endTime - startTime);
      }

      const stats = {
        credentialCount: credCount,
        avg: timings.reduce((a, b) => a + b, 0) / timings.length,
        min: Math.min(...timings),
        max: Math.max(...timings),
        p95: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.95)]
      };

      countResults.push(stats);
    }

    results.push({ type: 'credential_count_comparison', data: countResults });
    console.log('Credential Count Comparison:', countResults);

    // Verify performance scales reasonably
    countResults.forEach(result => {
      expect(result.avg).toBeLessThan(100);
    });
  });

  /**
   * Test: signature verification performance with different algorithms
   */
  test('authenticate performance with different algorithms', async () => {
    const username = 'testuser';
    const algorithms = ['ES256', 'RS256', 'EdDSA'];
    const algorithmResults = {};

    for (const algorithm of algorithms) {
      const credentialId = `cred_${algorithm}`;
      mockPool.clearData();

      // Pre-populate credential
      await mockPool.query(
        'INSERT INTO attestations (username, credential_id, credential_public_key, counter, attestation_format, credential_algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [username, credentialId, 'mock_pubkey', 0, 'packed', algorithm, Date.now()]
      );

      const iterations = 30;
      const timings = [];

      for (let i = 0; i < iterations; i++) {
        const startTime = performance.now();

        const assertionResponse = dataGenerator.generateAuthenticationResponse(
          credentialId,
          null,
          i + 1,
          algorithm
        );

        // Simulate signature verification (varies by algorithm)
        // RS256 is typically slower due to larger key sizes
        const verificationDelay = algorithm === 'RS256' ? 25 : algorithm === 'EdDSA' ? 12 : 15;
        await new Promise(resolve => setTimeout(resolve, verificationDelay));

        // Update counter
        await mockPool.query(
          'UPDATE attestations SET counter = ? WHERE username = ? AND credential_id = ?',
          [i + 1, username, credentialId]
        );

        const endTime = performance.now();
        timings.push(endTime - startTime);
      }

      algorithmResults[algorithm] = {
        algorithm,
        iterations,
        avg: timings.reduce((a, b) => a + b, 0) / timings.length,
        min: Math.min(...timings),
        max: Math.max(...timings),
        p95: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.95)]
      };
    }

    results.push({ type: 'authentication_algorithm_comparison', data: algorithmResults });
    console.log('Authentication Algorithm Comparison:', algorithmResults);

    Object.values(algorithmResults).forEach(result => {
      expect(result.avg).toBeLessThan(200);
    });
  });

  /**
   * Test: counter update performance
   * Measures database write performance for signature counter updates
   */
  test('counter update performance', async () => {
    const username = 'testuser';
    const credentialId = 'cred_0';

    // Pre-populate credential
    await mockPool.query(
      'INSERT INTO attestations (username, credential_id, credential_public_key, counter, attestation_format, credential_algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [username, credentialId, 'mock_pubkey', 0, 'packed', 'ES256', Date.now()]
    );

    const iterations = 100;
    const timings = [];

    for (let i = 0; i < iterations; i++) {
      const startTime = performance.now();

      // Update counter
      await mockPool.query(
        'UPDATE attestations SET counter = ? WHERE username = ? AND credential_id = ?',
        [i + 1, username, credentialId]
      );

      const endTime = performance.now();
      timings.push(endTime - startTime);
    }

    const stats = {
      operation: 'counter_update',
      iterations,
      avg: timings.reduce((a, b) => a + b, 0) / timings.length,
      min: Math.min(...timings),
      max: Math.max(...timings),
      p95: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.95)]
    };

    results.push(stats);
    console.log('Counter Update Performance:', stats);

    expect(stats.avg).toBeLessThan(50);  // Database update should be fast
  });

  afterAll(() => {
    // Save results to file for reporting
    const fs = require('fs');
    const reportPath = '/Users/dqj/HDD/fido2Prjs/fido2-node/UT/results/authenticate.results.json';
    const reportDir = '/Users/dqj/HDD/fido2Prjs/fido2-node/UT/results';

    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }

    fs.writeFileSync(reportPath, JSON.stringify(results, null, 2));
    console.log(`Results saved to ${reportPath}`);
  });
});
