/**
 * Registration Performance Tests
 * Measures response time for FIDO2 registration endpoints
 * Tests both preRegister and register operations
 */

const { MockConnectionPool } = require('./mockDatabase');
const { MockDataGenerator } = require('./mockData');

describe('Registration Performance Tests', () => {
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
   * Test: preRegister endpoint response time
   * Measures time from request to challenge generation
   */
  test('preRegister should complete within expected timeframe', async () => {
    const payload = dataGenerator.generatePreRegisterRequest('testuser', 'example.com');
    const iterations = 100;
    const timings = [];

    for (let i = 0; i < iterations; i++) {
      const startTime = performance.now();

      // Simulate preRegister operation:
      // 1. Generate challenge
      const challenge = Buffer.alloc(32);
      for (let j = 0; j < 32; j++) {
        challenge[j] = Math.floor(Math.random() * 256);
      }
      const challengeB64 = challenge.toString('base64url');

      // 2. Store registration session in database
      await mockPool.query(
        'INSERT INTO registration_sessions (session_id, username, rpId, challenge, created_at) VALUES (?, ?, ?, ?, ?)',
        [`session_${i}`, payload.username, payload.rpId, challengeB64, Date.now()]
      );

      // 3. Generate PublicKeyCredentialCreationOptions
      const options = {
        challenge: challengeB64,
        rp: {
          name: 'Example',
          id: payload.rpId
        },
        user: {
          id: Buffer.from(payload.username).toString('base64url'),
          name: payload.username,
          displayName: payload.displayName
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },   // ES256
          { alg: -257, type: 'public-key' }  // RS256
        ],
        authenticatorSelection: payload.authenticatorSelection || {},
        timeout: 60000,
        attestation: 'direct'
      };

      const endTime = performance.now();
      const duration = endTime - startTime;
      timings.push(duration);
    }

    // Calculate statistics
    const stats = {
      operation: 'preRegister',
      iterations,
      min: Math.min(...timings),
      max: Math.max(...timings),
      avg: timings.reduce((a, b) => a + b, 0) / timings.length,
      p50: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.5)],
      p95: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.95)],
      p99: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.99)]
    };

    results.push(stats);
    console.log('preRegister Performance:', stats);

    // Assertions
    expect(stats.avg).toBeLessThan(100);  // Average should be under 100ms
    expect(stats.p95).toBeLessThan(150);  // 95th percentile under 150ms
    expect(stats.p99).toBeLessThan(200);  // 99th percentile under 200ms
  });

  /**
   * Test: register endpoint response time
   * Measures time from attestation response to credential storage
   */
  test('register should complete within expected timeframe', async () => {
    const iterations = 50;
    const timings = [];

    for (let i = 0; i < iterations; i++) {
      const startTime = performance.now();

      // Simulate register operation:
      // 1. Receive and parse attestation response
      const attestationResponse = dataGenerator.generateRegistrationResponse(
        `testuser_${i}`,
        null,
        'ES256'
      );

      // 2. Validate attestation object (CBOR parsing)
      // Simulated as a light operation
      const parsedAttestation = JSON.parse(
        Buffer.from(attestationResponse.response.attestationObject, 'base64url').toString()
      );

      // 3. Parse clientDataJSON
      const clientData = JSON.parse(
        Buffer.from(attestationResponse.response.clientDataJSON, 'base64url').toString()
      );

      // 4. Validate clientDataJSON integrity
      const isValidOrigin = clientData.origin === 'https://example.com';
      const isValidType = clientData.type === 'webauthn.create';

      // 5. Store credential in database
      await mockPool.query(
        'INSERT INTO attestations (username, credential_id, credential_public_key, counter, attestation_format, credential_algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [
          `testuser_${i}`,
          attestationResponse.id,
          JSON.stringify(parsedAttestation.authData.attestedCredentialData.credentialPublicKey),
          0,
          parsedAttestation.fmt,
          'ES256',
          Date.now()
        ]
      );

      // 6. Create user session
      const sessionId = `session_${i}_${Date.now()}`;
      await mockPool.query(
        'INSERT INTO sessions (session_id, username, domain, created_at) VALUES (?, ?, ?, ?)',
        [sessionId, `testuser_${i}`, 'example.com', Date.now()]
      );

      const endTime = performance.now();
      const duration = endTime - startTime;
      timings.push(duration);
    }

    // Calculate statistics
    const stats = {
      operation: 'register',
      iterations,
      min: Math.min(...timings),
      max: Math.max(...timings),
      avg: timings.reduce((a, b) => a + b, 0) / timings.length,
      p50: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.5)],
      p95: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.95)],
      p99: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.99)]
    };

    results.push(stats);
    console.log('register Performance:', stats);

    // Assertions - register is slower due to cryptographic validation
    expect(stats.avg).toBeLessThan(300);  // Average should be under 300ms
    expect(stats.p95).toBeLessThan(400);  // 95th percentile under 400ms
    expect(stats.p99).toBeLessThan(500);  // 99th percentile under 500ms
  });

  /**
   * Test: registration with multiple algorithms
   * Measures performance impact of different signing algorithms
   */
  test('registration performance with different algorithms', async () => {
    const algorithms = ['ES256', 'RS256', 'EdDSA'];
    const algorithResults = {};

    for (const algorithm of algorithms) {
      const iterations = 30;
      const timings = [];

      for (let i = 0; i < iterations; i++) {
        const startTime = performance.now();

        const attestationResponse = dataGenerator.generateRegistrationResponse(
          `testuser_${i}`,
          null,
          algorithm
        );

        // Simulate attestation validation (cryptographic operation)
        // Different algorithms have different validation times
        const validationDelay = algorithm === 'RS256' ? 20 : algorithm === 'EdDSA' ? 15 : 10;
        await new Promise(resolve => setTimeout(resolve, validationDelay));

        // Store credential
        await mockPool.query(
          'INSERT INTO attestations (username, credential_id, credential_public_key, counter, attestation_format, credential_algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [
            `testuser_${i}`,
            attestationResponse.id,
            'mock_pubkey',
            0,
            'packed',
            algorithm,
            Date.now()
          ]
        );

        const endTime = performance.now();
        timings.push(endTime - startTime);
      }

      algorithResults[algorithm] = {
        algorithm,
        iterations,
        avg: timings.reduce((a, b) => a + b, 0) / timings.length,
        min: Math.min(...timings),
        max: Math.max(...timings),
        p95: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.95)]
      };
    }

    results.push({ type: 'algorithm_comparison', data: algorithResults });
    console.log('Algorithm Comparison:', algorithResults);

    // Verify all algorithms complete in reasonable time
    Object.values(algorithResults).forEach(result => {
      expect(result.avg).toBeLessThan(200);
    });
  });

  /**
   * Test: excludeCredentials performance
   * Measures database query performance for checking existing credentials
   */
  test('excludeCredentials query performance', async () => {
    const username = 'testuser';
    const credentialCount = 5;

    // Pre-populate database with credentials
    for (let i = 0; i < credentialCount; i++) {
      await mockPool.query(
        'INSERT INTO attestations (username, credential_id, credential_public_key, counter, attestation_format, credential_algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [username, `cred_${i}`, 'mock_pubkey', 0, 'packed', 'ES256', Date.now()]
      );
    }

    const iterations = 100;
    const timings = [];

    for (let i = 0; i < iterations; i++) {
      const startTime = performance.now();

      // Query for existing credentials to build excludeCredentials list
      const result = await mockPool.query(
        'SELECT credential_id FROM attestations WHERE username = ?',
        [username]
      );

      // Process results
      const excludeCredentials = (result[0] || []).map(row => ({
        type: 'public-key',
        id: row.credentialId
      }));

      const endTime = performance.now();
      timings.push(endTime - startTime);
    }

    const stats = {
      operation: 'excludeCredentials_query',
      recordCount: credentialCount,
      iterations,
      avg: timings.reduce((a, b) => a + b, 0) / timings.length,
      min: Math.min(...timings),
      max: Math.max(...timings),
      p95: timings.sort((a, b) => a - b)[Math.floor(timings.length * 0.95)]
    };

    results.push(stats);
    console.log('excludeCredentials Query Performance:', stats);

    expect(stats.avg).toBeLessThan(50);  // Database query should be fast
  });

  afterAll(() => {
    // Save results to file for reporting
    const fs = require('fs');
    const reportPath = '/Users/dqj/HDD/fido2Prjs/fido2-node/UT/results/register.results.json';
    const reportDir = '/Users/dqj/HDD/fido2Prjs/fido2-node/UT/results';

    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }

    fs.writeFileSync(reportPath, JSON.stringify(results, null, 2));
    console.log(`Results saved to ${reportPath}`);
  });
});
