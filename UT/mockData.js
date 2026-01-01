/**
 * Mock Data Generator for FIDO2 Performance Testing
 * Generates realistic mock registration and authentication payloads
 */

const { Readable } = require('stream');

class MockDataGenerator {
  constructor() {
    this.algorithms = {
      RS256: { alg: -7, name: 'RS256' },
      ES256: { alg: -7, name: 'ES256' },
      EdDSA: { alg: -8, name: 'EdDSA' }
    };
  }

  /**
   * Generate registration pre-request payload
   */
  generatePreRegisterRequest(username = 'testuser', rpId = 'example.com') {
    return {
      username,
      rpId,
      displayName: 'Test User',
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'preferred',
        userVerification: 'preferred'
      }
    };
  }

  /**
   * Generate mock attestation object (CBOR encoded)
   * Returns a base64url encoded attestation object
   */
  generateAttestationObject(algorithm = 'ES256') {
    // Simplified CBOR structure for mock data
    const attestationObject = {
      fmt: 'packed',
      attStmt: {
        alg: this.algorithms[algorithm].alg,
        sig: Buffer.from('mock_signature_' + algorithm + '_' + Date.now()).toString('base64')
      },
      authData: this._generateAuthData(algorithm)
    };

    return Buffer.from(JSON.stringify(attestationObject)).toString('base64url');
  }

  /**
   * Generate mock authenticator data
   */
  _generateAuthData(algorithm) {
    const rpIdHash = Buffer.alloc(32);
    rpIdHash.fill(0x01);

    return {
      rpIdHash: rpIdHash.toString('base64'),
      flags: {
        userPresent: true,
        userVerified: true,
        backupEligible: false,
        backupState: false,
        attestedCredentialData: true,
        extensionData: false
      },
      signCount: 0,
      attestedCredentialData: {
        credentialId: this._generateCredentialId(),
        credentialPublicKey: this._generatePublicKey(algorithm)
      }
    };
  }

  /**
   * Generate mock credential ID
   */
  _generateCredentialId() {
    const buf = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
      buf[i] = Math.floor(Math.random() * 256);
    }
    return buf.toString('base64url');
  }

  /**
   * Generate mock public key in COSE format
   */
  _generatePublicKey(algorithm = 'ES256') {
    const baseKey = {
      1: 2,  // kty: EC2
      3: this.algorithms[algorithm].alg,
      '-1': 1  // crv: P-256
    };

    // Add coordinate data
    const coordBuf = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
      coordBuf[i] = Math.floor(Math.random() * 256);
    }

    baseKey['-2'] = coordBuf.toString('base64url');  // x
    baseKey['-3'] = coordBuf.toString('base64url');  // y

    return baseKey;
  }

  /**
   * Generate mock clientDataJSON
   */
  generateClientDataJSON(type = 'webauthn.create', challenge = null) {
    const clientData = {
      type,
      challenge: challenge || this._generateChallenge(),
      origin: 'https://example.com',
      crossOrigin: false
    };

    return Buffer.from(JSON.stringify(clientData)).toString('base64url');
  }

  /**
   * Generate registration response payload
   */
  generateRegistrationResponse(
    username = 'testuser',
    challenge = null,
    algorithm = 'ES256'
  ) {
    const credentialId = this._generateCredentialId();
    const clientDataJSON = this.generateClientDataJSON('webauthn.create', challenge);
    const attestationObject = this.generateAttestationObject(algorithm);

    return {
      id: credentialId,
      rawId: credentialId,
      type: 'public-key',
      response: {
        clientDataJSON,
        attestationObject,
        transports: ['usb', 'ble', 'nfc']
      }
    };
  }

  /**
   * Generate authentication pre-request payload
   */
  generatePreAuthenticateRequest(username = 'testuser', rpId = 'example.com') {
    return {
      username,
      rpId,
      userVerification: 'preferred'
    };
  }

  /**
   * Generate mock authenticator data for assertion
   */
  _generateAssertionAuthData(signCount = 1) {
    const rpIdHash = Buffer.alloc(32);
    rpIdHash.fill(0x01);

    return {
      rpIdHash: rpIdHash.toString('base64'),
      flags: {
        userPresent: true,
        userVerified: true,
        backupEligible: false,
        backupState: false,
        attestedCredentialData: false,
        extensionData: false
      },
      signCount
    };
  }

  /**
   * Generate authentication response payload
   */
  generateAuthenticationResponse(
    credentialId = null,
    challenge = null,
    signCount = 1,
    algorithm = 'ES256'
  ) {
    credentialId = credentialId || this._generateCredentialId();
    challenge = challenge || this._generateChallenge();

    const clientDataJSON = this.generateClientDataJSON('webauthn.get', challenge);
    const authenticatorData = this._generateAssertionAuthData(signCount);

    // Generate mock signature
    const signature = Buffer.from(
      'mock_signature_' + algorithm + '_' + Date.now() + '_' + Math.random()
    ).toString('base64url');

    return {
      id: credentialId,
      rawId: credentialId,
      type: 'public-key',
      response: {
        clientDataJSON,
        authenticatorData: Buffer.from(JSON.stringify(authenticatorData)).toString('base64url'),
        signature,
        userHandle: Buffer.from('user_handle_' + Date.now()).toString('base64url')
      }
    };
  }

  /**
   * Generate random challenge
   */
  _generateChallenge() {
    const buf = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
      buf[i] = Math.floor(Math.random() * 256);
    }
    return buf.toString('base64url');
  }

  /**
   * Generate batch of registration requests
   */
  generateRegistrationBatch(count = 10, algorithm = 'ES256') {
    const batch = [];
    for (let i = 0; i < count; i++) {
      batch.push({
        preRequest: this.generatePreRegisterRequest(`user_${i}`, 'example.com'),
        response: this.generateRegistrationResponse(`user_${i}`, null, algorithm)
      });
    }
    return batch;
  }

  /**
   * Generate batch of authentication requests
   */
  generateAuthenticationBatch(count = 10, credentialIds = null) {
    const batch = [];
    for (let i = 0; i < count; i++) {
      const credId = credentialIds && credentialIds[i] ? credentialIds[i] : this._generateCredentialId();
      batch.push({
        preRequest: this.generatePreAuthenticateRequest(`user_${i}`, 'example.com'),
        response: this.generateAuthenticationResponse(credId, null, i + 1)
      });
    }
    return batch;
  }

  /**
   * Generate dataset with multiple algorithms
   */
  generateMultiAlgorithmDataset(count = 5) {
    const algorithms = Object.keys(this.algorithms);
    const dataset = {};

    algorithms.forEach(algo => {
      dataset[algo] = {
        registrations: this.generateRegistrationBatch(count, algo),
        authentications: this.generateAuthenticationBatch(count)
      };
    });

    return dataset;
  }
}

module.exports = {
  MockDataGenerator,
  createMockDataGenerator: () => new MockDataGenerator()
};
