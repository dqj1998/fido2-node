/**
 * Mock Database Module with configurable latency simulation
 * Simulates MySQL operations with realistic delays for performance testing
 */

class MockConnection {
  constructor(delayConfig = {}) {
    this.delayConfig = {
      query: 10,
      insert: 15,
      update: 12,
      select: 8,
      ...delayConfig
    };
    this.data = {
      users: new Map(),
      credentials: new Map(),
      sessions: new Map(),
      logs: []
    };
  }

  /**
   * Execute a query with simulated delay
   * @param {string} sql - SQL query
   * @param {array} params - Query parameters
   * @returns {Promise} Query result
   */
  async query(sql, params = []) {
    const delay = this._getDelay(sql);
    await this._simulateDelay(delay);

    // Parse simple SQL operations
    if (sql.includes('INSERT')) {
      return this._handleInsert(sql, params);
    } else if (sql.includes('UPDATE')) {
      return this._handleUpdate(sql, params);
    } else if (sql.includes('SELECT')) {
      return this._handleSelect(sql, params);
    } else if (sql.includes('DELETE')) {
      return this._handleDelete(sql, params);
    }

    return { affectedRows: 0 };
  }

  /**
   * Get delay based on operation type
   * @private
   */
  _getDelay(sql) {
    const upperSql = sql.toUpperCase();
    if (upperSql.includes('INSERT')) return this.delayConfig.insert;
    if (upperSql.includes('UPDATE')) return this.delayConfig.update;
    if (upperSql.includes('SELECT')) return this.delayConfig.select;
    return this.delayConfig.query;
  }

  /**
   * Simulate database latency
   * @private
   */
  async _simulateDelay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Handle INSERT operations
   * @private
   */
  _handleInsert(sql, params) {
    if (sql.includes('users')) {
      const [username, rpId] = params;
      this.data.users.set(username, {
        username,
        rpId,
        createdAt: Date.now()
      });
      return { affectedRows: 1, insertId: 1 };
    } else if (sql.includes('credentials') || sql.includes('attestations')) {
      const [username, credentialId, credentialPublicKey, counter, attestationFormat, credentialAlgorithm] = params;
      const key = `${username}_${credentialId}`;
      this.data.credentials.set(key, {
        username,
        credentialId,
        credentialPublicKey,
        counter,
        attestationFormat,
        credentialAlgorithm,
        createdAt: Date.now()
      });
      return { affectedRows: 1, insertId: 1 };
    } else if (sql.includes('sessions')) {
      const [sessionId, username, domain] = params;
      this.data.sessions.set(sessionId, {
        sessionId,
        username,
        domain,
        createdAt: Date.now()
      });
      return { affectedRows: 1 };
    }
    return { affectedRows: 0 };
  }

  /**
   * Handle UPDATE operations
   * @private
   */
  _handleUpdate(sql, params) {
    if (sql.includes('counter') || sql.includes('attestations')) {
      // Update counter for credential
      const [counter, username, credentialId] = params;
      const key = `${username}_${credentialId}`;
      if (this.data.credentials.has(key)) {
        const cred = this.data.credentials.get(key);
        cred.counter = counter;
        cred.updatedAt = Date.now();
        return { affectedRows: 1 };
      }
    }
    return { affectedRows: 0 };
  }

  /**
   * Handle SELECT operations
   * @private
   */
  _handleSelect(sql, params) {
    if (sql.includes('credentials') || sql.includes('attestations')) {
      if (sql.includes('WHERE')) {
        const [username] = params;
        const credentials = [];
        this.data.credentials.forEach((cred, key) => {
          if (cred.username === username) {
            credentials.push(cred);
          }
        });
        return [credentials, null];
      }
    } else if (sql.includes('users')) {
      const [username] = params;
      const user = this.data.users.get(username);
      return user ? [[user], null] : [[], null];
    }
    return [[], null];
  }

  /**
   * Handle DELETE operations
   * @private
   */
  _handleDelete(sql, params) {
    return { affectedRows: 0 };
  }

  /**
   * Release connection
   */
  release() {
    // Mock release - no-op
  }
}

class MockConnectionPool {
  constructor(delayConfig = {}) {
    this.delayConfig = delayConfig;
    this.poolConnections = [];
    this.activeConnections = new Set();
    this.maxConnections = 10;
    this.connectionTimeout = 10000;

    // Initialize pool
    for (let i = 0; i < this.maxConnections; i++) {
      this.poolConnections.push(new MockConnection(delayConfig));
    }
  }

  /**
   * Get a connection from the pool
   */
  async getConnection() {
    if (this.poolConnections.length === 0) {
      throw new Error('No available connections in pool');
    }
    const connection = this.poolConnections.pop();
    this.activeConnections.add(connection);
    return connection;
  }

  /**
   * Execute query using a pooled connection
   */
  async query(sql, params = []) {
    const connection = await this.getConnection();
    try {
      const result = await connection.query(sql, params);
      return result;
    } finally {
      this.activeConnections.delete(connection);
      this.poolConnections.push(connection);
    }
  }

  /**
   * Get pool statistics
   */
  getStats() {
    return {
      activeConnections: this.activeConnections.size,
      availableConnections: this.poolConnections.length,
      totalConnections: this.maxConnections
    };
  }

  /**
   * Clear all data (for testing)
   */
  clearData() {
    this.poolConnections.forEach(conn => {
      conn.data = {
        users: new Map(),
        credentials: new Map(),
        sessions: new Map(),
        logs: []
      };
    });
  }

  /**
   * End the pool
   */
  end() {
    this.poolConnections = [];
    this.activeConnections.clear();
  }
}

module.exports = {
  MockConnection,
  MockConnectionPool,
  createMockPool: (delayConfig) => new MockConnectionPool(delayConfig)
};
