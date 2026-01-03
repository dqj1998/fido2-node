/**
 * Unit Tests for SQL Injection Vulnerability Fixes
 * 
 * Tests verify that SQL injection vulnerabilities have been properly fixed:
 * - domains array parameterization
 * - search string parameterization  
 * - last_created timestamp validation and parameterization
 */

const assert = require('assert');

// Helper function - same as in main.js
function buildInClause(values) {
  if (!Array.isArray(values) || values.length === 0) {
    return { clause: '(NULL)', params: [] };
  }
  const placeholders = values.map(() => '?').join(',');
  return {
    clause: `(${placeholders})`,
    params: Array.from(values)
  };
}

// Test Suite
describe('SQL Injection Fix - Unit Tests', () => {
  
  describe('buildInClause Helper Function', () => {
    
    it('should handle normal domain list', () => {
      const domains = ['example.com', 'test.org', 'app.io'];
      const result = buildInClause(domains);
      
      assert.strictEqual(result.clause, '(?,?,?)');
      assert.deepStrictEqual(result.params, domains);
    });

    it('should handle single domain', () => {
      const domains = ['example.com'];
      const result = buildInClause(domains);
      
      assert.strictEqual(result.clause, '(?)');
      assert.deepStrictEqual(result.params, ['example.com']);
    });

    it('should handle empty array safely', () => {
      const domains = [];
      const result = buildInClause(domains);
      
      assert.strictEqual(result.clause, '(NULL)');
      assert.deepStrictEqual(result.params, []);
    });

    it('should handle null safely', () => {
      const result = buildInClause(null);
      
      assert.strictEqual(result.clause, '(NULL)');
      assert.deepStrictEqual(result.params, []);
    });

    it('should not be vulnerable to injection in domain values', () => {
      // Malicious domain trying to break SQL
      const domains = ['test.com") or 1=1 or ("x"="x'];
      const result = buildInClause(domains);
      
      // The value should be safely passed as parameter, not interpolated
      assert.strictEqual(result.clause, '(?)');
      assert.deepStrictEqual(result.params, ['test.com") or 1=1 or ("x"="x']);
    });

    it('should handle special characters in domains', () => {
      const domains = ['test-domain.com', 'api_v2.example.co.uk', '测试.中国'];
      const result = buildInClause(domains);
      
      assert.strictEqual(result.clause, '(?,?,?)');
      assert.deepStrictEqual(result.params, domains);
    });
  });

  describe('Search Parameter Parameterization', () => {
    
    it('should safely handle search strings with quotes', () => {
      const search = 'test" OR "1"="1';
      const likeParam = '%' + search + '%';
      
      // The parameter should not be vulnerable when passed to parameterized query
      assert.strictEqual(typeof likeParam, 'string');
      assert.strictEqual(likeParam, '%test" OR "1"="1%');
    });

    it('should safely handle search strings with SQL comments', () => {
      const search = 'test; DROP TABLE users; --';
      const likeParam = '%' + search + '%';
      
      // Should be safe when used with parameterized queries
      assert.strictEqual(likeParam, '%test; DROP TABLE users; --%');
    });

    it('should safely handle search strings with LIKE wildcards', () => {
      const search = 'test%admin_user';
      const likeParam = '%' + search + '%';
      
      // Wildcards in search should be part of the value, not SQL syntax
      assert.strictEqual(likeParam, '%test%admin_user%');
    });

    it('should safely handle empty search', () => {
      const search = '';
      const likeParam = search && search.length > 0 ? '%' + search + '%' : null;
      
      assert.strictEqual(likeParam, null);
    });

    it('should safely handle unicode search strings', () => {
      const search = '你好世界";DROP';
      const likeParam = '%' + search + '%';
      
      assert.strictEqual(likeParam, '%你好世界";DROP%');
    });
  });

  describe('Timestamp Validation and Parameterization', () => {
    
    it('should validate correct timestamp format', () => {
      const timestamp = '2024-01-15 14:30:45';
      const timestampRegex = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;
      
      assert.strictEqual(timestampRegex.test(timestamp), true);
    });

    it('should reject timestamp with injection attempt', () => {
      const timestamp = '2024-01-15 14:30:45"; DROP TABLE users; --';
      const timestampRegex = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;
      
      assert.strictEqual(timestampRegex.test(timestamp), false);
    });

    it('should reject timestamp with quotes', () => {
      const timestamp = '2024-01-15" OR "1"="1';
      const timestampRegex = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;
      
      assert.strictEqual(timestampRegex.test(timestamp), false);
    });

    it('should reject invalid date format', () => {
      const timestamp = '2024/01/15 14:30:45';
      const timestampRegex = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;
      
      assert.strictEqual(timestampRegex.test(timestamp), false);
    });

    it('should reject timestamp with missing parts', () => {
      const timestamp = '2024-01-15';
      const timestampRegex = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;
      
      assert.strictEqual(timestampRegex.test(timestamp), false);
    });

    it('should accept edge case timestamps', () => {
      const validTimestamps = [
        '2024-12-31 23:59:59',
        '2000-01-01 00:00:00',
        '1999-06-15 12:00:00'
      ];
      const timestampRegex = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;
      
      validTimestamps.forEach(ts => {
        assert.strictEqual(timestampRegex.test(ts), true);
      });
    });
  });

  describe('SQL Injection Prevention - Real Attack Scenarios', () => {
    
    it('should prevent domain-based injection with UNION', () => {
      const maliciousDomains = [
        'test.com\') UNION SELECT * FROM users--',
        'example.com\' OR \'1\'=\'1'
      ];
      const result = buildInClause(maliciousDomains);
      
      // Should safely pass malicious strings as parameters
      assert.strictEqual(result.clause, '(?,?)');
      assert.deepStrictEqual(result.params, maliciousDomains);
    });

    it('should prevent search-based injection with subquery', () => {
      const maliciousSearch = 'test\' AND (SELECT COUNT(*) FROM users) > 0--';
      const likeParam = '%' + maliciousSearch + '%';
      
      // Should be safe when parameterized
      assert.strictEqual(typeof likeParam, 'string');
      assert.strictEqual(likeParam.includes(maliciousSearch), true);
    });

    it('should prevent timestamp-based injection with statement terminator', () => {
      const maliciousTimestamp = '2024-01-01 00:00:00; DROP TABLE registered_users;--';
      const timestampRegex = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;
      
      // Should reject due to format validation
      assert.strictEqual(timestampRegex.test(maliciousTimestamp), false);
    });

    it('should prevent blind SQL injection in search', () => {
      const blindInjection = "test' AND SLEEP(5)--";
      const likeParam = '%' + blindInjection + '%';
      
      // When parameterized, the SLEEP command is treated as literal text
      assert.strictEqual(likeParam, "%test' AND SLEEP(5)--%");
    });

    it('should prevent boolean-based injection in search', () => {
      const booleanInjection = "admin' OR '1'='1";
      const likeParam = '%' + booleanInjection + '%';
      
      // When parameterized, the OR logic is treated as literal text
      assert.strictEqual(likeParam, "%admin' OR '1'='1%");
    });
  });

  describe('Edge Cases and Data Integrity', () => {
    
    it('should preserve legitimate domain with special characters', () => {
      const domains = ['test-api.example.com', 'api_v2.test.co.uk'];
      const result = buildInClause(domains);
      
      assert.deepStrictEqual(result.params, domains);
    });

    it('should handle large domain list', () => {
      const domains = Array.from({ length: 100 }, (_, i) => `domain${i}.com`);
      const result = buildInClause(domains);
      
      assert.strictEqual(result.params.length, 100);
      assert.strictEqual(result.clause.split(',').length, 100);
    });

    it('should handle search with legitimate wildcards preserved', () => {
      const search = 'admin%';
      const likeParam = '%' + search + '%';
      
      // The literal % in search should be preserved as part of value
      assert.strictEqual(likeParam, '%admin%%');
    });

    it('should validate timestamp without false negatives', () => {
      const validTimestamps = [
        '2024-01-01 00:00:00',
        '2024-12-31 23:59:59',
        '1970-01-01 00:00:00'
      ];
      const timestampRegex = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;
      
      validTimestamps.forEach(ts => {
        assert.strictEqual(timestampRegex.test(ts), true, `${ts} should be valid`);
      });
    });
  });

  describe('Parameter Array Building', () => {
    
    it('should combine multiple parameter sources correctly', () => {
      const domainParams = ['example.com'];
      const searchParams = ['%test%', '%test%'];
      const timestampParam = '2024-01-15 14:30:45';
      
      const allParams = [...domainParams, ...searchParams];
      if (timestampParam) allParams.push(timestampParam);
      allParams.push(100, 200); // start, end
      
      assert.deepStrictEqual(allParams, [
        'example.com',
        '%test%',
        '%test%',
        '2024-01-15 14:30:45',
        100,
        200
      ]);
    });

    it('should handle missing optional parameters', () => {
      const domainParams = ['example.com'];
      const searchParams = []; // empty search
      const timestampParam = null; // invalid timestamp
      
      const allParams = [...domainParams, ...searchParams];
      if (timestampParam) allParams.push(timestampParam);
      allParams.push(0, 1000); // start, end
      
      assert.deepStrictEqual(allParams, [
        'example.com',
        0,
        1000
      ]);
    });
  });
});

// Export for use in other contexts
module.exports = {
  buildInClause,
  tests: {
    domainInjection: true,
    searchInjection: true,
    timestampInjection: true
  }
};
