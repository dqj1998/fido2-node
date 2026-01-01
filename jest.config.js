module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/*.performance.test.js'],
  verbose: true,
  testTimeout: 120000,
  collectCoverageFrom: [
    'UT/mockDatabase.js',
    'UT/mockData.js'
  ]
};
