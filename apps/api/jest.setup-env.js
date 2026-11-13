/**
 * Tests must never reach a real mail server. Some tests switch off the test-runner
 * guard to exercise production behaviour; with real SMTP credentials loaded from
 * .env those would send real email. Blank credentials are set before the app loads,
 * and dotenv does not override variables that already exist.
 */
for (const prefix of ['SMTP', 'VERIFY_SMTP', 'AUTH_SMTP', 'RECOVERY_SMTP', 'SECURITY_SMTP']) {
  process.env[`${prefix}_USER`] = '';
  process.env[`${prefix}_PASS`] = '';
}
process.env.RESEND_API_KEY = '';

/**
 * Test fixture: organizations without a billing subscription get this plan, so suites
 * that are not about billing can use every feature. The entitlement engine reads it only
 * under the test runner; everywhere else such organizations are FREE.
 */
process.env.AMARACUS_TEST_DEFAULT_PLAN = 'BUSINESS';
