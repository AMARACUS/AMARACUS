/**
 * Sends one real signup-code email (VERIFY account) and one real password-reset
 * email (RECOVERY account) to the given address, to confirm delivery end to end.
 * The code and link are dummies; prints no secrets.
 *
 *   pnpm --filter api exec ts-node --transpile-only scripts/recovery/email-send-test.ts you@example.com
 */
import path from 'path';
import dotenv from 'dotenv';

dotenv.config({ path: path.resolve(__dirname, '..', '..', '..', '..', '.env'), quiet: true } as any);
process.env.NODE_ENV = process.env.NODE_ENV === 'test' ? 'development' : process.env.NODE_ENV || 'development';

async function main() {
  const to = process.argv[2];
  if (!to || !to.includes('@')) {
    console.error('Usage: email-send-test.ts <recipient email>');
    process.exit(2);
  }
  const { sendOtpEmail, sendPasswordResetEmail } = await import('../../src/lib/email-service');

  const otp = await sendOtpEmail(to, '000000', 'AMARACUS test');
  console.log(`Signup code email:    ${otp.success ? 'SENT' : 'FAILED'}${otp.simulated ? ' (simulated)' : ''}`);

  const reset = await sendPasswordResetEmail({
    toEmail: to,
    resetLink: 'https://amaracus.tech/reset-password?token=test-only-not-a-real-token',
    recipientName: 'AMARACUS test',
  });
  console.log(`Password reset email: ${reset.success ? 'SENT' : 'FAILED'}${reset.simulated ? ' (simulated)' : ''}`);

  process.exit(otp.success && reset.success && !otp.simulated && !reset.simulated ? 0 : 1);
}

main().catch((err) => {
  console.error('email-send-test failed:', err.message);
  process.exit(1);
});
