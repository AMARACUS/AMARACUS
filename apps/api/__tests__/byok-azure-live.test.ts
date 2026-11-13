import dotenv from 'dotenv';
import path from 'path';
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

import { CustomerAzureKeyVaultProvider } from '@amaracus/crypto-core';

describe('Phase 5.2 — Live Azure Key Vault BYOK Verification', () => {
  const vaultUrl = process.env.AZURE_KEY_VAULT_URL;
  const tenantId = process.env.AZURE_TENANT_ID;
  const clientId = process.env.AZURE_CLIENT_ID;
  const clientSecret = process.env.AZURE_CLIENT_SECRET;

  const isConfigured = !!(vaultUrl && tenantId && clientId && clientSecret);

  if (!isConfigured) {
    test.skip('LIVE AZURE TESTS — NOT RUN (Missing AZURE_KEY_VAULT_URL or Azure Service Principal credentials)', () => {
      console.log('[Live Azure BYOK Test] Skipped: Azure environment variables not configured.');
    });
    return;
  }

  test('Live Azure Key Vault: validates delegated authentication and live connectivity', async () => {
    const provider = new CustomerAzureKeyVaultProvider({
      name: 'Live Production Customer Vault',
      providerType: 'AZURE_KEY_VAULT',
      ownershipType: 'CUSTOMER_OWNED',
      vaultUrl: vaultUrl!,
      authType: 'SERVICE_PRINCIPAL',
      tenantId: tenantId!,
      clientId: clientId!,
      clientSecret: clientSecret!,
    });

    const result = await provider.testConnection();

    console.log('[Live Azure Key Vault BYOK Test Result]:', {
      success: result.success,
      vaultUrl: result.vaultUrl,
      accessibleKeysCount: result.accessibleKeysCount,
      latencyMs: result.latencyMs,
      message: result.message,
    });

    expect(result.success).toBe(true);
    expect(result.vaultUrl).toBe(vaultUrl);
    expect(result.latencyMs).toBeGreaterThan(0);
    expect(result.capabilities.supportsEnvelopeEncryption).toBe(true);
    expect(result.capabilities.isFips140Validated).toBe(true);
  }, 30000);
});
