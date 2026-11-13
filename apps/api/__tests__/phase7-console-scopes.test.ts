import fs from 'fs';
import path from 'path';
import { VALID_SCOPES } from '../src/lib/api-keys';

// The console's "Generate Key" form offered scopes the API rejected (webhooks:manage,
// jobs:execute), so key creation failed with "Invalid scopes provided".
describe('Phase 7: console API-key scopes match the API', () => {
  it('every scope the console offers is accepted by validateScopes', () => {
    const page = fs.readFileSync(
      path.resolve(__dirname, '../../web/src/app/dashboard/api-keys/page.tsx'),
      'utf8'
    );
    const block = page.slice(page.indexOf('const AVAILABLE_SCOPES'), page.indexOf('];', page.indexOf('const AVAILABLE_SCOPES')));
    const offered = [...block.matchAll(/id:\s*"([^"]+)"/g)].map((m) => m[1]);

    expect(offered.length).toBeGreaterThan(0);
    const invalid = offered.filter((s) => !(VALID_SCOPES as readonly string[]).includes(s));
    expect(invalid).toEqual([]);
  });
});
