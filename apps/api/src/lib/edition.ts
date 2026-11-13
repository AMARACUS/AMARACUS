/**
 * Which product this process is: AMARACUS Cloud (the hosted service at amaracus.tech) or a
 * self-hosted installation run by a customer on their own infrastructure.
 *
 * - `AMARACUS_EDITION=cloud` or `AMARACUS_EDITION=selfhosted` decides it.
 * - Unset: `cloud` when the Cloud module (src/cloud) is in this source tree, which is only the
 *   case in AMARACUS's private repository. The public source tree does not contain that
 *   module, so it always runs as `selfhosted` and can never run as `cloud`.
 */
export type Edition = 'cloud' | 'selfhosted';

let cloudModulePresent: boolean | null = null;

/** True when the Cloud-only module (billing, webhooks, hosted-site features) is in this tree. */
export function isCloudModulePresent(): boolean {
  if (cloudModulePresent === null) {
    try {
      require.resolve('../cloud');
      cloudModulePresent = true;
    } catch {
      cloudModulePresent = false;
    }
  }
  return cloudModulePresent;
}

export function getEdition(): Edition {
  const raw = (process.env.AMARACUS_EDITION || '').trim().toLowerCase();
  if (raw === 'selfhosted' || raw === 'self-hosted' || raw === 'self_hosted') return 'selfhosted';
  if (!isCloudModulePresent()) return 'selfhosted';
  // The private repository (Cloud module present) runs as the hosted service unless told
  // otherwise, so AMARACUS Cloud needs no new variable and cannot flip edition by accident.
  return 'cloud';
}

export function isSelfHosted(): boolean {
  return getEdition() === 'selfhosted';
}

export function isCloud(): boolean {
  return getEdition() === 'cloud';
}

/** Problems with the AMARACUS_EDITION value itself, for startup validation. */
export function editionConfigErrors(): string[] {
  const raw = (process.env.AMARACUS_EDITION || '').trim().toLowerCase();
  const errors: string[] = [];
  if (raw && !['cloud', 'selfhosted', 'self-hosted', 'self_hosted'].includes(raw)) {
    errors.push(`AMARACUS_EDITION must be "selfhosted" or "cloud" (got "${raw}").`);
  }
  if (raw === 'cloud' && !isCloudModulePresent()) {
    errors.push(
      'AMARACUS_EDITION=cloud is not available in this source tree: it does not contain the AMARACUS Cloud module. Use AMARACUS_EDITION=selfhosted.'
    );
  }
  return errors;
}

/**
 * The Cloud module, or null on a self-hosted installation and in a source tree without it.
 * Typed loosely on purpose: nothing outside `src/cloud` may depend on its types.
 */
export function loadCloudModule(): any | null {
  if (getEdition() !== 'cloud') return null;
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require('../cloud');
}
