import { isCloud } from '../../src/lib/edition';

/**
 * For tests of AMARACUS Cloud behaviour (plans, the hosted service's own senders and pages,
 * Trigger.dev and moderation routes). They run in the private repository, which has the Cloud
 * module, and are skipped in the public, self-hosted source tree.
 */
export const describeCloud: jest.Describe = (isCloud() ? describe : describe.skip) as jest.Describe;
export const itCloud: jest.It = (isCloud() ? it : it.skip) as jest.It;
