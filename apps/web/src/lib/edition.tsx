'use client';

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { api } from './api-client';
import { cloudDefaults } from './cloud/cloud-defaults';
import type { SelfHostStatus } from './selfhost';

export type Edition = 'cloud' | 'selfhosted' | 'unknown';

interface EditionContextValue {
  /** 'unknown' only while the first lookup is in flight. */
  edition: Edition;
  /** The self-hosted status (null on Cloud). */
  status: SelfHostStatus | null;
  /** Ask the API again, e.g. after accepting the licences or adding a licence key. */
  refresh: () => Promise<void>;
}

const EditionContext = createContext<EditionContextValue | undefined>(undefined);

// Looked up once per page load and shared by every component that asks.
let inflight: Promise<SelfHostStatus | null> | null = null;

/** The API answers 404 on /v1/selfhost/status when it is AMARACUS Cloud; any failure also means Cloud. */
function probe(force: boolean): Promise<SelfHostStatus | null> {
  if (!inflight || force) {
    inflight = api.selfhost
      .status()
      .then((res) => (res?.data?.edition === 'selfhosted' ? res.data : null))
      .catch(() => null);
  }
  return inflight;
}

/** Whether this build asks the API for its edition at all (AMARACUS Cloud builds do not). */
const PROBE_ENABLED = cloudDefaults.probeEdition || process.env.NEXT_PUBLIC_EDITION_PROBE === '1';

export function EditionProvider({ children }: { children: React.ReactNode }) {
  const [edition, setEdition] = useState<Edition>(PROBE_ENABLED ? 'unknown' : 'cloud');
  const [status, setStatus] = useState<SelfHostStatus | null>(null);

  const load = useCallback(async (force: boolean) => {
    if (!PROBE_ENABLED) return;
    const result = await probe(force);
    setStatus(result);
    setEdition(result ? 'selfhosted' : 'cloud');
  }, []);

  useEffect(() => {
    void load(false);
  }, [load]);

  const refresh = useCallback(() => load(true), [load]);
  const value = useMemo(() => ({ edition, status, refresh }), [edition, status, refresh]);

  return <EditionContext.Provider value={value}>{children}</EditionContext.Provider>;
}

export function useEdition(): EditionContextValue {
  const ctx = useContext(EditionContext);
  if (!ctx) throw new Error('useEdition must be used within EditionProvider');
  return ctx;
}
