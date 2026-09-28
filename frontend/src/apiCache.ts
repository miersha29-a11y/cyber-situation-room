import { useCallback, useEffect, useRef, useState } from "react";

export type CachePolicy = {
  staleTime?: number;
  enabled?: boolean;
};

type CacheEntry = {
  data: unknown;
  timestamp: number;
};

const DEFAULT_STALE_TIME = 60_000;

const cache = new Map<string, CacheEntry>();
const inFlight = new Map<string, Promise<unknown>>();
const listeners = new Set<() => void>();

function notifyInvalidation() {
  listeners.forEach((listener) => listener());
}

export function invalidateApiCache(prefix?: string) {
  if (!prefix) {
    cache.clear();
  } else {
    for (const key of cache.keys()) {
      if (key.startsWith(prefix)) cache.delete(key);
    }
  }

  notifyInvalidation();
}

export function clearApiCache() {
  invalidateApiCache();
}

async function fetchJson<T>(url: string): Promise<T> {
  const existingRequest = inFlight.get(url);
  if (existingRequest) return existingRequest as Promise<T>;

  const request = fetch(url).then(async (response) => {
    if (!response.ok) {
      throw new Error(`API request failed: ${response.status} ${response.statusText}`);
    }
    return (await response.json()) as T;
  });

  inFlight.set(url, request);

  try {
    return await request;
  } finally {
    inFlight.delete(url);
  }
}

export function useCachedApi<T>(
  key: string,
  url: string,
  policy: CachePolicy = {}
) {
  const staleTime = policy.staleTime ?? DEFAULT_STALE_TIME;
  const enabled = policy.enabled ?? true;
  const [state, setState] = useState<{
    data: T | undefined;
    loading: boolean;
    error: Error | null;
  }>(() => {
    const entry = cache.get(key);
    const fresh = entry && Date.now() - entry.timestamp < staleTime;
    return {
      data: fresh ? (entry.data as T) : undefined,
      loading: !fresh,
      error: null,
    };
  });

  const mountedRef = useRef(true);

  const load = useCallback(
    async (force = false) => {
      if (!enabled) return undefined;

      const entry = cache.get(key);
      const fresh = entry && Date.now() - entry.timestamp < staleTime;

      if (!force && fresh) {
        if (mountedRef.current) {
          setState({
            data: entry.data as T,
            loading: false,
            error: null,
          });
        }
        return entry.data as T;
      }

      if (mountedRef.current) {
        setState((current) => ({
          ...current,
          loading: !current.data,
          error: null,
        }));
      }

      try {
        const data = await fetchJson<T>(url);
        cache.set(key, { data, timestamp: Date.now() });

        if (mountedRef.current) {
          setState({ data, loading: false, error: null });
        }

        return data;
      } catch (error) {
        const normalized =
          error instanceof Error ? error : new Error("API request failed");

        if (mountedRef.current) {
          setState((current) => ({
            ...current,
            loading: false,
            error: normalized,
          }));
        }

        throw normalized;
      }
    },
    [enabled, key, staleTime, url]
  );

  useEffect(() => {
    mountedRef.current = true;

    if (!enabled) return () => {
      mountedRef.current = false;
    };

    const handleInvalidation = () => {
      if (mountedRef.current) {
        void load(true).catch(() => undefined);
      }
    };

    listeners.add(handleInvalidation);
    void load().catch(() => undefined);

    return () => {
      mountedRef.current = false;
      listeners.delete(handleInvalidation);
    };
  }, [enabled, load]);

  return {
    data: state.data,
    loading: state.loading,
    error: state.error,
    refetch: () => load(true),
  };
}
