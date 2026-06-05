"use client"

import { useCallback, useEffect, useState } from "react"
import { isApiError } from "@/lib/api/client"
import { useAppSettings } from "@/components/providers/app-settings-provider"

interface ArtifactState<T> {
  data: T | null
  loading: boolean
  error: string | null
  notReady: boolean
  reload: () => Promise<void>
}

interface UseArtifactOptions {
  pollWhileNotReady?: boolean
  pollIntervalMs?: number
}

export function useArtifact<T>(
  loader: () => Promise<T>,
  deps: unknown[],
  options?: UseArtifactOptions
): ArtifactState<T> {
  const { resolvedPollIntervalMs } = useAppSettings()
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notReady, setNotReady] = useState(false)

  const reload = useCallback(async () => {
    setLoading(true)
    try {
      const value = await loader()
      setData(value)
      setError(null)
      setNotReady(false)
    } catch (err) {
      if (isApiError(err) && err.status === 409) {
        setNotReady(true)
        setError(err.detail || "Artifact is not ready yet.")
      } else if (isApiError(err)) {
        setNotReady(false)
        setError(err.detail || err.message)
      } else {
        setNotReady(false)
        setError("Failed to load artifact.")
      }
    } finally {
      setLoading(false)
    }
  }, [loader])

  useEffect(() => {
    void reload()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  useEffect(() => {
    if (!options?.pollWhileNotReady || !notReady) {
      return
    }

    const timer = window.setTimeout(() => {
      void reload()
    }, options.pollIntervalMs ?? resolvedPollIntervalMs)

    return () => window.clearTimeout(timer)
  }, [notReady, options?.pollIntervalMs, options?.pollWhileNotReady, reload, resolvedPollIntervalMs])

  return {
    data,
    loading,
    error,
    notReady,
    reload,
  }
}
