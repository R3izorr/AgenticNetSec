"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import { getTotalJobStatus } from "@/lib/api/analysis"
import { isApiError } from "@/lib/api/client"
import { adaptTotalJobStatus } from "@/lib/adapters/analysis"
import { useAppSettings } from "@/components/providers/app-settings-provider"
import type { TotalJobStatus } from "@/lib/types/analysis"

const POLLING_STATES = new Set(["queued", "running"])
const POLLING_STAGES = new Set(["deterministic_analysis", "enrichment_running"])
const POLLING_ENRICHMENT_STATES = new Set(["queued", "running"])

export function useTotalJobStatus(totalJobId: string) {
  const { resolvedPollIntervalMs } = useAppSettings()
  const [job, setJob] = useState<TotalJobStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const response = await getTotalJobStatus(totalJobId)
      setJob(adaptTotalJobStatus(response))
      setError(null)
    } catch (err) {
      const message = isApiError(err)
        ? err.detail || err.message
        : err instanceof Error
          ? err.message
          : "Failed to load total job."
      setError(message)
    } finally {
      setLoading(false)
    }
  }, [totalJobId])

  useEffect(() => {
    setLoading(true)
    void refresh()
  }, [refresh])

  const shouldPoll = useMemo(() => {
    if (!job) {
      return false
    }
    return (
      POLLING_STATES.has(job.status.toLowerCase()) ||
      POLLING_STAGES.has(job.currentStage) ||
      POLLING_ENRICHMENT_STATES.has(job.enrichmentStatus.toLowerCase())
    )
  }, [job])

  useEffect(() => {
    if (!shouldPoll) {
      return
    }
    const timer = window.setTimeout(() => {
      void refresh()
    }, resolvedPollIntervalMs)
    return () => window.clearTimeout(timer)
  }, [refresh, resolvedPollIntervalMs, shouldPoll, job?.status, job?.currentStage, job?.progress, job?.enrichmentStatus, job?.enrichmentProgress])

  return {
    job,
    loading,
    error,
    refresh,
    isPolling: shouldPoll,
  }
}
