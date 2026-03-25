"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import { getAnalysisJobStatus } from "@/lib/api/analysis"
import { isApiError } from "@/lib/api/client"
import { adaptJobStatus } from "@/lib/adapters/analysis"
import { useAppSettings } from "@/components/providers/app-settings-provider"
import type { JobStatus } from "@/lib/types/analysis"

const POLLING_STATUSES = new Set(["queued", "running"])

export function useJobStatus(jobId: string) {
  const { resolvedPollIntervalMs } = useAppSettings()
  const [job, setJob] = useState<JobStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastUpdatedAt, setLastUpdatedAt] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const response = await getAnalysisJobStatus(jobId)
      setJob(adaptJobStatus(response))
      setError(null)
      setLastUpdatedAt(new Date().toISOString())
    } catch (err) {
      if (isApiError(err)) {
        setError(err.detail || err.message)
      } else {
        setError("Failed to load job status.")
      }
    } finally {
      setLoading(false)
    }
  }, [jobId])

  useEffect(() => {
    setLoading(true)
    void refresh()
  }, [refresh])

  const shouldPoll = useMemo(() => {
    if (!job) {
      return false
    }
    return POLLING_STATUSES.has(job.status.toLowerCase())
  }, [job])

  useEffect(() => {
    if (!shouldPoll) {
      return
    }

    const timer = window.setTimeout(() => {
      void refresh()
    }, resolvedPollIntervalMs)

    return () => window.clearTimeout(timer)
  }, [refresh, resolvedPollIntervalMs, shouldPoll, job?.status, job?.currentPhase, job?.progress])

  return {
    job,
    loading,
    error,
    refresh,
    isPolling: shouldPoll,
    lastUpdatedAt,
  }
}
