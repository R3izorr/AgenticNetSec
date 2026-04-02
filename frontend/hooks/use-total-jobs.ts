"use client"

import { useCallback, useEffect, useState } from "react"
import { getTotalJobs } from "@/lib/api/analysis"
import { isApiError } from "@/lib/api/client"
import type { TotalJobStatus } from "@/lib/types/analysis"

export function useTotalJobs() {
  const [jobs, setJobs] = useState<TotalJobStatus[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const response = await getTotalJobs()
      setJobs(response.jobs)
      setError(null)
    } catch (err) {
      const message = isApiError(err)
        ? err.detail || err.message
        : err instanceof Error
          ? err.message
          : "Failed to load total jobs."
      setJobs([])
      setError(message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  return {
    jobs,
    loading,
    error,
    refresh,
  }
}
