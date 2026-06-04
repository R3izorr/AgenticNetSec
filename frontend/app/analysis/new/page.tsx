"use client"

import { useMemo, useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"

import { InlineNotice } from "@/components/common/inline-notice"
import { EmptyState } from "@/components/common/page-state"
import { SectionCard } from "@/components/common/section-card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useToast } from "@/components/ui/toast"
import { useAuth } from "@/components/providers/auth-provider"
import { createBatchAnalysisJob } from "@/lib/api/analysis"
import { isApiError } from "@/lib/api/client"
import { adaptTotalJobStatus } from "@/lib/adapters/analysis"
import type { AnalysisProfile } from "@/lib/types/analysis"
import { canCreateAnalysis } from "@/lib/permissions"

const MIN_WORKERS = 2

export default function NewAnalysisPage() {
  const router = useRouter()
  const { pushToast } = useToast()
  const { session } = useAuth()
  const mayCreateAnalysis = canCreateAnalysis(session?.organization.role)

  const [files, setFiles] = useState<File[]>([])
  const [workerCount, setWorkerCount] = useState<number>(MIN_WORKERS)
  const [analysisProfile, setAnalysisProfile] = useState<AnalysisProfile>("standard")
  const [submitting, setSubmitting] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const selectedCount = files.length
  const helperText = useMemo(() => {
    if (!selectedCount) {
      return "Select one or more PCAP files to create a total job."
    }
    return `${selectedCount} file${selectedCount === 1 ? "" : "s"} selected for one total job.`
  }, [selectedCount])

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setFormError(null)

    if (!files.length) {
      setFormError("Please select at least one PCAP file before submitting.")
      return
    }

    setSubmitting(true)
    try {
      const response = await createBatchAnalysisJob({
        files,
        workerCount: Math.max(MIN_WORKERS, Math.round(workerCount || MIN_WORKERS)),
        analysisProfile,
      })
      const totalJob = adaptTotalJobStatus(response)
      pushToast({
        variant: "success",
        title: "Batch started",
        description: `Total job ${totalJob.totalJobId} now tracks ${totalJob.fileCount} file${totalJob.fileCount === 1 ? "" : "s"}.`,
      })
      router.push(`/total-jobs/${encodeURIComponent(totalJob.totalJobId)}`)
    } catch (error) {
      const message = isApiError(error)
        ? error.detail || error.message
        : error instanceof Error
          ? error.message
          : "Failed to submit batch analysis."
      setFormError(message)
      pushToast({
        variant: "error",
        title: "Submission failed",
        description: message,
      })
    } finally {
      setSubmitting(false)
    }
  }

  if (!mayCreateAnalysis) {
    return (
      <div className="flex flex-col gap-6">
        <EmptyState
          title="Analysis creation unavailable"
          description="Your current role can review jobs and reports but cannot submit PCAP files."
          action={
            <div className="flex items-center gap-2">
              <Button asChild>
                <Link href="/analysis/history">Open History</Link>
              </Button>
              <Button variant="outline" asChild>
                <Link href="/total-jobs">View Total Jobs</Link>
              </Button>
            </div>
          }
        />
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <SectionCard
        title="Submit Batch Analysis"
        subtitle="Every submission becomes one total job, whether you choose one PCAP or many."
      >
        <form className="flex flex-col gap-5" onSubmit={onSubmit}>
          <div className="flex flex-col gap-2">
            <Label htmlFor="pcap-files">PCAP files</Label>
            <Input
              id="pcap-files"
              type="file"
              accept=".pcap,.pcapng,.cap"
              multiple
              onChange={(event) => {
                setFiles(Array.from(event.target.files ?? []))
              }}
              className="h-auto bg-card py-2"
            />
            <p className="text-xs text-muted-foreground">{helperText}</p>
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <div className="flex flex-col gap-2">
              <Label htmlFor="worker-count">Worker count</Label>
              <Input
                id="worker-count"
                type="number"
                min={MIN_WORKERS}
                step={1}
                value={workerCount}
                onChange={(event) => setWorkerCount(Number(event.target.value) || MIN_WORKERS)}
                className="bg-card"
              />
              <p className="text-xs text-muted-foreground">
                Batch execution uses at least {MIN_WORKERS} workers. Higher values can speed up deterministic analysis.
              </p>
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="analysis-profile">Stage 1 profile</Label>
              <Select value={analysisProfile} onValueChange={(value) => setAnalysisProfile(value as AnalysisProfile)}>
                <SelectTrigger id="analysis-profile" className="bg-card">
                  <SelectValue placeholder="Select a stage-1 profile" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="fast">Fast</SelectItem>
                  <SelectItem value="standard">Standard</SelectItem>
                  <SelectItem value="full">Full</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Fast is triage only. Standard is recommended and only runs deep dive or carving when evidence justifies it. Full keeps all heavy deterministic steps.
              </p>
            </div>
            <div className="rounded-lg border border-border/70 bg-background/40 p-4 text-sm text-muted-foreground">
              <p className="font-medium text-foreground">Run flow</p>
              <p className="mt-2">
                Stage 1 runs code-only analysis for each file. AI summary and sandbox are triggered later from the total-job page.
              </p>
              <p className="mt-2">
                Active profile: <span className="font-medium text-foreground">{analysisProfile}</span>
              </p>
            </div>
          </div>

          {formError ? <InlineNotice variant="error">{formError}</InlineNotice> : null}

          <div className="flex items-center gap-3">
            <Button type="submit" disabled={submitting}>
              {submitting ? "Submitting..." : "Start Batch"}
            </Button>
            <p className="text-xs text-muted-foreground">The backend creates child jobs automatically after submission.</p>
          </div>
        </form>
      </SectionCard>
    </div>
  )
}
