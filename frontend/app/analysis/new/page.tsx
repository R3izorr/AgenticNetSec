"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { SectionCard } from "@/components/common/section-card"
import { createAnalysisJob } from "@/lib/api/analysis"
import { isApiError } from "@/lib/api/client"
import { adaptJobStatus } from "@/lib/adapters/analysis"
import { useToast } from "@/components/ui/toast"

export default function NewAnalysisPage() {
  const router = useRouter()
  const { pushToast } = useToast()

  const [inputMode, setInputMode] = useState<"file" | "path">("file")
  const [file, setFile] = useState<File | undefined>(undefined)
  const [pcapPath, setPcapPath] = useState("")
  const [provider, setProvider] = useState("gemini")
  const [model, setModel] = useState("")
  const [useAi, setUseAi] = useState(true)
  const [requireAi, setRequireAi] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setFormError(null)

    if (inputMode === "file" && !file) {
      setFormError("Please select a PCAP file before submitting.")
      return
    }

    if (inputMode === "path" && !pcapPath.trim()) {
      setFormError("Please enter a pcap_path before submitting.")
      return
    }

    setSubmitting(true)
    try {
      const response = await createAnalysisJob({
        file: inputMode === "file" ? file : undefined,
        pcapPath: inputMode === "path" ? pcapPath : undefined,
        provider: provider.trim() || undefined,
        model: model.trim() || undefined,
        useAi,
        requireAi,
      })

      const job = adaptJobStatus(response)
      pushToast({
        variant: "success",
        title: "Analysis started",
        description: `Job ${job.analysisJobId} has been queued.`,
      })
      router.push(`/analysis/${job.analysisJobId}`)
    } catch (error) {
      const message = isApiError(error)
        ? error.detail || error.message
        : error instanceof Error
          ? error.message
          : "Failed to submit analysis job."

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

  return (
    <div className="space-y-6">
      <SectionCard
        title="Submit Analysis"
        subtitle="Provide exactly one input source: file upload or pcap_path."
      >
        <form className="space-y-5" onSubmit={onSubmit}>
          <div className="grid gap-3 sm:grid-cols-2">
            <button
              type="button"
              onClick={() => {
                setInputMode("file")
                setPcapPath("")
              }}
              className={`rounded-lg border px-4 py-3 text-left transition ${
                inputMode === "file"
                  ? "border-primary/40 bg-primary/10"
                  : "border-border hover:bg-muted"
              }`}
            >
              <p className="text-sm font-medium">Upload PCAP File</p>
              <p className="mt-1 text-xs text-muted-foreground">
                Use local file input and send multipart upload.
              </p>
            </button>
            <button
              type="button"
              onClick={() => {
                setInputMode("path")
                setFile(undefined)
              }}
              className={`rounded-lg border px-4 py-3 text-left transition ${
                inputMode === "path"
                  ? "border-primary/40 bg-primary/10"
                  : "border-border hover:bg-muted"
              }`}
            >
              <p className="text-sm font-medium">Use pcap_path</p>
              <p className="mt-1 text-xs text-muted-foreground">
                Provide a backend-readable filesystem path.
              </p>
            </button>
          </div>

          {inputMode === "file" ? (
            <div className="space-y-2">
              <label htmlFor="pcap-file" className="text-sm font-medium">
                PCAP file
              </label>
              <input
                id="pcap-file"
                type="file"
                accept=".pcap,.pcapng"
                onChange={(event) => setFile(event.target.files?.[0])}
                className="block w-full rounded-lg border border-input bg-card px-3 py-2 text-sm"
              />
            </div>
          ) : (
            <div className="space-y-2">
              <label htmlFor="pcap-path" className="text-sm font-medium">
                pcap_path
              </label>
              <input
                id="pcap-path"
                type="text"
                value={pcapPath}
                onChange={(event) => setPcapPath(event.target.value)}
                placeholder="C:\\captures\\case1.pcap"
                className="block w-full rounded-lg border border-input bg-card px-3 py-2 text-sm"
              />
            </div>
          )}

          <details className="rounded-lg border border-border bg-background/40 p-4">
            <summary className="cursor-pointer text-sm font-medium">Advanced options</summary>
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <label className="space-y-1 text-sm">
                <span className="text-muted-foreground">Provider</span>
                <input
                  type="text"
                  value={provider}
                  onChange={(event) => setProvider(event.target.value)}
                  className="block w-full rounded-md border border-input bg-card px-2 py-1.5"
                />
              </label>
              <label className="space-y-1 text-sm">
                <span className="text-muted-foreground">Model (optional)</span>
                <input
                  type="text"
                  value={model}
                  onChange={(event) => setModel(event.target.value)}
                  className="block w-full rounded-md border border-input bg-card px-2 py-1.5"
                />
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={useAi}
                  onChange={(event) => setUseAi(event.target.checked)}
                />
                <span>use_ai</span>
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={requireAi}
                  onChange={(event) => setRequireAi(event.target.checked)}
                />
                <span>require_ai</span>
              </label>
            </div>
          </details>

          {formError ? (
            <p className="rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-sm text-red-200">
              {formError}
            </p>
          ) : null}

          <div className="flex items-center gap-3">
            <Button type="submit" disabled={submitting}>
              {submitting ? "Submitting..." : "Start Analysis"}
            </Button>
            <p className="text-xs text-muted-foreground">
              Analysis runs autonomously after submission.
            </p>
          </div>
        </form>
      </SectionCard>
    </div>
  )
}
