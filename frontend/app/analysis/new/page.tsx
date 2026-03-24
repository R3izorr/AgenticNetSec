"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"

import { InlineNotice } from "@/components/common/inline-notice"
import { SectionCard } from "@/components/common/section-card"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { useToast } from "@/components/ui/toast"
import { adaptJobStatus } from "@/lib/adapters/analysis"
import { createAnalysisJob } from "@/lib/api/analysis"
import { isApiError } from "@/lib/api/client"

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
    <div className="flex flex-col gap-6">
      <SectionCard
        title="Submit Analysis"
        subtitle="Provide exactly one input source: file upload or pcap_path."
      >
        <form className="flex flex-col gap-5" onSubmit={onSubmit}>
          <div className="flex flex-col gap-3">
            <Label>Input source</Label>
            <ToggleGroup
              type="single"
              value={inputMode}
              variant="outline"
              className="grid w-full grid-cols-1 gap-3 sm:grid-cols-2"
              onValueChange={(value) => {
                if (!value) {
                  return
                }

                if (value === "file") {
                  setInputMode("file")
                  setPcapPath("")
                  return
                }

                setInputMode("path")
                setFile(undefined)
              }}
            >
              <ToggleGroupItem value="file" className="h-auto items-start justify-start px-4 py-3 text-left">
                <div className="flex flex-col gap-1">
                  <span className="text-sm font-medium text-foreground">Upload PCAP File</span>
                  <span className="text-xs text-muted-foreground">
                    Use local file input and send multipart upload.
                  </span>
                </div>
              </ToggleGroupItem>
              <ToggleGroupItem value="path" className="h-auto items-start justify-start px-4 py-3 text-left">
                <div className="flex flex-col gap-1">
                  <span className="text-sm font-medium text-foreground">Use pcap_path</span>
                  <span className="text-xs text-muted-foreground">
                    Provide a backend-readable filesystem path.
                  </span>
                </div>
              </ToggleGroupItem>
            </ToggleGroup>
          </div>

          {inputMode === "file" ? (
            <div className="flex flex-col gap-2">
              <Label htmlFor="pcap-file">PCAP file</Label>
              <Input
                id="pcap-file"
                type="file"
                accept=".pcap,.pcapng"
                onChange={(event) => setFile(event.target.files?.[0])}
                className="h-auto bg-card py-2"
              />
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              <Label htmlFor="pcap-path">pcap_path</Label>
              <Input
                id="pcap-path"
                type="text"
                value={pcapPath}
                onChange={(event) => setPcapPath(event.target.value)}
                placeholder="C:\\captures\\case1.pcap"
                className="bg-card"
              />
            </div>
          )}

          <Separator />

          <details className="rounded-lg border border-border/70 bg-background/40 p-4">
            <summary className="cursor-pointer text-sm font-medium">Advanced options</summary>
            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <div className="flex flex-col gap-2">
                <Label htmlFor="provider">Provider</Label>
                <Input
                  id="provider"
                  type="text"
                  value={provider}
                  onChange={(event) => setProvider(event.target.value)}
                  className="bg-card"
                />
              </div>
              <div className="flex flex-col gap-2">
                <Label htmlFor="model">Model (optional)</Label>
                <Input
                  id="model"
                  type="text"
                  value={model}
                  onChange={(event) => setModel(event.target.value)}
                  className="bg-card"
                />
              </div>
              <div className="flex items-center gap-3 rounded-lg border border-border/70 bg-card/60 px-3 py-2">
                <Checkbox
                  id="use-ai"
                  checked={useAi}
                  onCheckedChange={(checked) => setUseAi(checked === true)}
                />
                <Label htmlFor="use-ai">use_ai</Label>
              </div>
              <div className="flex items-center gap-3 rounded-lg border border-border/70 bg-card/60 px-3 py-2">
                <Checkbox
                  id="require-ai"
                  checked={requireAi}
                  onCheckedChange={(checked) => setRequireAi(checked === true)}
                />
                <Label htmlFor="require-ai">require_ai</Label>
              </div>
            </div>
          </details>

          {formError ? <InlineNotice variant="error">{formError}</InlineNotice> : null}

          <div className="flex items-center gap-3">
            <Button type="submit" disabled={submitting}>
              {submitting ? "Submitting..." : "Start Analysis"}
            </Button>
            <p className="text-xs text-muted-foreground">Analysis runs autonomously after submission.</p>
          </div>
        </form>
      </SectionCard>
    </div>
  )
}
