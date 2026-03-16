"use client"

import { useState } from "react"

export function CopyButton({
  value,
  label = "Copy",
}: {
  value: string
  label?: string
}) {
  const [copied, setCopied] = useState(false)

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1400)
    } catch {
      setCopied(false)
    }
  }

  return (
    <button
      type="button"
      onClick={onCopy}
      className="rounded-md border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-muted"
    >
      {copied ? "Copied" : label}
    </button>
  )
}
