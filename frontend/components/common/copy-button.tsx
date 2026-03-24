"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"

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
    <Button type="button" variant="outline" size="sm" className="h-7 px-2 text-xs" onClick={onCopy}>
      {copied ? "Copied" : label}
    </Button>
  )
}
