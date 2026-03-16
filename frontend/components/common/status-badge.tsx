import { cn } from "@/lib/utils"

const badgeClassMap: Record<string, string> = {
  queued: "border-yellow-500/40 bg-yellow-500/10 text-yellow-300",
  running: "border-blue-500/40 bg-blue-500/10 text-blue-300",
  completed: "border-green-500/40 bg-green-500/10 text-green-300",
  failed: "border-red-500/40 bg-red-500/10 text-red-300",
  yes: "border-red-500/40 bg-red-500/10 text-red-300",
  no: "border-green-500/40 bg-green-500/10 text-green-300",
}

export function StatusBadge({
  value,
  className,
}: {
  value: string
  className?: string
}) {
  const key = value.toLowerCase()
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium",
        badgeClassMap[key] ?? "border-border bg-muted text-muted-foreground",
        className
      )}
    >
      {value}
    </span>
  )
}
