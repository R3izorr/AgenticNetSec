import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

const badgeConfig: Record<
  string,
  {
    variant: "default" | "secondary" | "destructive" | "outline"
    className?: string
  }
> = {
  queued: {
    variant: "outline",
    className: "border-yellow-500/40 bg-yellow-500/10 text-yellow-300",
  },
  running: {
    variant: "outline",
    className: "border-blue-500/40 bg-blue-500/10 text-blue-300",
  },
  completed: {
    variant: "outline",
    className: "border-green-500/40 bg-green-500/10 text-green-300",
  },
  failed: {
    variant: "destructive",
    className: "border-red-500/40 bg-red-500/10 text-red-300",
  },
  pass: {
    variant: "outline",
    className: "border-green-500/40 bg-green-500/10 text-green-300",
  },
  yes: {
    variant: "destructive",
    className: "border-red-500/40 bg-red-500/10 text-red-300",
  },
  no: {
    variant: "outline",
    className: "border-green-500/40 bg-green-500/10 text-green-300",
  },
  low: {
    variant: "outline",
    className: "border-green-500/40 bg-green-500/10 text-green-300",
  },
  medium: {
    variant: "outline",
    className: "border-yellow-500/40 bg-yellow-500/10 text-yellow-300",
  },
  high: {
    variant: "destructive",
    className: "border-red-500/40 bg-red-500/10 text-red-300",
  },
}

export function StatusBadge({
  value,
  className,
}: {
  value: string
  className?: string
}) {
  const key = value.toLowerCase()
  const config = badgeConfig[key] ?? { variant: "secondary" as const }

  return (
    <Badge
      variant={config.variant}
      className={cn("rounded-full border px-2.5 py-0.5 font-medium", config.className, className)}
    >
      {value}
    </Badge>
  )
}
