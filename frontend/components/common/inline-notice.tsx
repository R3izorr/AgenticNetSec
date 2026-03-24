import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { cn } from "@/lib/utils"
import { InfoIcon, OctagonXIcon, TriangleAlertIcon } from "lucide-react"

const noticeConfig = {
  info: {
    icon: InfoIcon,
    className: "border-border/70 bg-background/60 text-foreground",
    descriptionClassName: "text-muted-foreground",
    title: "Notice",
  },
  warning: {
    icon: TriangleAlertIcon,
    className: "border-yellow-500/30 bg-yellow-500/5 text-yellow-100",
    descriptionClassName: "text-yellow-100/80",
    title: "Warning",
  },
  error: {
    icon: OctagonXIcon,
    className: "border-destructive/30 bg-destructive/5 text-destructive",
    descriptionClassName: "text-destructive/90",
    title: "Error",
  },
} as const

export function InlineNotice({
  variant = "info",
  title,
  children,
  className,
}: {
  variant?: keyof typeof noticeConfig
  title?: string
  children: React.ReactNode
  className?: string
}) {
  const config = noticeConfig[variant]
  const Icon = config.icon

  return (
    <Alert
      variant={variant === "error" ? "destructive" : "default"}
      className={cn(config.className, className)}
    >
      <Icon />
      <AlertTitle>{title ?? config.title}</AlertTitle>
      <AlertDescription className={config.descriptionClassName}>{children}</AlertDescription>
    </Alert>
  )
}
