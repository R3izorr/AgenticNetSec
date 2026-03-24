import { CopyButton } from "@/components/common/copy-button"
import { SectionCard } from "@/components/common/section-card"
import { cn } from "@/lib/utils"

export function ArtifactPanel({
  title,
  subtitle,
  copyValue,
  copyLabel,
  children,
  className,
  contentClassName,
}: {
  title: string
  subtitle?: string
  copyValue?: string
  copyLabel?: string
  children: React.ReactNode
  className?: string
  contentClassName?: string
}) {
  return (
    <SectionCard
      title={title}
      subtitle={subtitle}
      actions={copyValue ? <CopyButton value={copyValue} label={copyLabel} /> : null}
      className={className}
    >
      <div className={cn("rounded-lg border border-border/70 bg-background/40 p-3", contentClassName)}>
        {children}
      </div>
    </SectionCard>
  )
}
