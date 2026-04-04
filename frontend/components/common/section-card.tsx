import { cn } from "@/lib/utils"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"

export function SectionCard({
  title,
  subtitle,
  actions,
  children,
  className,
}: {
  title: string
  subtitle?: string
  actions?: React.ReactNode
  children: React.ReactNode
  className?: string
}) {
  return (
    <section>
      <Card className={cn("border border-border/70 bg-card/95 shadow-sm", className)}>
        <CardHeader className="gap-2 border-b border-border/60">
          <div>
            <CardTitle>{title}</CardTitle>
            {subtitle ? <CardDescription>{subtitle}</CardDescription> : null}
          </div>
          {actions ? <CardAction>{actions}</CardAction> : null}
        </CardHeader>
        <CardContent className="pt-4">{children}</CardContent>
      </Card>
    </section>
  )
}
