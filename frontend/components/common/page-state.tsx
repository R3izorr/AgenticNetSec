import { Button } from "@/components/ui/button"
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"

export function LoadingState({
  title = "Loading",
  description,
}: {
  title?: string
  description?: string
}) {
  return (
    <section>
      <Card className="border border-border/70 bg-card/95 shadow-sm">
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          {description ? <CardDescription>{description}</CardDescription> : null}
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Skeleton className="h-4 w-2/3" />
          <Skeleton className="h-4 w-1/2" />
          <Skeleton className="h-4 w-3/4" />
        </CardContent>
      </Card>
    </section>
  )
}

export function ErrorState({
  title,
  description,
  onRetry,
}: {
  title: string
  description?: string
  onRetry?: () => void
}) {
  return (
    <section>
      <Card className="border border-destructive/30 bg-card/95 shadow-sm">
        <CardHeader>
          <CardTitle>{title}</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <Alert variant="destructive" className="border-destructive/30 bg-destructive/5">
            <AlertTitle>{title}</AlertTitle>
            {description ? <AlertDescription>{description}</AlertDescription> : null}
          </Alert>
          {onRetry ? (
            <div>
              <Button type="button" variant="outline" size="sm" onClick={onRetry}>
                Retry
              </Button>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </section>
  )
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string
  description?: string
  action?: React.ReactNode
}) {
  return (
    <section>
      <Card className="border border-border/70 bg-card/95 shadow-sm">
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          {description ? <CardDescription>{description}</CardDescription> : null}
        </CardHeader>
        {action ? <CardContent>{action}</CardContent> : null}
      </Card>
    </section>
  )
}
