export function ProgressBar({ value }: { value: number }) {
  const width = `${Math.max(0, Math.min(100, Math.round(value * 100)))}%`
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
      <div className="h-full rounded-full bg-primary transition-all" style={{ width }} />
    </div>
  )
}
