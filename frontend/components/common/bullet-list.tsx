export function BulletList({
  items,
  emptyLabel,
}: {
  items: string[]
  emptyLabel?: string
}) {
  if (!items.length) {
    return <p className="text-sm text-muted-foreground">{emptyLabel ?? "No data available."}</p>
  }

  return (
    <ul className="space-y-2 text-sm">
      {items.map((item, index) => (
        <li key={`${item}-${index}`} className="rounded-md border border-border/70 bg-background/40 px-3 py-2">
          {item}
        </li>
      ))}
    </ul>
  )
}
