import { Progress } from "@/components/ui/progress"

export function ProgressBar({ value }: { value: number }) {
  const normalized = Math.max(0, Math.min(100, Math.round(value * 100)))

  return <Progress value={normalized} className="h-2" />
}
