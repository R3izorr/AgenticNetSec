"use client"

import { useCallback, useEffect, useState } from "react"
import Link from "next/link"
import type { Column, ColumnDef } from "@tanstack/react-table"
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react"

import { EmptyState, ErrorState, LoadingState } from "@/components/common/page-state"
import { InlineNotice } from "@/components/common/inline-notice"
import { SectionCard } from "@/components/common/section-card"
import { StatusBadge } from "@/components/common/status-badge"
import { Button } from "@/components/ui/button"
import { useToast } from "@/components/ui/toast"
import { getJobHistory } from "@/lib/api/analysis"
import { isApiError } from "@/lib/api/client"
import { formatDateTime } from "@/lib/format"
import type { JobStatus } from "@/lib/types/analysis"
import { DataTable } from "./data-table"

function SortableHeader({
  column,
  title,
}: {
  column: Column<JobStatus, unknown>
  title: string
}) {
  const sorted = column.getIsSorted()

  return (
    <Button
      variant="ghost"
      className="h-auto p-0 font-medium hover:bg-transparent"
      onClick={() => column.toggleSorting(sorted === "asc")}
    >
      {title}
      {sorted === "asc" ? (
        <ArrowUp className="ml-1 h-3 w-3 shrink-0" />
      ) : sorted === "desc" ? (
        <ArrowDown className="ml-1 h-3 w-3 shrink-0" />
      ) : (
        <ArrowUpDown className="ml-1 h-3 w-3 shrink-0 opacity-50" />
      )}
    </Button>
  )
}

export const columns: ColumnDef<JobStatus>[] = [
  {
    accessorKey: "analysisJobId",
    header: ({ column }) => <SortableHeader column={column} title="Job ID" />,
    cell: ({ getValue }) => (
      <span className="font-mono text-xs text-foreground/80">{getValue<string>()}</span>
    ),
  },
  {
    accessorKey: "status",
    header: ({ column }) => <SortableHeader column={column} title="Status" />,
    cell: ({ getValue }) => <StatusBadge value={getValue<string>()} />,
  },
  {
    accessorKey: "currentPhase",
    header: ({ column }) => <SortableHeader column={column} title="Phase" />,
    cell: ({ getValue }) => (
      <span className="text-sm text-foreground/70">{getValue<string>() || "-"}</span>
    ),
  },
  {
    accessorKey: "progress",
    header: ({ column }) => <SortableHeader column={column} title="Progress" />,
    cell: ({ getValue }) => {
      const value = getValue<number | null | undefined>()
      return (
        <span className="text-sm text-foreground/70">
          {typeof value === "number" ? `${Math.round(value * 100)}%` : "-"}
        </span>
      )
    },
  },
  {
    accessorKey: "guardrailState",
    header: ({ column }) => <SortableHeader column={column} title="Guardrail" />,
    cell: ({ getValue }) => {
      const value = getValue<string | null | undefined>()
      return value ? <StatusBadge value={value} /> : <span className="text-sm text-muted-foreground">-</span>
    },
  },
  {
    accessorKey: "createdAt",
    header: ({ column }) => <SortableHeader column={column} title="Created" />,
    cell: ({ getValue }) => (
      <span className="text-xs text-muted-foreground">{formatDateTime(getValue<string>())}</span>
    ),
  },
  {
    accessorKey: "updatedAt",
    header: ({ column }) => <SortableHeader column={column} title="Updated" />,
    cell: ({ getValue }) => (
      <span className="text-xs text-muted-foreground">{formatDateTime(getValue<string>())}</span>
    ),
  },
  {
    id: "action",
    header: "Action",
    enableSorting: false,
    cell: ({ row }) => (
      <Button asChild size="sm" variant="ghost">
        <Link href={`/analysis/${row.original.analysisJobId}`}>View</Link>
      </Button>
    ),
  },
]

export default function HistoryPage() {
  const { pushToast } = useToast()

  const [tableData, setTableData] = useState<JobStatus[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadHistory = useCallback(async () => {
    setLoading(true)
    setError(null)

    try {
      const response = await getJobHistory()
      setTableData(response.jobs ?? [])
    } catch (err) {
      const message = isApiError(err)
        ? err.detail || err.message
        : err instanceof Error
          ? err.message
          : "Failed to load job history"

      setTableData([])
      setError(message)

      pushToast({
        variant: "error",
        title: "Failed to load history",
        description: message,
      })
    } finally {
      setLoading(false)
    }
  }, [pushToast])

  useEffect(() => {
    void loadHistory()
  }, [loadHistory])

  if (loading) {
    return (
      <div className="flex flex-col gap-6">
        <LoadingState
          title="Loading ingestion history"
          description="Fetching submitted analyses and their current state."
        />
      </div>
    )
  }

  if (error && !tableData.length) {
    return (
      <div className="flex flex-col gap-6">
        <ErrorState title="Unable to load history" description={error} onRetry={() => void loadHistory()} />
      </div>
    )
  }

  if (!tableData.length) {
    return (
      <div className="flex flex-col gap-6">
        <EmptyState
          title="PCAP Ingestion History"
          description="No jobs have been submitted yet."
          action={
            <Button asChild>
              <Link href="/analysis/new">Create Your First Analysis</Link>
            </Button>
          }
        />
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <SectionCard title="PCAP Ingestion History" subtitle="View all submitted analyses">
        <div className="flex flex-col gap-4">
          {error ? <InlineNotice variant="error">{error}</InlineNotice> : null}
          <DataTable columns={columns} data={tableData} />
        </div>
      </SectionCard>
    </div>
  )
}
