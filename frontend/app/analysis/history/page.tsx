"use client"

import { useCallback, useEffect, useState } from "react"
import Link from "next/link"
import type { Column, ColumnDef } from "@tanstack/react-table"

import { Button } from "@/components/ui/button"
import { SectionCard } from "@/components/common/section-card"
import { StatusBadge } from "@/components/common/status-badge"
import { getJobHistory } from "@/lib/api/analysis"
import { isApiError } from "@/lib/api/client"
import { useToast } from "@/components/ui/toast"
import type { JobStatus } from "@/lib/types/analysis"
import { formatDateTime } from "@/lib/format"
import { DataTable } from "./data-table"
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react"

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
    header: ({ column }) => (
      <SortableHeader column={column} title="Job ID" />
    ),
    cell: ({ getValue }) => (
      <span className="font-mono text-xs text-foreground/80">
        {getValue<string>()}
      </span>
    ),
  },
  {
    accessorKey: "status",
    header: ({ column }) => (
      <SortableHeader column={column} title="Status" />
    ),
    cell: ({ getValue }) => <StatusBadge value={getValue<string>()} />,
  },
  {
    accessorKey: "currentPhase",
    header: ({ column }) => (
      <SortableHeader column={column} title="Phase" />
    ),
    cell: ({ getValue }) => (
      <span className="text-sm text-foreground/70">
        {getValue<string>() || "-"}
      </span>
    ),
  },
  {
    accessorKey: "progress",
    header: ({ column }) => (
      <SortableHeader column={column} title="Progress" />
    ),
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
    header: ({ column }) => (
      <SortableHeader column={column} title="Guardrail" />
    ),
    cell: ({ getValue }) => {
      const value = getValue<string | null | undefined>()
      return value ? (
        <StatusBadge value={value} />
      ) : (
        <span className="text-sm text-muted-foreground">-</span>
      )
    },
  },
  {
    accessorKey: "createdAt",
    header: ({ column }) => (
      <SortableHeader column={column} title="Created" />
    ),
    cell: ({ getValue }) => (
      <span className="text-xs text-muted-foreground">
        {formatDateTime(getValue<string>())}
      </span>
    ),
  },
  {
    accessorKey: "updatedAt",
    header: ({ column }) => (
      <SortableHeader column={column} title="Updated" />
    ),
    cell: ({ getValue }) => (
      <span className="text-xs text-muted-foreground">
        {formatDateTime(getValue<string>())}
      </span>
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

  const loadHistory = useCallback(
    async () => {
      setLoading(true)
      setError(null)

      try {
        const response = await getJobHistory()
        console.log(response)
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
    },
    [pushToast]
  )

  useEffect(() => {
    loadHistory()
  }, [loadHistory])

  return (
    <div className="space-y-6">
      <SectionCard
        title="PCAP Ingestion History"
        subtitle="View all submitted analyses"
      >
        {error && (
          <div className="mb-4 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
            {error}
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="space-y-2 text-center">
              <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-border border-t-primary" />
              <p className="text-sm text-muted-foreground">Loading jobs...</p>
            </div>
          </div>
        ) : tableData.length > 0 ? (
          <>
            <div className="overflow-x-auto">
              <DataTable columns={columns} data={tableData} />
            </div>

        
          </>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <p className="text-sm text-muted-foreground">No jobs found</p>
            <Button asChild className="mt-4">
              <Link href="/analysis/new">Create Your First Analysis</Link>
            </Button>
          </div>
        )}
      </SectionCard>
    </div>
  )
}