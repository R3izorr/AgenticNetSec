"use client"

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react"
import { cn } from "@/lib/utils"

type ToastVariant = "info" | "success" | "error"

interface ToastInput {
  title: string
  description?: string
  variant?: ToastVariant
}

interface ToastItem extends ToastInput {
  id: number
}

interface ToastContextValue {
  pushToast: (input: ToastInput) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

const toastStyles: Record<ToastVariant, string> = {
  info: "border-blue-500/40 bg-blue-500/10",
  success: "border-green-500/40 bg-green-500/10",
  error: "border-red-500/40 bg-red-500/10",
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])

  const pushToast = useCallback((input: ToastInput) => {
    const id = Date.now() + Math.floor(Math.random() * 1000)
    const nextToast: ToastItem = {
      id,
      variant: input.variant ?? "info",
      title: input.title,
      description: input.description,
    }

    setToasts((current) => [...current, nextToast])
    window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id))
    }, 4200)
  }, [])

  const value = useMemo<ToastContextValue>(
    () => ({
      pushToast,
    }),
    [pushToast]
  )

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-[min(92vw,420px)] flex-col gap-2">
        {toasts.map((toast) => {
          const variant = toast.variant ?? "info"
          return (
            <div
              key={toast.id}
              className={cn(
                "rounded-lg border px-4 py-3 text-sm shadow-lg backdrop-blur",
                toastStyles[variant]
              )}
            >
              <p className="font-medium text-foreground">{toast.title}</p>
              {toast.description ? (
                <p className="mt-1 text-xs text-muted-foreground">{toast.description}</p>
              ) : null}
            </div>
          )
        })}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast() {
  const context = useContext(ToastContext)
  if (!context) {
    throw new Error("useToast must be used within ToastProvider")
  }
  return context
}
