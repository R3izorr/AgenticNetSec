"use client"

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  type ReactNode,
} from "react"
import { toast } from "sonner"
import { Toaster } from "@/components/ui/sonner"

type ToastVariant = "info" | "success" | "error"

interface ToastInput {
  title: string
  description?: string
  variant?: ToastVariant
}

interface ToastContextValue {
  pushToast: (input: ToastInput) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

export function ToastProvider({ children }: { children: ReactNode }) {
  const pushToast = useCallback((input: ToastInput) => {
    const variant = input.variant ?? "info"

    if (variant === "success") {
      toast.success(input.title, { description: input.description })
      return
    }

    if (variant === "error") {
      toast.error(input.title, { description: input.description })
      return
    }

    toast(input.title, { description: input.description })
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
      <Toaster position="bottom-right" richColors />
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
