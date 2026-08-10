"use client"

import { useEffect, useState } from "react"
import { api } from "@/lib/api"
import { NavHeader } from "@/components/nav-header"

type ReviewItem = {
  alert_id: string
  alert_type: string | null
  severity: string | null
  verdict: string | null
  confidence_score: number | null
  reasoning_text: string | null
  created_at: string
}

export default function ReviewQueuePage() {
  const [items, setItems] = useState<ReviewItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [resolving, setResolving] = useState<string | null>(null)

  const loadQueue = async () => {
    try {
      setLoading(true)
      setError(null)

      const data = await api.get("/review-queue")

      setItems(data)
    } catch (err) {
      console.error("Failed to load review queue:", err)

      setError(
        err instanceof Error
          ? err.message
          : "Failed to load review queue"
      )
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadQueue()
  }, [])

  const handleResolve = async (
    alertId: string,
    verdict: "known_pattern" | "novel" | "uncertain"
  ) => {
    try {
      setResolving(alertId)

      await api.post(
        `/review-queue/${alertId}/resolve`,
        {
          verdict,
        }
      )

      // Remove resolved alert immediately from UI.
      setItems((current) =>
        current.filter(
          (item) => item.alert_id !== alertId
        )
      )
    } catch (err) {
      console.error("Failed to resolve review:", err)

      setError(
        err instanceof Error
          ? err.message
          : "Failed to resolve review"
      )
    } finally {
      setResolving(null)
    }
  }

  const severityClass = (severity: string | null) => {
    switch (severity?.toLowerCase()) {
      case "critical":
        return "bg-red-500/20 text-red-400 border border-red-500/30"

      case "high":
        return "bg-orange-500/20 text-orange-400 border border-orange-500/30"

      case "medium":
        return "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30"

      default:
        return "bg-muted text-muted-foreground"
    }
  }

  const verdictClass = (verdict: string | null) => {
    switch (verdict) {
      case "known_pattern":
        return "text-green-400"

      case "novel":
        return "text-blue-400"

      case "uncertain":
      default:
        return "text-orange-400"
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <NavHeader title="Review Queue" />

      <main className="p-6">

        {/* Header */}
        <div className="mb-6">
          <h1 className="text-2xl font-semibold">
            Analyst Review Queue
          </h1>

          <p className="text-sm text-muted-foreground mt-1">
            Alerts requiring human validation and triage.
          </p>
        </div>

        {/* Error */}
        {error && (
          <div className="mb-6 rounded-lg border border-red-500/50 bg-red-500/10 p-4 text-red-400">
            <p className="font-semibold">
              Error loading review queue
            </p>

            <p className="text-sm mt-1">
              {error}
            </p>
          </div>
        )}

        {/* Loading */}
        {loading ? (
          <div className="rounded-lg border border-border p-6">
            <p className="text-muted-foreground">
              Loading review queue...
            </p>
          </div>
        ) : items.length === 0 ? (

          /* Empty */
          <div className="rounded-lg border border-border p-10 text-center">
            <div className="text-lg font-medium">
              Review queue is clear
            </div>

            <p className="text-sm text-muted-foreground mt-2">
              No alerts currently require analyst review.
            </p>
          </div>

        ) : (

          /* Queue */
          <div className="space-y-4">

            {/* Queue count */}
            <div className="text-sm text-muted-foreground">
              {items.length} alert{items.length !== 1 ? "s" : ""}{" "}
              awaiting review
            </div>

            {items.map((item) => (

              <div
                key={item.alert_id}
                className="rounded-lg border border-border bg-card p-5"
              >

                {/* Top row */}
                <div className="flex justify-between items-start gap-4">

                  <div className="min-w-0">

                    <h3 className="font-semibold text-lg">
                      {item.alert_type || "Unknown Alert"}
                    </h3>

                    <p className="text-xs text-muted-foreground font-mono mt-1">
                      Alert ID: {item.alert_id}
                    </p>

                  </div>

                  <span
                    className={`px-2.5 py-1 rounded text-xs font-medium shrink-0 ${severityClass(
                      item.severity
                    )}`}
                  >
                    {item.severity || "unknown"}
                  </span>

                </div>

                {/* Metadata */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-5">

                  <div>
                    <p className="text-xs text-muted-foreground">
                      Current Verdict
                    </p>

                    <p
                      className={`text-sm font-medium mt-1 ${verdictClass(
                        item.verdict
                      )}`}
                    >
                      {item.verdict || "uncertain"}
                    </p>
                  </div>

                  <div>
                    <p className="text-xs text-muted-foreground">
                      Confidence
                    </p>

                    <p className="text-sm font-medium mt-1">
                      {item.confidence_score !== null &&
                      item.confidence_score !== undefined
                        ? `${(
                            item.confidence_score * 100
                          ).toFixed(0)}%`
                        : "Not calculated"}
                    </p>
                  </div>

                  <div>
                    <p className="text-xs text-muted-foreground">
                      Created
                    </p>

                    <p className="text-sm mt-1">
                      {new Date(
                        item.created_at
                      ).toLocaleString()}
                    </p>
                  </div>

                </div>

                {/* Reasoning */}
                <div className="mt-5 rounded-md bg-muted/30 p-3">

                  <p className="text-xs font-medium mb-1">
                    Analyst Context
                  </p>

                  <p className="text-sm text-muted-foreground">
                    {item.reasoning_text ||
                      "Awaiting correlation analysis and analyst review."}
                  </p>

                </div>

                {/* Actions */}
                <div className="flex flex-wrap gap-2 mt-5">

                  <button
                    disabled={resolving === item.alert_id}
                    onClick={() =>
                      handleResolve(
                        item.alert_id,
                        "known_pattern"
                      )
                    }
                    className="px-3 py-2 rounded-md bg-green-600 text-white text-sm hover:bg-green-700 disabled:opacity-50"
                  >
                    Known Pattern
                  </button>

                  <button
                    disabled={resolving === item.alert_id}
                    onClick={() =>
                      handleResolve(
                        item.alert_id,
                        "novel"
                      )
                    }
                    className="px-3 py-2 rounded-md bg-blue-600 text-white text-sm hover:bg-blue-700 disabled:opacity-50"
                  >
                    Novel
                  </button>

                  <button
                    disabled={resolving === item.alert_id}
                    onClick={() =>
                      handleResolve(
                        item.alert_id,
                        "uncertain"
                      )
                    }
                    className="px-3 py-2 rounded-md bg-orange-600 text-white text-sm hover:bg-orange-700 disabled:opacity-50"
                  >
                    Uncertain
                  </button>

                </div>

              </div>

            ))}

          </div>
        )}

      </main>
    </div>
  )
}
