"use client"

import { useEffect, useState } from "react"
import { api } from "@/lib/api"
import { NavHeader } from "@/components/nav-header"

type ReviewItem = {
  alert_id: string
  alert_type: string
  severity: string
  verdict: string
  confidence_score: number
  reasoning_text: string
}

export default function ReviewQueuePage() {
  const [items, setItems] = useState<ReviewItem[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get<ReviewItem[]>("/review-queue")
      .then(setItems)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  const handleResolve = async (alertId: string, verdict: string) => {
    try {
      await api.post(`/review-queue/${alertId}/resolve`, { verdict })
      setItems(items.filter((i) => i.alert_id !== alertId))
    } catch (err) {
      console.error("Failed to resolve:", err)
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <NavHeader title="Review Queue" />
      <main className="p-6">
        {loading ? <p>Loading...</p> : (
          <div className="space-y-4">
            {items.map((item) => (
              <div key={item.alert_id} className="rounded-lg border border-border p-4">
                <div className="flex justify-between items-start mb-2">
                  <div>
                    <h3 className="font-semibold">{item.alert_type}</h3>
                    <p className="text-sm text-muted-foreground">
                      Confidence: {item.confidence_score?.toFixed(2) || "N/A"} | Current verdict: {item.verdict}
                    </p>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-xs ${
                    item.severity === "critical" ? "bg-red-500/20 text-red-500" :
                    "bg-orange-500/20 text-orange-500"
                  }`}>{item.severity}</span>
                </div>
                <p className="text-sm text-muted-foreground mb-3">{item.reasoning_text?.slice(0, 200)}</p>
                <div className="flex gap-2">
                  <button
                    onClick={() => handleResolve(item.alert_id, "known_pattern")}
                    className="px-3 py-1 rounded bg-green-600 text-white text-sm hover:bg-green-700"
                  >Known Pattern</button>
                  <button
                    onClick={() => handleResolve(item.alert_id, "novel")}
                    className="px-3 py-1 rounded bg-blue-600 text-white text-sm hover:bg-blue-700"
                  >Novel</button>
                  <button
                    onClick={() => handleResolve(item.alert_id, "uncertain")}
                    className="px-3 py-1 rounded bg-orange-600 text-white text-sm hover:bg-orange-700"
                  >Uncertain</button>
                </div>
              </div>
            ))}
            {items.length === 0 && <p className="text-muted-foreground">No items in review queue.</p>}
          </div>
        )}
      </main>
    </div>
  )
}
