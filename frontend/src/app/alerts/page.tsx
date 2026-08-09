"use client"

import { useEffect, useState } from "react"
import { api } from "@/lib/api"
import { NavHeader } from "@/components/nav-header"

type Alert = {
  id: string
  source: string
  alert_type: string | null
  severity: string | null
  status: string | null
  created_at: string
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .get("/alerts")
      .then((data) => {
        setAlerts(data as Alert[])
        setError(null)
      })
      .catch((err) => {
        console.error("Failed to fetch alerts:", err)

        setError(
          err instanceof Error
            ? err.message
            : "Failed to load alerts"
        )
      })
      .finally(() => {
        setLoading(false)
      })
  }, [])

  return (
    <div className="min-h-screen bg-background">
      <NavHeader title="Alerts" />

      <main className="p-6">
        {loading ? (
          <p className="text-muted-foreground">
            Loading alerts...
          </p>
        ) : error ? (
          <div className="rounded-lg border border-red-500/50 bg-red-500/10 p-4 text-red-500">
            <p className="font-semibold">
              Error loading alerts
            </p>

            <p className="text-sm">
              {error}
            </p>
          </div>
        ) : alerts.length === 0 ? (
          <p className="text-muted-foreground">
            No alerts found
          </p>
        ) : (
          <div className="rounded-lg border border-border overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-2 px-3">
                    ID
                  </th>

                  <th className="text-left py-2 px-3">
                    Source
                  </th>

                  <th className="text-left py-2 px-3">
                    Type
                  </th>

                  <th className="text-left py-2 px-3">
                    Severity
                  </th>

                  <th className="text-left py-2 px-3">
                    Status
                  </th>

                  <th className="text-left py-2 px-3">
                    Time
                  </th>
                </tr>
              </thead>

              <tbody>
                {alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="border-b border-border/50 hover:bg-muted/50"
                  >
                    <td className="py-2 px-3 font-mono text-xs">
                      {alert.id.slice(0, 8)}
                    </td>

                    <td className="py-2 px-3">
                      {alert.source || "N/A"}
                    </td>

                    <td className="py-2 px-3">
                      {alert.alert_type || "N/A"}
                    </td>

                    <td className="py-2 px-3">
                      {alert.severity || "N/A"}
                    </td>

                    <td className="py-2 px-3">
                      {alert.status || "N/A"}
                    </td>

                    <td className="py-2 px-3 text-muted-foreground">
                      {alert.created_at
                        ? new Date(
                            alert.created_at
                          ).toLocaleString()
                        : "N/A"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </main>
    </div>
  )
}
