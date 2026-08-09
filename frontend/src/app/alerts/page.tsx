"use client"

import { useEffect, useState } from "react"
import { api } from "@/lib/api"
import { NavHeader } from "@/components/nav-header"

type Alert = {
  id: string
  source: string
  alert_type: string
  severity: string
  status: string
  created_at: string
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get<Alert[]>("/alerts")
      .then(setAlerts)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="min-h-screen bg-background">
      <NavHeader title="Alerts" />
      <main className="p-6">
        {loading ? <p>Loading...</p> : (
          <div className="rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-2 px-3">ID</th>
                  <th className="text-left py-2 px-3">Source</th>
                  <th className="text-left py-2 px-3">Type</th>
                  <th className="text-left py-2 px-3">Severity</th>
                  <th className="text-left py-2 px-3">Status</th>
                  <th className="text-left py-2 px-3">Time</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <tr key={a.id} className="border-b border-border/50 hover:bg-muted/50">
                    <td className="py-2 px-3 font-mono text-xs">{a.id.slice(0, 8)}</td>
                    <td className="py-2 px-3">{a.source}</td>
                    <td className="py-2 px-3">{a.alert_type}</td>
                    <td className="py-2 px-3">{a.severity}</td>
                    <td className="py-2 px-3">{a.status}</td>
                    <td className="py-2 px-3 text-muted-foreground">{new Date(a.created_at).toLocaleString()}</td>
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
