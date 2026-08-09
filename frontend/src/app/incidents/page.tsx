"use client"

import { useEffect, useState } from "react"
import { api } from "@/lib/api"
import { NavHeader } from "@/components/nav-header"

type Incident = {
  id: string
  title: string
  severity: string
  status: string
  opened_at: string
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get<Incident[]>("/incidents")
      .then(setIncidents)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="min-h-screen bg-background">
      <NavHeader title="Incidents" />
      <main className="p-6">
        {loading ? <p>Loading...</p> : (
          <div className="space-y-4">
            {incidents.map((inc) => (
              <div key={inc.id} className="rounded-lg border border-border p-4 hover:bg-muted/50">
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="font-semibold">{inc.title}</h3>
                    <p className="text-sm text-muted-foreground">ID: {inc.id.slice(0, 8)}</p>
                  </div>
                  <div className="flex gap-2">
                    <span className={`px-2 py-0.5 rounded text-xs ${
                      inc.severity === "critical" ? "bg-red-500/20 text-red-500" :
                      inc.severity === "high" ? "bg-orange-500/20 text-orange-500" :
                      "bg-muted text-muted-foreground"
                    }`}>{inc.severity}</span>
                    <span className="px-2 py-0.5 rounded text-xs bg-muted">{inc.status}</span>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground mt-2">
                  Opened: {new Date(inc.opened_at).toLocaleString()}
                </p>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  )
}
