"use client"

import { useEffect, useState } from "react"
import { api } from "@/lib/api"
import { NavHeader } from "@/components/nav-header"

type Incident = {
  id: string
  title: string
  description?: string | null
  severity?: string | null
  status: string
  opened_at: string
  closed_at?: string | null
  assigned_to?: string | null
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .get("/incidents")
      .then((data) => {
        setIncidents(data)
        setError(null)
      })
      .catch((err) => {
        console.error("Failed to fetch incidents:", err)
        setError(
          err instanceof Error
            ? err.message
            : "Failed to load incidents"
        )
      })
      .finally(() => {
        setLoading(false)
      })
  }, [])

  const getSeverityClass = (severity?: string | null) => {
    switch (severity?.toLowerCase()) {
      case "critical":
        return "bg-red-500/20 text-red-400 border border-red-500/30"

      case "high":
        return "bg-orange-500/20 text-orange-400 border border-orange-500/30"

      case "medium":
        return "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30"

      case "low":
        return "bg-green-500/20 text-green-400 border border-green-500/30"

      default:
        return "bg-muted text-muted-foreground"
    }
  }

  const getStatusClass = (status: string) => {
    switch (status.toLowerCase()) {
      case "open":
        return "text-blue-400"

      case "investigating":
        return "text-orange-400"

      case "resolved":
      case "closed":
        return "text-green-400"

      default:
        return "text-muted-foreground"
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <NavHeader title="Incidents" />

      <main className="p-6">
        {/* Loading */}
        {loading && (
          <div className="rounded-lg border border-border p-6">
            <p className="text-muted-foreground">
              Loading incidents...
            </p>
          </div>
        )}

        {/* Error */}
        {!loading && error && (
          <div className="rounded-lg border border-red-500/50 bg-red-500/10 p-4 text-red-500">
            <p className="font-semibold">
              Error loading incidents
            </p>

            <p className="mt-1 text-sm">
              {error}
            </p>
          </div>
        )}

        {/* Empty */}
        {!loading && !error && incidents.length === 0 && (
          <div className="rounded-lg border border-border p-8 text-center">
            <p className="text-muted-foreground">
              No incidents found.
            </p>
          </div>
        )}

        {/* Incidents */}
        {!loading && !error && incidents.length > 0 && (
          <div className="space-y-4">
            {incidents.map((incident) => (
              <div
                key={incident.id}
                className="rounded-lg border border-border bg-background p-5 transition-colors hover:bg-muted/30"
              >
                <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                  {/* Left */}
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-3">
                      <h2 className="text-lg font-semibold">
                        {incident.title}
                      </h2>

                      <span
                        className={`rounded px-2 py-0.5 text-xs font-medium ${getSeverityClass(
                          incident.severity
                        )}`}
                      >
                        {incident.severity || "N/A"}
                      </span>
                    </div>

                    <p className="mt-2 font-mono text-xs text-muted-foreground">
                      ID: {incident.id}
                    </p>

                    {incident.description && (
                      <p className="mt-3 text-sm text-muted-foreground">
                        {incident.description}
                      </p>
                    )}
                  </div>

                  {/* Right */}
                  <div className="flex shrink-0 flex-col gap-2 text-sm md:items-end">
                    <span
                      className={`font-medium capitalize ${getStatusClass(
                        incident.status
                      )}`}
                    >
                      {incident.status}
                    </span>

                    <span className="text-xs text-muted-foreground">
                      Opened:{" "}
                      {new Date(
                        incident.opened_at
                      ).toLocaleString()}
                    </span>

                    {incident.closed_at && (
                      <span className="text-xs text-muted-foreground">
                        Closed:{" "}
                        {new Date(
                          incident.closed_at
                        ).toLocaleString()}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  )
}
