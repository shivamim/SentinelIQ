"use client"

import { useState } from "react"
import { api } from "@/lib/api"
import { NavHeader } from "@/components/nav-header"
import { FileText, Download } from "lucide-react"

export default function ReportsPage() {
  const [incidentId, setIncidentId] = useState("")
  const [loading, setLoading] = useState(false)

  const downloadReport = async () => {
    if (!incidentId) return
    setLoading(true)
    try {
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/reports/incidents/${incidentId}/pdf`,
        { headers: { Authorization: `Bearer ${(await (await import("@/components/auth-provider")).supabase.auth.getSession()).data.session?.access_token}` } }
      )
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = `incident_${incidentId}.pdf`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error("Failed to download report:", err)
    }
    setLoading(false)
  }

  return (
    <div className="min-h-screen bg-background">
      <NavHeader title="Reports" />
      <main className="p-6 max-w-lg">
        <div className="rounded-lg border border-border p-6 space-y-4">
          <div className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-muted-foreground" />
            <h2 className="text-lg font-semibold">Generate PDF Report</h2>
          </div>
          <p className="text-sm text-muted-foreground">
            Download a PDF incident report with correlation results, postmortem details, and MITRE ATT&CK mapping.
          </p>
          <div>
            <label className="block text-sm font-medium mb-1">Incident ID</label>
            <input
              type="text"
              value={incidentId}
              onChange={(e) => setIncidentId(e.target.value)}
              placeholder="Enter incident UUID..."
              className="w-full px-3 py-2 rounded-md border border-border bg-background"
            />
          </div>
          <button
            onClick={downloadReport}
            disabled={loading || !incidentId}
            className="flex items-center gap-2 px-4 py-2 rounded-md bg-primary text-primary-foreground font-medium hover:bg-primary/90 disabled:opacity-50"
          >
            <Download className="h-4 w-4" />
            {loading ? "Generating..." : "Download PDF"}
          </button>
        </div>
      </main>
    </div>
  )
}
