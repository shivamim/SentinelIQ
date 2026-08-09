"use client"

import { useEffect, useState } from "react"
import { api } from "@/lib/api"
import { NavHeader } from "@/components/nav-header"
import { AlertTriangle, CheckCircle, Clock, FileText, Activity } from "lucide-react"

type DashboardData = {
  severity_counts: Record<string, number>
  verdict_counts: Record<string, number>
  recent_alerts: any[]
  review_queue_size: number
  total_alerts: number
  total_incidents: number
}

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get<DashboardData>("/reports/dashboard")
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="p-8 text-muted-foreground">Loading dashboard...</div>

  return (
    <div className="min-h-screen bg-background">
      <NavHeader title="Dashboard" />

      <main className="p-6 space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <StatCard
            icon={<Activity className="h-5 w-5" />}
            title="Total Alerts"
            value={data?.total_alerts || 0}
            color="text-blue-500"
          />
          <StatCard
            icon={<AlertTriangle className="h-5 w-5" />}
            title="Review Queue"
            value={data?.review_queue_size || 0}
            color="text-yellow-500"
          />
          <StatCard
            icon={<CheckCircle className="h-5 w-5" />}
            title="Known Patterns"
            value={data?.verdict_counts?.known_pattern || 0}
            color="text-green-500"
          />
          <StatCard
            icon={<Clock className="h-5 w-5" />}
            title="Uncertain"
            value={data?.verdict_counts?.uncertain || 0}
            color="text-orange-500"
          />
        </div>

        {/* Severity Distribution & Verdict Breakdown */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-lg border border-border p-4">
            <h3 className="text-lg font-semibold mb-4">Severity Distribution</h3>
            <SeverityChart counts={data?.severity_counts || {}} />
          </div>
          <div className="rounded-lg border border-border p-4">
            <h3 className="text-lg font-semibold mb-4">Verdict Breakdown</h3>
            <VerdictChart counts={data?.verdict_counts || {}} />
          </div>
        </div>

        {/* Recent Alerts */}
        <div className="rounded-lg border border-border p-4">
          <h3 className="text-lg font-semibold mb-4">Recent Alerts</h3>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3">Source</th>
                <th className="text-left py-2 px-3">Type</th>
                <th className="text-left py-2 px-3">Severity</th>
                <th className="text-left py-2 px-3">Status</th>
                <th className="text-left py-2 px-3">Time</th>
              </tr>
            </thead>
            <tbody>
              {(data?.recent_alerts || []).map((alert: any) => (
                <tr key={alert.id} className="border-b border-border/50 hover:bg-muted/50">
                  <td className="py-2 px-3">{alert.source}</td>
                  <td className="py-2 px-3">{alert.alert_type}</td>
                  <td className="py-2 px-3">
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td className="py-2 px-3">{alert.status}</td>
                  <td className="py-2 px-3 text-muted-foreground">
                    {new Date(alert.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  )
}

function StatCard({ icon, title, value, color }: { icon: React.ReactNode; title: string; value: number; color: string }) {
  return (
    <div className="rounded-lg border border-border p-4 flex items-center gap-4">
      <div className={`${color}`}>{icon}</div>
      <div>
        <p className="text-2xl font-bold">{value}</p>
        <p className="text-sm text-muted-foreground">{title}</p>
      </div>
    </div>
  )
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-500",
    high: "bg-orange-500/20 text-orange-500",
    medium: "bg-yellow-500/20 text-yellow-500",
    low: "bg-green-500/20 text-green-500",
  }
  return <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors[severity] || "bg-muted text-muted-foreground"}`}>{severity}</span>
}

function SeverityChart({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1
  return (
    <div className="space-y-3">
      {["critical", "high", "medium", "low"].map((sev) => {
        const count = counts[sev] || 0
        const pct = (count / total) * 100
        const colors: Record<string, string> = { critical: "bg-red-500", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-green-500" }
        return (
          <div key={sev} className="flex items-center gap-3">
            <span className="w-16 text-sm capitalize">{sev}</span>
            <div className="flex-1 h-6 bg-muted rounded overflow-hidden">
              <div className={`h-full ${colors[sev]} rounded`} style={{ width: `${pct}%` }} />
            </div>
            <span className="w-10 text-sm text-right">{count}</span>
          </div>
        )
      })}
    </div>
  )
}

function VerdictChart({ counts }: { counts: Record<string, number> }) {
  const entries = Object.entries(counts)
  const total = entries.reduce((a, [, b]) => a + b, 0) || 1
  const colors: Record<string, string> = { known_pattern: "bg-green-500", novel: "bg-blue-500", uncertain: "bg-orange-500" }
  return (
    <div className="space-y-3">
      {entries.map(([verdict, count]) => {
        const pct = (count / total) * 100
        return (
          <div key={verdict} className="flex items-center gap-3">
            <span className="w-28 text-sm capitalize">{verdict.replace("_", " ")}</span>
            <div className="flex-1 h-6 bg-muted rounded overflow-hidden">
              <div className={`h-full ${colors[verdict] || "bg-muted-foreground"} rounded`} style={{ width: `${pct}%` }} />
            </div>
            <span className="w-10 text-sm text-right">{count}</span>
          </div>
        )
      })}
    </div>
  )
}
