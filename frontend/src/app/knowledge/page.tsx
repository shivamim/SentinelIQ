"use client"

import { useEffect, useState } from "react"
import { NavHeader } from "@/components/nav-header"
import { api } from "@/lib/api"
import { cn } from "@/lib/utils"
import {
  FileText,
  Plus,
  Loader2,
  AlertTriangle,
  CheckCircle,
  BookOpen,
  Shield,
  Search,
  RefreshCw,
} from "lucide-react"

/* ── Types ──────────────────────────────────────────── */

type Document = {
  id: string
  title: string
  source: string
  document_type: string
  content?: string
  metadata?: Record<string, any>
  created_at: string
  updated_at?: string
}

type IngestForm = {
  title: string
  source: string
  document_type: string
  content: string
  metadata: string
}

const DOC_TYPES = [
  "mitre_attack",
  "incident_report",
  "postmortem",
  "threat_intel",
  "playbook",
  "runbook",
  "policy",
  "generic",
]

const DOC_TYPE_LABELS: Record<string, string> = {
  mitre_attack: "MITRE ATT&CK",
  incident_report: "Incident Report",
  postmortem: "Postmortem",
  threat_intel: "Threat Intel",
  playbook: "Playbook",
  runbook: "Runbook",
  policy: "Policy",
  generic: "Generic",
}

function docTypeIcon(dt: string) {
  if (dt === "mitre_attack") return <Shield className="h-4 w-4 text-blue-400" />
  if (dt === "incident_report") return <AlertTriangle className="h-4 w-4 text-orange-400" />
  if (dt === "postmortem") return <FileText className="h-4 w-4 text-purple-400" />
  return <BookOpen className="h-4 w-4 text-muted-foreground" />
}

/* ── Main Page ──────────────────────────────────────── */

export default function KnowledgePage() {
  const [documents, setDocuments] = useState<Document[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState("")

  // Ingest form state
  const [showForm, setShowForm] = useState(false)
  const [ingesting, setIngesting] = useState(false)
  const [ingestSuccess, setIngestSuccess] = useState(false)
  const [ingestError, setIngestError] = useState<string | null>(null)
  const [form, setForm] = useState<IngestForm>({
    title: "",
    source: "",
    document_type: "generic",
    content: "",
    metadata: "{}",
  })

  const fetchDocuments = async () => {
    setLoading(true)
    setError(null)
    try {
      const docs = await api.get<Document[]>("/documents/")
      setDocuments(docs)
    } catch (err: any) {
      setError(err.message || "Failed to load documents")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchDocuments()
  }, [])

  const handleIngest = async () => {
    setIngesting(true)
    setIngestError(null)
    setIngestSuccess(false)

    try {
      let metadata = {}
      if (form.metadata.trim()) {
        metadata = JSON.parse(form.metadata)
      }

      await api.post("/documents/ingest", {
        title: form.title,
        source: form.source,
        document_type: form.document_type,
        content: form.content,
        metadata,
      })

      setIngestSuccess(true)
      setForm({ title: "", source: "", document_type: "generic", content: "", metadata: "{}" })
      fetchDocuments() // Refresh list

      setTimeout(() => setIngestSuccess(false), 3000)
    } catch (err: any) {
      setIngestError(err.message || "Failed to ingest document")
    } finally {
      setIngesting(false)
    }
  }

  const filteredDocs = documents.filter((doc) => {
    if (!searchQuery) return true
    const q = searchQuery.toLowerCase()
    return (
      doc.title?.toLowerCase().includes(q) ||
      doc.source?.toLowerCase().includes(q) ||
      doc.document_type?.toLowerCase().includes(q)
    )
  })

  return (
    <div className="min-h-screen bg-background">
      <NavHeader title="Knowledge Base" />

      <main className="p-6 max-w-5xl mx-auto space-y-6">
        {/* Header row */}
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold">Documents</h2>
            <p className="text-sm text-muted-foreground">
              {documents.length} document{documents.length !== 1 ? "s" : ""} in the knowledge base
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={fetchDocuments}
              disabled={loading}
              className="flex items-center gap-1.5 rounded-md border border-border px-3 py-2 text-sm hover:bg-muted transition-colors disabled:opacity-50"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
              Refresh
            </button>
            <button
              onClick={() => setShowForm(!showForm)}
              className={cn(
                "flex items-center gap-1.5 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                showForm
                  ? "bg-muted text-foreground"
                  : "bg-primary text-primary-foreground hover:bg-primary/90"
              )}
            >
              <Plus className="h-3.5 w-3.5" />
              {showForm ? "Cancel" : "Ingest Document"}
            </button>
          </div>
        </div>

        {/* Ingest form */}
        {showForm && (
          <div className="rounded-lg border border-border bg-card p-6 space-y-4">
            <h3 className="text-base font-semibold flex items-center gap-2">
              <Plus className="h-4 w-4" />
              Ingest New Document
            </h3>

            {ingestSuccess && (
              <div className="flex items-center gap-2 rounded-md bg-emerald-500/10 border border-emerald-500/30 p-3 text-sm text-emerald-400">
                <CheckCircle className="h-4 w-4" />
                Document ingested successfully!
              </div>
            )}

            {ingestError && (
              <div className="flex items-center gap-2 rounded-md bg-red-500/10 border border-red-500/30 p-3 text-sm text-red-400">
                <AlertTriangle className="h-4 w-4" />
                {ingestError}
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium mb-1">Title</label>
                <input
                  type="text"
                  value={form.title}
                  onChange={(e) => setForm({ ...form, title: e.target.value })}
                  placeholder="e.g., MITRE ATT&CK T1059.001"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Source</label>
                <input
                  type="text"
                  value={form.source}
                  onChange={(e) => setForm({ ...form, source: e.target.value })}
                  placeholder="e.g., https://attack.mitre.org/techniques/T1059/001/"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">Document Type</label>
              <select
                value={form.document_type}
                onChange={(e) => setForm({ ...form, document_type: e.target.value })}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                {DOC_TYPES.map((dt) => (
                  <option key={dt} value={dt}>
                    {DOC_TYPE_LABELS[dt] || dt}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">Content</label>
              <textarea
                value={form.content}
                onChange={(e) => setForm({ ...form, content: e.target.value })}
                placeholder="Paste the document content here..."
                rows={6}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring resize-y"
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">
                Metadata <span className="text-muted-foreground font-normal">(JSON, optional)</span>
              </label>
              <textarea
                value={form.metadata}
                onChange={(e) => setForm({ ...form, metadata: e.target.value })}
                placeholder='{"key": "value"}'
                rows={3}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring resize-y"
              />
            </div>

            <button
              onClick={handleIngest}
              disabled={ingesting || !form.title || !form.content}
              className="flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {ingesting ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Plus className="h-4 w-4" />
              )}
              {ingesting ? "Ingesting..." : "Ingest"}
            </button>
          </div>
        )}

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search documents..."
            className="w-full rounded-md border border-border bg-card pl-10 pr-4 py-2.5 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>

        {/* Error */}
        {error && (
          <div className="flex items-center gap-2 rounded-md bg-red-500/10 border border-red-500/30 p-4 text-sm text-red-400">
            <AlertTriangle className="h-4 w-4" />
            {error}
          </div>
        )}

        {/* Document list */}
        {loading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground py-8 justify-center">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading documents...
          </div>
        ) : filteredDocs.length === 0 ? (
          <div className="text-center py-12 text-muted-foreground">
            <BookOpen className="h-10 w-10 mx-auto mb-3 opacity-50" />
            <p className="text-sm">
              {searchQuery ? "No documents match your search." : "No documents in the knowledge base yet."}
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {filteredDocs.map((doc) => (
              <div
                key={doc.id}
                className="rounded-lg border border-border bg-card p-4 hover:bg-muted/30 transition-colors"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-3 min-w-0">
                    <div className="mt-0.5 flex-shrink-0">{docTypeIcon(doc.document_type)}</div>
                    <div className="min-w-0">
                      <h3 className="text-sm font-semibold truncate">
                        {doc.title || "Untitled"}
                      </h3>
                      {doc.source && (
                        <p className="text-xs text-muted-foreground truncate mt-0.5">
                          {doc.source}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="px-2 py-0.5 rounded text-xs font-medium bg-muted text-muted-foreground">
                      {DOC_TYPE_LABELS[doc.document_type] || doc.document_type}
                    </span>
                  </div>
                </div>
                <div className="mt-2 flex items-center gap-3 text-xs text-muted-foreground">
                  <span className="font-mono">{doc.id.slice(0, 8)}</span>
                  <span>
                    Created: {new Date(doc.created_at).toLocaleString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  )
}
