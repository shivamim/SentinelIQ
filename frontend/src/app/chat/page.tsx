"use client"

import { useEffect, useRef, useState, useCallback } from "react"
import { NavHeader } from "@/components/nav-header"
import { api, apiFetch } from "@/lib/api"
import { cn } from "@/lib/utils"
import {
  Send,
  AlertTriangle,
  CheckCircle,
  BookOpen,
  Loader2,
  ChevronDown,
  ChevronUp,
  RotateCcw,
  Search,
  Shield,
  XCircle,
  FileText,
  Sparkles,
} from "lucide-react"

/* ── Types ──────────────────────────────────────────── */

type Source = {
  document_id: string
  chunk_id: string
  title: string
  source: string
  document_type: string
  score: number
  chunk_text: string
}

type RetrievalMetrics = {
  chunks_retrieved: number
  reranked_count: number
  sources_used: number
  vector_score_range: string
  bm25_score_range: string
  rrf_score_range: string
}

type ChatResponse = {
  answer: string
  sources: Source[]
  retrieval_metrics: RetrievalMetrics
  grounding_status: "fully_grounded" | "partially_grounded" | "ungrounded"
  conversation_id: string
}

type UserMessage = { role: "user"; content: string }
type AssistantMessage = {
  role: "assistant"
  content: string
  sources: Source[]
  retrievalMetrics: RetrievalMetrics | null
  groundingStatus: string | null
  conversationId: string | null
  error?: string
}
type Message = UserMessage | AssistantMessage

/* ── Helpers ────────────────────────────────────────── */

function groundingColor(status: string | null) {
  if (status === "fully_grounded") return "text-emerald-400"
  if (status === "partially_grounded") return "text-amber-400"
  return "text-red-400"
}

function groundingIcon(status: string | null) {
  if (status === "fully_grounded")
    return <CheckCircle className="h-4 w-4 text-emerald-400" />
  if (status === "partially_grounded")
    return <AlertTriangle className="h-4 w-4 text-amber-400" />
  return <XCircle className="h-4 w-4 text-red-400" />
}

function groundingLabel(status: string | null) {
  if (status === "fully_grounded") return "Fully Grounded"
  if (status === "partially_grounded") return "Partially Grounded"
  return "Ungrounded"
}

function docTypeIcon(dt: string) {
  if (dt === "mitre_attack") return <Shield className="h-3.5 w-3.5 text-blue-400" />
  if (dt === "incident_report") return <AlertTriangle className="h-3.5 w-3.5 text-orange-400" />
  if (dt === "postmortem") return <FileText className="h-3.5 w-3.5 text-purple-400" />
  return <BookOpen className="h-3.5 w-3.5 text-muted-foreground" />
}

/* ── Source Card ────────────────────────────────────── */

function SourceCard({
  source,
  index,
}: {
  source: Source
  index: number
}) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div
      className={cn(
        "rounded-md border border-border bg-card p-3 transition-colors",
        "hover:bg-muted/30 cursor-pointer"
      )}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="flex-shrink-0 text-xs font-mono text-muted-foreground">
            [{index + 1}]
          </span>
          {docTypeIcon(source.document_type)}
          <span className="text-sm font-medium truncate">
            {source.title || source.source}
          </span>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="text-xs text-muted-foreground">
            Score: {source.score.toFixed(2)}
          </span>
          {expanded ? (
            <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
          )}
        </div>
      </div>
      {expanded && source.chunk_text && (
        <div className="mt-2 rounded bg-muted/50 p-2 text-xs text-muted-foreground leading-relaxed whitespace-pre-wrap">
          {source.chunk_text}
        </div>
      )}
    </div>
  )
}

/* ── Main Page ──────────────────────────────────────── */

export default function ChatPage() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState("")
  const [loading, setLoading] = useState(false)
  const [streaming, setStreaming] = useState(false)
  const [streamTokens, setStreamTokens] = useState("")
  const [statusMessage, setStatusMessage] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [conversationId, setConversationId] = useState<string | null>(null)
  const [docTypeFilter, setDocTypeFilter] = useState<string>("")
  const [useStreaming, setUseStreaming] = useState(true)

  const bottomRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const abortRef = useRef<AbortController | null>(null)

  /* auto-scroll */
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [messages, streamTokens, statusMessage])

  /* focus input on mount */
  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  /* ── Send message ────────────────────────────────── */

  const sendMessage = useCallback(async () => {
    const text = input.trim()
    if (!text || loading) return

    // Add user message
    const userMsg: UserMessage = { role: "user", content: text }
    setMessages((prev) => [...prev, userMsg])
    setInput("")
    setError(null)
    setLoading(true)

    if (useStreaming) {
      await sendStreaming(text)
    } else {
      await sendNonStreaming(text)
    }
  }, [input, loading, useStreaming, conversationId, docTypeFilter])

  /* ── Non-streaming ───────────────────────────────── */

  const sendNonStreaming = async (text: string) => {
    try {
      const body: Record<string, any> = {
        question: text,
        conversation_id: conversationId,
      }
      if (docTypeFilter) body.document_type = docTypeFilter

      const res = await api.post<ChatResponse>("/chat/", body)

      const assistantMsg: AssistantMessage = {
        role: "assistant",
        content: res.answer,
        sources: res.sources,
        retrievalMetrics: res.retrieval_metrics,
        groundingStatus: res.grounding_status,
        conversationId: res.conversation_id,
      }
      setMessages((prev) => [...prev, assistantMsg])
      setConversationId(res.conversation_id)
    } catch (err: any) {
      setError(err.message || "Failed to get response")
      const assistantMsg: AssistantMessage = {
        role: "assistant",
        content: "",
        sources: [],
        retrievalMetrics: null,
        groundingStatus: null,
        conversationId: null,
        error: err.message || "Failed to get response",
      }
      setMessages((prev) => [...prev, assistantMsg])
    } finally {
      setLoading(false)
    }
  }

  /* ── SSE Streaming ───────────────────────────────── */

  const sendStreaming = async (text: string) => {
    setStreaming(true)
    setStreamTokens("")
    setStatusMessage("Connecting...")

    const abort = new AbortController()
    abortRef.current = abort

    try {
      // We need to use fetch directly for SSE because apiFetch parses JSON
      const { supabase } = await import("@/components/auth-provider")
      const { data: { session } } = await supabase.auth.getSession()
      const token = session?.access_token || ""

      const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

      const body: Record<string, any> = {
        question: text,
        conversation_id: conversationId,
      }
      if (docTypeFilter) body.document_type = docTypeFilter

      const res = await fetch(`${API_BASE}/chat/stream`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(body),
        signal: abort.signal,
      })

      if (!res.ok) {
        const errData = await res.json().catch(() => ({ detail: res.statusText }))
        throw new Error(errData.detail || `Stream error: ${res.status}`)
      }

      const reader = res.body?.getReader()
      if (!reader) throw new Error("No readable stream")

      const decoder = new TextDecoder()
      let buffer = ""
      let fullAnswer = ""
      let sources: Source[] = []
      let retrievalMetrics: RetrievalMetrics | null = null
      let groundingStatus: string | null = null
      let convId: string | null = null

      let currentEvent = ""

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })

        // Parse SSE events from buffer
        const lines = buffer.split("\n")
        buffer = lines.pop() || "" // Keep incomplete line in buffer

        for (const line of lines) {
          if (line.startsWith("event: ")) {
            currentEvent = line.slice(7).trim()
            continue
          }
          if (line.startsWith("data: ")) {
            const dataStr = line.slice(6)
            try {
              const data = JSON.parse(dataStr)

              if (currentEvent === "token") {
                fullAnswer += data.text
                setStreamTokens(fullAnswer)
              } else if (currentEvent === "status") {
                setStatusMessage(data.message)
              } else if (currentEvent === "done") {
                sources = data.sources || []
                retrievalMetrics = data.retrieval_metrics || null
                groundingStatus = data.grounding_status || null
                convId = data.conversation_id || null
                fullAnswer = data.answer || fullAnswer
              } else if (currentEvent === "error") {
                throw new Error(data.message || "Stream error")
              }
            } catch (parseErr: any) {
              // If it's our thrown error, re-throw
              if (parseErr.message && !parseErr.message.includes("JSON")) throw parseErr
            }
            currentEvent = ""
          }
        }
      }

      // Finalize
      const assistantMsg: AssistantMessage = {
        role: "assistant",
        content: fullAnswer,
        sources,
        retrievalMetrics,
        groundingStatus,
        conversationId: convId,
      }
      setMessages((prev) => [...prev, assistantMsg])
      if (convId) setConversationId(convId)
    } catch (err: any) {
      if (err.name === "AbortError") return
      setError(err.message || "Stream failed")
      const assistantMsg: AssistantMessage = {
        role: "assistant",
        content: "",
        sources: [],
        retrievalMetrics: null,
        groundingStatus: null,
        conversationId: null,
        error: err.message || "Stream failed",
      }
      setMessages((prev) => [...prev, assistantMsg])
    } finally {
      setStreaming(false)
      setStreamTokens("")
      setStatusMessage("")
      setLoading(false)
      abortRef.current = null
    }
  }

  /* ── Retry ────────────────────────────────────────── */

  const retry = () => {
    // Remove the last assistant message if it was an error
    setMessages((prev) => {
      const last = prev[prev.length - 1]
      if (last?.role === "assistant" && last.error) {
        return prev.slice(0, -1)
      }
      return prev
    })
    setError(null)
    // Re-send the last user message
    const lastUser = [...messages].reverse().find((m) => m.role === "user")
    if (lastUser) {
      setInput(lastUser.content)
      setTimeout(() => {
        inputRef.current?.focus()
      }, 100)
    }
  }

  /* ── Clear conversation ───────────────────────────── */

  const clearConversation = () => {
    setMessages([])
    setConversationId(null)
    setError(null)
    setStreamTokens("")
    setStatusMessage("")
  }

  /* ── Key handler ──────────────────────────────────── */

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  /* ── Render ───────────────────────────────────────── */

  return (
    <div className="flex h-screen flex-col bg-background">
      <NavHeader title="AI Chat" />

      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Messages area */}
        <div className="flex-1 overflow-y-auto px-4 py-6 md:px-8">
          <div className="mx-auto max-w-3xl space-y-6">
            {/* Welcome message */}
            {messages.length === 0 && !loading && (
              <div className="flex flex-col items-center justify-center py-20 text-center">
                <Sparkles className="h-12 w-12 text-primary/60 mb-4" />
                <h2 className="text-xl font-semibold mb-2">
                  SentinelIQ AI Investigation Assistant
                </h2>
                <p className="text-sm text-muted-foreground max-w-md">
                  Ask questions about MITRE ATT&amp;CK techniques, incident patterns,
                  threat intelligence, and security postmortems. Responses are
                  grounded in your knowledge base with source citations.
                </p>
              </div>
            )}

            {/* Messages */}
            {messages.map((msg, i) => {
              if (msg.role === "user") {
                return (
                  <div key={i} className="flex justify-end">
                    <div className="max-w-[80%] rounded-lg bg-primary px-4 py-3 text-primary-foreground">
                      <p className="text-sm whitespace-pre-wrap">{msg.content}</p>
                    </div>
                  </div>
                )
              }

              // Assistant message
              return (
                <div key={i} className="flex justify-start">
                  <div className="max-w-[90%] space-y-3">
                    {/* Error state */}
                    {msg.error ? (
                      <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4">
                        <div className="flex items-center gap-2 text-red-400 mb-2">
                          <AlertTriangle className="h-4 w-4" />
                          <span className="text-sm font-medium">Error</span>
                        </div>
                        <p className="text-sm text-red-300">{msg.error}</p>
                        <button
                          onClick={retry}
                          className="mt-3 flex items-center gap-1.5 rounded-md bg-red-500/20 px-3 py-1.5 text-xs text-red-300 hover:bg-red-500/30 transition-colors"
                        >
                          <RotateCcw className="h-3 w-3" />
                          Retry
                        </button>
                      </div>
                    ) : (
                      <>
                        {/* Answer */}
                        {msg.content && (
                          <div className="rounded-lg border border-border bg-card p-4">
                            <p className="text-sm leading-relaxed whitespace-pre-wrap">
                              {msg.content}
                            </p>
                          </div>
                        )}

                        {/* Ungrounded warning */}
                        {msg.groundingStatus === "ungrounded" && (
                          <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 flex items-start gap-2">
                            <AlertTriangle className="h-4 w-4 text-amber-400 mt-0.5 flex-shrink-0" />
                            <div>
                              <p className="text-sm font-medium text-amber-300">
                                Insufficient Evidence
                              </p>
                              <p className="text-xs text-amber-400/80 mt-0.5">
                                This response could not be grounded in the knowledge base.
                                Verify independently.
                              </p>
                            </div>
                          </div>
                        )}

                        {/* Sources */}
                        {msg.sources && msg.sources.length > 0 && (
                          <div className="space-y-2">
                            <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                              <BookOpen className="h-3.5 w-3.5" />
                              Sources
                            </div>
                            <div className="space-y-2">
                              {msg.sources.map((src, j) => (
                                <SourceCard key={j} source={src} index={j} />
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Grounding + Metrics */}
                        {(msg.groundingStatus || msg.retrievalMetrics) && (
                          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                            {msg.groundingStatus && (
                              <span className="flex items-center gap-1">
                                {groundingIcon(msg.groundingStatus)}
                                <span className={groundingColor(msg.groundingStatus)}>
                                  {groundingLabel(msg.groundingStatus)}
                                </span>
                              </span>
                            )}
                            {msg.retrievalMetrics && (
                              <span>
                                Retrieved: {msg.retrievalMetrics.chunks_retrieved} chunks
                                {" | "}
                                Reranked: {msg.retrievalMetrics.reranked_count}
                                {" | "}
                                Sources: {msg.retrievalMetrics.sources_used}
                              </span>
                            )}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                </div>
              )
            })}

            {/* Streaming tokens */}
            {streaming && (
              <div className="flex justify-start">
                <div className="max-w-[90%] space-y-3">
                  <div className="rounded-lg border border-border bg-card p-4">
                    {streamTokens ? (
                      <p className="text-sm leading-relaxed whitespace-pre-wrap">
                        {streamTokens}
                        <span className="inline-block w-1.5 h-4 ml-0.5 bg-primary animate-pulse rounded-sm" />
                      </p>
                    ) : (
                      <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <Loader2 className="h-4 w-4 animate-spin" />
                        <span>{statusMessage || "Thinking..."}</span>
                      </div>
                    )}
                  </div>
                  {statusMessage && streamTokens && (
                    <p className="text-xs text-muted-foreground">{statusMessage}</p>
                  )}
                </div>
              </div>
            )}

            {/* Non-streaming loading */}
            {loading && !streaming && (
              <div className="flex justify-start">
                <div className="rounded-lg border border-border bg-card p-4">
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Searching knowledge base...</span>
                  </div>
                </div>
              </div>
            )}

            <div ref={bottomRef} />
          </div>
        </div>

        {/* Input area */}
        <div className="border-t border-border bg-background px-4 py-4 md:px-8">
          <div className="mx-auto max-w-3xl space-y-3">
            {/* Filters row */}
            <div className="flex flex-wrap items-center gap-3 text-xs">
              <select
                value={docTypeFilter}
                onChange={(e) => setDocTypeFilter(e.target.value)}
                className="rounded-md border border-border bg-muted/50 px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
              >
                <option value="">All Document Types</option>
                <option value="mitre_attack">MITRE ATT&amp;CK</option>
                <option value="incident_report">Incident Report</option>
                <option value="postmortem">Postmortem</option>
                <option value="threat_intel">Threat Intel</option>
                <option value="playbook">Playbook</option>
              </select>

              <label className="flex items-center gap-1.5 text-muted-foreground cursor-pointer">
                <input
                  type="checkbox"
                  checked={useStreaming}
                  onChange={(e) => setUseStreaming(e.target.checked)}
                  className="rounded border-border"
                />
                Streaming
              </label>

              {conversationId && (
                <button
                  onClick={clearConversation}
                  className="ml-auto text-muted-foreground hover:text-foreground transition-colors"
                >
                  New Conversation
                </button>
              )}
            </div>

            {/* Input row */}
            <div className="flex items-end gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground pointer-events-none" />
                <textarea
                  ref={inputRef}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Ask a cybersecurity question..."
                  disabled={loading}
                  rows={1}
                  className="w-full resize-none rounded-lg border border-border bg-card pl-10 pr-4 py-3 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
                  style={{ minHeight: "44px", maxHeight: "120px" }}
                  onInput={(e) => {
                    const el = e.currentTarget
                    el.style.height = "auto"
                    el.style.height = Math.min(el.scrollHeight, 120) + "px"
                  }}
                />
              </div>
              <button
                onClick={sendMessage}
                disabled={loading || !input.trim()}
                className="flex h-11 w-11 items-center justify-center rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                <Send className="h-4 w-4" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
