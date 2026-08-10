"use client"

import {
  useCallback,
  useEffect,
  useState,
} from "react"

import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  useNodesState,
  useEdgesState,
  addEdge,
  Connection,
} from "@xyflow/react"

import "@xyflow/react/dist/style.css"

import { useSearchParams } from "next/navigation"

import { api } from "@/lib/api"
import { NavHeader } from "@/components/nav-header"


type CorrelationResult = {
  id: string
  alert_id: string

  matched_incident_ids?: string[] | null
  matched_cve_ids?: string[] | null
  matched_mitre_techniques?: string[] | null

  reasoning_text?: string | null
  confidence_score?: number | null
  verdict?: string | null
  grounding_passed?: boolean | null
  retry_count?: number

  created_at?: string
}


export default function AttackReplayPage() {
  const searchParams = useSearchParams()

  const [nodes, setNodes, onNodesChange] =
    useNodesState<Node>([])

  const [edges, setEdges, onEdgesChange] =
    useEdgesState<Edge>([])

  const [alertId, setAlertId] = useState("")

  const [loading, setLoading] =
    useState(false)

  const [error, setError] =
    useState<string | null>(null)

  const [hasTraced, setHasTraced] =
    useState(false)


  // ==========================================================
  // React Flow connections
  // ==========================================================

  const onConnect = useCallback(
    (connection: Connection) => {
      setEdges((eds) =>
        addEdge(connection, eds)
      )
    },
    [setEdges]
  )


  // ==========================================================
  // Read alertId from URL
  //
  // Example:
  // /attack-replay?alertId=2d959777-xxxx-xxxx-xxxx-xxxxxxxx
  // ==========================================================

  useEffect(() => {
    const urlAlertId =
      searchParams.get("alertId")

    if (urlAlertId) {
      setAlertId(urlAlertId)
    }
  }, [searchParams])


  // ==========================================================
  // Build graph from actual correlation result
  // ==========================================================

  const buildGraphFromCorrelation = (
    correlation: CorrelationResult
  ) => {
    const graphNodes: Node[] = []
    const graphEdges: Edge[] = []

    // --------------------------------------------------------
    // Alert node
    // --------------------------------------------------------

    const alertNodeId =
      `alert-${correlation.alert_id}`

    graphNodes.push({
      id: alertNodeId,
      type: "input",

      data: {
        label: `Alert\n${correlation.alert_id.slice(0, 8)}`,
      },

      position: {
        x: 0,
        y: 250,
      },

      style: {
        borderColor: "#ef4444",
        borderWidth: 2,
        padding: 12,
        minWidth: 180,
      },
    })


    // --------------------------------------------------------
    // Incident nodes
    // --------------------------------------------------------

    const incidents =
      correlation.matched_incident_ids || []

    incidents.forEach(
      (incidentId, index) => {
        const nodeId =
          `incident-${incidentId}`

        graphNodes.push({
          id: nodeId,
          type: "output",

          data: {
            label: `Incident\n${incidentId.slice(0, 8)}`,
          },

          position: {
            x: 400,
            y: index * 160,
          },

          style: {
            borderColor: "#f59e0b",
            borderWidth: 2,
            padding: 12,
            minWidth: 180,
          },
        })

        graphEdges.push({
          id: `edge-alert-incident-${index}`,
          source: alertNodeId,
          target: nodeId,

          animated: true,

          style: {
            stroke: "#f59e0b",
          },
        })
      }
    )


    // --------------------------------------------------------
    // MITRE technique nodes
    // --------------------------------------------------------

    const techniques =
      correlation.matched_mitre_techniques || []

    techniques.forEach(
      (technique, index) => {
        const nodeId =
          `technique-${technique}-${index}`

        graphNodes.push({
          id: nodeId,

          data: {
            label: `MITRE\n${technique}`,
          },

          position: {
            x: 400,
            y: 300 + index * 130,
          },

          style: {
            borderColor: "#8b5cf6",
            borderWidth: 2,
            padding: 12,
            minWidth: 180,
          },
        })

        graphEdges.push({
          id: `edge-alert-technique-${index}`,
          source: alertNodeId,
          target: nodeId,

          style: {
            stroke: "#8b5cf6",
          },
        })
      }
    )


    // --------------------------------------------------------
    // CVE nodes
    // --------------------------------------------------------

    const cves =
      correlation.matched_cve_ids || []

    cves.forEach(
      (cve, index) => {
        const nodeId =
          `cve-${cve}-${index}`

        graphNodes.push({
          id: nodeId,

          data: {
            label: `CVE\n${cve}`,
          },

          position: {
            x: 800,
            y: index * 130,
          },

          style: {
            borderColor: "#06b6d4",
            borderWidth: 2,
            padding: 12,
            minWidth: 180,
          },
        })

        graphEdges.push({
          id: `edge-alert-cve-${index}`,
          source: alertNodeId,
          target: nodeId,

          style: {
            stroke: "#06b6d4",
          },
        })
      }
    )


    // --------------------------------------------------------
    // If correlation exists but has no relationships
    // --------------------------------------------------------

    if (
      graphNodes.length === 1
    ) {
      graphNodes.push({
        id: "no-correlation",

        data: {
          label:
            "No correlated entities found",
        },

        position: {
          x: 400,
          y: 250,
        },

        style: {
          borderColor: "#6b7280",
          borderWidth: 1,
          padding: 12,
          minWidth: 220,
        },
      })

      graphEdges.push({
        id: "edge-no-correlation",
        source: alertNodeId,
        target: "no-correlation",

        style: {
          stroke: "#6b7280",
          strokeDasharray: "5 5",
        },
      })
    }


    setNodes(graphNodes)
    setEdges(graphEdges)
  }


  // ==========================================================
  // Fetch correlation
  // ==========================================================

  const fetchCorrelationGraph = async () => {
    if (!alertId.trim()) {
      setError("Please provide an alert ID.")
      return
    }

    setLoading(true)
    setError(null)
    setHasTraced(false)

    try {
      const result =
        await api.get<CorrelationResult>(
          `/alerts/${encodeURIComponent(
            alertId.trim()
          )}/correlation`
        )

      buildGraphFromCorrelation(result)

      setHasTraced(true)

    } catch (err) {
      console.error(
        "Failed to fetch correlation:",
        err
      )

      setNodes([])
      setEdges([])

      setError(
        err instanceof Error
          ? err.message
          : "Failed to load attack correlation."
      )
    } finally {
      setLoading(false)
    }
  }


  // ==========================================================
  // Demo graph
  //
  // This is ONLY available through the Demo button.
  // API failure will NEVER show fake data.
  // ==========================================================

  const buildDemoGraph = () => {
    const demoNodes: Node[] = [
      {
        id: "alert-1",
        type: "input",

        data: {
          label:
            "Alert: Brute Force SSH",
        },

        position: {
          x: 0,
          y: 100,
        },

        style: {
          borderColor: "#ef4444",
          borderWidth: 2,
        },
      },

      {
        id: "asset-1",

        data: {
          label:
            "Asset: srv-01.corp.local",
        },

        position: {
          x: 300,
          y: 0,
        },

        style: {
          borderColor: "#3b82f6",
          borderWidth: 2,
        },
      },

      {
        id: "alert-2",
        type: "input",

        data: {
          label:
            "Alert: Lateral Movement",
        },

        position: {
          x: 300,
          y: 200,
        },

        style: {
          borderColor: "#ef4444",
          borderWidth: 2,
        },
      },

      {
        id: "asset-2",

        data: {
          label:
            "Asset: srv-02.corp.local",
        },

        position: {
          x: 600,
          y: 100,
        },

        style: {
          borderColor: "#3b82f6",
          borderWidth: 2,
        },
      },

      {
        id: "incident-1",
        type: "output",

        data: {
          label:
            "Incident: SSH Compromise",
        },

        position: {
          x: 600,
          y: 300,
        },

        style: {
          borderColor: "#f59e0b",
          borderWidth: 2,
        },
      },

      {
        id: "technique-1",

        data: {
          label: "MITRE: T1110",
        },

        position: {
          x: 900,
          y: 100,
        },

        style: {
          borderColor: "#8b5cf6",
          borderWidth: 2,
        },
      },

      {
        id: "technique-2",

        data: {
          label:
            "MITRE: T1021.002",
        },

        position: {
          x: 900,
          y: 300,
        },

        style: {
          borderColor: "#8b5cf6",
          borderWidth: 2,
        },
      },
    ]


    const demoEdges: Edge[] = [
      {
        id: "e1",
        source: "alert-1",
        target: "asset-1",
        animated: true,

        style: {
          stroke: "#ef4444",
        },
      },

      {
        id: "e2",
        source: "alert-1",
        target: "technique-1",

        style: {
          stroke: "#8b5cf6",
        },
      },

      {
        id: "e3",
        source: "alert-2",
        target: "asset-2",
        animated: true,

        style: {
          stroke: "#ef4444",
        },
      },

      {
        id: "e4",
        source: "asset-1",
        target: "asset-2",

        style: {
          stroke: "#3b82f6",
          strokeDasharray: "5 5",
        },
      },

      {
        id: "e5",
        source: "alert-2",
        target: "incident-1",

        style: {
          stroke: "#f59e0b",
        },
      },

      {
        id: "e6",
        source: "alert-2",
        target: "technique-2",

        style: {
          stroke: "#8b5cf6",
        },
      },
    ]

    setNodes(demoNodes)
    setEdges(demoEdges)

    setError(null)
    setHasTraced(false)
  }


  return (
    <div className="min-h-screen bg-background">

      <NavHeader title="Attack Replay" />

      <main className="p-6">

        {/* ================================================= */}
        {/* Controls */}
        {/* ================================================= */}

        <div className="flex gap-4 mb-4">

          <input
            type="text"
            placeholder="Enter full alert UUID..."
            value={alertId}
            onChange={(e) =>
              setAlertId(e.target.value)
            }
            className="flex-1 px-4 py-2 rounded-md border border-border bg-background font-mono text-sm"
          />

          <button
            onClick={fetchCorrelationGraph}
            disabled={loading || !alertId.trim()}
            className="px-6 py-2 rounded-md bg-primary text-primary-foreground font-medium hover:bg-primary/90 disabled:opacity-50"
          >
            {loading
              ? "Loading..."
              : "Trace"}
          </button>

          <button
            onClick={buildDemoGraph}
            disabled={loading}
            className="px-4 py-2 rounded-md border border-border hover:bg-muted text-sm"
          >
            Demo
          </button>

        </div>


        {/* ================================================= */}
        {/* Error */}
        {/* ================================================= */}

        {error && (
          <div className="mb-4 rounded-lg border border-red-500/50 bg-red-500/10 p-4">

            <p className="font-semibold text-red-400">
              Attack Replay Error
            </p>

            <p className="text-sm text-red-300 mt-1">
              {error}
            </p>

          </div>
        )}


        {/* ================================================= */}
        {/* Correlation status */}
        {/* ================================================= */}

        {hasTraced && !error && (
          <div className="mb-4 rounded-lg border border-border bg-card p-4">

            <p className="text-sm">
              Correlation loaded for:
            </p>

            <p className="font-mono text-xs text-muted-foreground mt-1">
              {alertId}
            </p>

          </div>
        )}


        {/* ================================================= */}
        {/* Graph */}
        {/* ================================================= */}

        <div className="h-[600px] rounded-lg border border-border overflow-hidden">

          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            fitView
          >

            <Background />

            <Controls />

            <MiniMap />

          </ReactFlow>

        </div>


        {/* ================================================= */}
        {/* Explanation */}
        {/* ================================================= */}

        <div className="mt-4 text-sm text-muted-foreground">

          <p>
            <strong>
              Attack Replay
            </strong>{" "}
            visualizes correlation data associated
            with an alert.
          </p>

          <p className="mt-1">
            Red = alerts · Amber = incidents ·
            Purple = MITRE ATT&amp;CK · Cyan = CVEs.
          </p>

          <p className="mt-1 text-xs">
            The Demo button shows sample data.
            Trace uses your authenticated backend.
          </p>

        </div>

      </main>
    </div>
  )
}
