"use client"

import { useCallback, useState } from "react"
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

import { api } from "@/lib/api"
import { NavHeader } from "@/components/nav-header"


type GraphNode = {
  id: string
  type: "alert" | "asset" | "incident" | "technique" | "unknown"
  labels?: string[]
  properties?: Record<string, any>
}


type GraphEdge = {
  id: string
  source: string
  target: string
  type?: string
  relationship?: string
}


type AttackReplayResponse = {
  alert_id: string
  nodes: GraphNode[]
  edges: GraphEdge[]
}


export default function AttackReplayPage() {
  const [nodes, setNodes, onNodesChange] =
    useNodesState<Node>([])

  const [edges, setEdges, onEdgesChange] =
    useEdgesState<Edge>([])

  const [alertId, setAlertId] =
    useState("")

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
      setEdges((currentEdges) =>
        addEdge(
          connection,
          currentEdges
        )
      )
    },
    [setEdges]
  )


  // ==========================================================
  // Convert Neo4j node → React Flow node
  // ==========================================================

  const convertNode = (
    node: GraphNode,
    index: number
  ): Node => {
    const properties =
      node.properties || {}

    let label = node.id

    let borderColor = "#6b7280"

    let flowType:
      | "input"
      | "output"
      | "default" = "default"


    switch (node.type) {
      case "alert":
        label =
          `Alert: ${
            properties.alert_type ||
            "Unknown"
          }`

        borderColor = "#ef4444"

        flowType = "input"

        break


      case "asset":
        label =
          `Asset: ${
            properties.hostname ||
            properties.ip ||
            "Unknown"
          }`

        borderColor = "#3b82f6"

        break


      case "incident":
        label =
          `Incident: ${
            properties.title ||
            "Unknown"
          }`

        borderColor = "#f59e0b"

        flowType = "output"

        break


      case "technique":
        label =
          `MITRE: ${
            properties.name ||
            properties.id ||
            "Unknown"
          }`

        borderColor = "#8b5cf6"

        break


      default:
        label =
          `${node.type}: ${node.id}`

        break
    }


    return {
      id: node.id,

      type: flowType,

      data: {
        label,
      },

      position: {
        x: (index % 4) * 300,
        y:
          Math.floor(index / 4) *
          180,
      },

      style: {
        borderColor,
        borderWidth: 2,
        borderRadius: 8,
        padding: 12,
        minWidth: 190,
        background:
          "var(--background)",
      },
    }
  }


  // ==========================================================
  // Convert Neo4j edge → React Flow edge
  // ==========================================================

  const convertEdge = (
    edge: GraphEdge
  ): Edge => {
    let stroke = "#6b7280"


    switch (
      edge.relationship
    ) {
      case "TARGETS":
        stroke = "#3b82f6"
        break

      case "CORRELATES_TO":
        stroke = "#f59e0b"
        break

      case "USES_TECHNIQUE":
        stroke = "#8b5cf6"
        break

      case "CONNECTED_TO":
        stroke = "#06b6d4"
        break

      default:
        stroke = "#6b7280"
        break
    }


    return {
      id: edge.id,

      source: edge.source,

      target: edge.target,

      type: "default",

      animated:
        edge.relationship ===
        "TARGETS",

      label:
        edge.relationship || "",

      style: {
        stroke,
        strokeWidth: 2,
      },
    }
  }


  // ==========================================================
  // Build graph from Neo4j response
  // ==========================================================

  const buildGraphFromNeo4j = (
    result: AttackReplayResponse
  ) => {
    if (
      !result.nodes ||
      result.nodes.length === 0
    ) {
      setNodes([])

      setEdges([])

      setHasTraced(false)

      setError(
        "No Neo4j graph data found for this alert. The alert may not have been synchronized to Neo4j yet."
      )

      return
    }


    const flowNodes =
      result.nodes.map(
        (node, index) =>
          convertNode(
            node,
            index
          )
      )


    const flowEdges =
      (result.edges || []).map(
        (edge) =>
          convertEdge(edge)
      )


    setNodes(flowNodes)

    setEdges(flowEdges)

    setError(null)

    setHasTraced(true)
  }


  // ==========================================================
  // Fetch real Attack Replay
  // ==========================================================

  const fetchAttackReplay =
    async () => {
      const id =
        alertId.trim()


      if (!id) {
        setError(
          "Please provide an alert ID."
        )

        return
      }


      setLoading(true)

      setError(null)

      setHasTraced(false)


      try {
        const result =
          await api.get<AttackReplayResponse>(
            `/alerts/${encodeURIComponent(
              id
            )}/attack-replay`
          )


        buildGraphFromNeo4j(
          result
        )

      } catch (err) {
        console.error(
          "Failed to fetch attack replay:",
          err
        )


        setNodes([])

        setEdges([])

        setHasTraced(false)


        setError(
          err instanceof Error
            ? err.message
            : "Failed to load attack replay."
        )

      } finally {
        setLoading(false)
      }
    }


  // ==========================================================
  // Demo graph
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
          borderColor:
            "#ef4444",

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
          borderColor:
            "#3b82f6",

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
          borderColor:
            "#ef4444",

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
          borderColor:
            "#3b82f6",

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
          borderColor:
            "#f59e0b",

          borderWidth: 2,
        },
      },


      {
        id: "technique-1",

        data: {
          label:
            "MITRE: T1110",
        },

        position: {
          x: 900,
          y: 100,
        },

        style: {
          borderColor:
            "#8b5cf6",

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
          borderColor:
            "#8b5cf6",

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
          stroke:
            "#ef4444",
        },
      },


      {
        id: "e2",

        source: "alert-1",

        target: "technique-1",

        style: {
          stroke:
            "#8b5cf6",
        },
      },


      {
        id: "e3",

        source: "alert-2",

        target: "asset-2",

        animated: true,

        style: {
          stroke:
            "#ef4444",
        },
      },


      {
        id: "e4",

        source: "asset-1",

        target: "asset-2",

        style: {
          stroke:
            "#3b82f6",

          strokeDasharray:
            "5 5",
        },
      },


      {
        id: "e5",

        source: "alert-2",

        target: "incident-1",

        style: {
          stroke:
            "#f59e0b",
        },
      },


      {
        id: "e6",

        source: "alert-2",

        target: "technique-2",

        style: {
          stroke:
            "#8b5cf6",
        },
      },
    ]


    setNodes(
      demoNodes
    )

    setEdges(
      demoEdges
    )

    setError(null)

    setHasTraced(false)
  }


  // ==========================================================
  // UI
  // ==========================================================

  return (
    <div className="min-h-screen bg-background">

      <NavHeader
        title="Attack Replay"
      />


      <main className="p-6">

        {/* ================================================= */}
        {/* Search / Controls */}
        {/* ================================================= */}

        <div className="flex gap-4 mb-4">

          <input
            type="text"
            placeholder="Enter full alert UUID..."
            value={alertId}
            onChange={(e) =>
              setAlertId(
                e.target.value
              )
            }
            className="flex-1 px-4 py-2 rounded-md border border-border bg-background font-mono text-sm"
          />


          <button
            onClick={
              fetchAttackReplay
            }
            disabled={
              loading ||
              !alertId.trim()
            }
            className="px-6 py-2 rounded-md bg-primary text-primary-foreground font-medium hover:bg-primary/90 disabled:opacity-50"
          >
            {loading
              ? "Tracing..."
              : "Trace"}
          </button>


          <button
            onClick={
              buildDemoGraph
            }
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
              Attack Replay
            </p>

            <p className="text-sm text-red-300 mt-1">
              {error}
            </p>

          </div>
        )}


        {/* ================================================= */}
        {/* Success */}
        {/* ================================================= */}

        {hasTraced &&
          !error && (
            <div className="mb-4 rounded-lg border border-border bg-card p-4">

              <p className="text-sm">
                Neo4j attack graph loaded
              </p>

              <p className="font-mono text-xs text-muted-foreground mt-1">
                {alertId}
              </p>

            </div>
          )}


        {/* ================================================= */}
        {/* React Flow */}
        {/* ================================================= */}

        <div className="h-[600px] rounded-lg border border-border overflow-hidden">

          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={
              onNodesChange
            }
            onEdgesChange={
              onEdgesChange
            }
            onConnect={
              onConnect
            }
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
            visualizes the real Neo4j
            knowledge graph associated
            with an alert.
          </p>


          <p className="mt-1">
            Red = Alert · Blue = Asset ·
            Amber = Incident · Purple =
            MITRE ATT&amp;CK · Cyan =
            Network connection.
          </p>


          <p className="mt-1">
            Relationships are taken
            directly from Neo4j.
          </p>


          <p className="mt-2 text-xs">
            Demo uses sample data.
            Trace uses the authenticated
            backend.
          </p>

        </div>

      </main>

    </div>
  )
}
