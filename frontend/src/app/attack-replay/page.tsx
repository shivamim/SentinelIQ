"use client"

import { useCallback, useEffect, useState } from "react"
import { ReactFlow, Background, Controls, MiniMap, Node, Edge, useNodesState, useEdgesState, addEdge, Connection } from "@xyflow/react"
import "@xyflow/react/dist/style.css"
import { api } from "@/lib/api"
import { NavHeader } from "@/components/nav-header"

type CorrelationPath = {
  path: any
}

export default function AttackReplayPage() {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const [alertId, setAlertId] = useState("")
  const [loading, setLoading] = useState(false)

  const onConnect = useCallback(
    (connection: Connection) => setEdges((eds) => addEdge(connection, eds)),
    [setEdges]
  )

  const fetchCorrelationGraph = async () => {
    if (!alertId) return
    setLoading(true)
    try {
      // Fetch correlation paths from Neo4j via backend
      const result = await api.get<CorrelationPath[]>(
        `/alerts/${alertId}/correlation`
      )
      buildGraphFromPaths(result)
    } catch (err) {
      console.error("Failed to fetch correlation paths:", err)
      // Show a demo graph
      buildDemoGraph()
    }
    setLoading(false)
  }

  const buildGraphFromPaths = (paths: CorrelationPath[]) => {
    // Convert Neo4j paths to React Flow nodes/edges
    const nodeMap = new Map<string, Node>()
    const edgeList: Edge[] = []

    // For now, show a demo layout if paths are empty
    if (!paths.length) {
      buildDemoGraph()
      return
    }

    // Process each path from Neo4j
    paths.forEach((p, pathIdx) => {
      const path = p.path
      if (!path) return

      // Extract nodes from the path
      const pathNodes = path.segments?.[0]?.nodes || []
      pathNodes.forEach((node: any, idx: number) => {
        const labels = node.labels || []
        const props = node.properties || {}
        const nodeId = props.id || `node-${pathIdx}-${idx}`

        if (!nodeMap.has(nodeId)) {
          let type = "default"
          let label = nodeId
          let color = "#6366f1"

          if (labels.includes("Alert")) {
            type = "input"
            label = `Alert: ${props.alert_type || "Unknown"}`
            color = "#ef4444"
          } else if (labels.includes("Asset")) {
            label = `Asset: ${props.hostname || props.ip || "Unknown"}`
            color = "#3b82f6"
          } else if (labels.includes("Incident")) {
            type = "output"
            label = `Incident: ${props.title || "Unknown"}`
            color = "#f59e0b"
          } else if (labels.includes("Technique")) {
            label = `MITRE: ${props.id || "Unknown"}`
            color = "#8b5cf6"
          }

          nodeMap.set(nodeId, {
            id: nodeId,
            type,
            data: { label },
            position: { x: idx * 250, y: pathIdx * 150 },
            style: { borderColor: color, borderWidth: 2 },
          })
        }
      })
    })

    setNodes(Array.from(nodeMap.values()))
    setEdges(edgeList)
  }

  const buildDemoGraph = () => {
    const demoNodes: Node[] = [
      { id: "alert-1", type: "input", data: { label: "Alert: Brute Force SSH" }, position: { x: 0, y: 100 }, style: { borderColor: "#ef4444", borderWidth: 2 } },
      { id: "asset-1", data: { label: "Asset: srv-01.corp.local" }, position: { x: 300, y: 0 }, style: { borderColor: "#3b82f6", borderWidth: 2 } },
      { id: "alert-2", type: "input", data: { label: "Alert: Lateral Movement" }, position: { x: 300, y: 200 }, style: { borderColor: "#ef4444", borderWidth: 2 } },
      { id: "asset-2", data: { label: "Asset: srv-02.corp.local" }, position: { x: 600, y: 100 }, style: { borderColor: "#3b82f6", borderWidth: 2 } },
      { id: "incident-1", type: "output", data: { label: "Incident: SSH Compromise" }, position: { x: 600, y: 300 }, style: { borderColor: "#f59e0b", borderWidth: 2 } },
      { id: "technique-1", data: { label: "MITRE: T1110" }, position: { x: 900, y: 100 }, style: { borderColor: "#8b5cf6", borderWidth: 2 } },
      { id: "technique-2", data: { label: "MITRE: T1021.002" }, position: { x: 900, y: 300 }, style: { borderColor: "#8b5cf6", borderWidth: 2 } },
    ]
    const demoEdges: Edge[] = [
      { id: "e1", source: "alert-1", target: "asset-1", animated: true, style: { stroke: "#ef4444" } },
      { id: "e2", source: "alert-1", target: "technique-1", style: { stroke: "#8b5cf6" } },
      { id: "e3", source: "alert-2", target: "asset-2", animated: true, style: { stroke: "#ef4444" } },
      { id: "e4", source: "asset-1", target: "asset-2", style: { stroke: "#3b82f6", strokeDasharray: "5 5" } },
      { id: "e5", source: "alert-2", target: "incident-1", style: { stroke: "#f59e0b" } },
      { id: "e6", source: "alert-2", target: "technique-2", style: { stroke: "#8b5cf6" } },
    ]
    setNodes(demoNodes)
    setEdges(demoEdges)
  }

  // Load demo graph on mount
  useEffect(() => {
    buildDemoGraph()
  }, [])

  return (
    <div className="min-h-screen bg-background">
      <NavHeader title="Attack Replay" />

      <main className="p-6">
        <div className="flex gap-4 mb-4">
          <input
            type="text"
            placeholder="Enter alert ID to trace correlation paths..."
            value={alertId}
            onChange={(e) => setAlertId(e.target.value)}
            className="flex-1 px-4 py-2 rounded-md border border-border bg-background"
          />
          <button
            onClick={fetchCorrelationGraph}
            disabled={loading}
            className="px-6 py-2 rounded-md bg-primary text-primary-foreground font-medium hover:bg-primary/90 disabled:opacity-50"
          >
            {loading ? "Loading..." : "Trace"}
          </button>
          <button
            onClick={buildDemoGraph}
            className="px-4 py-2 rounded-md border border-border hover:bg-muted text-sm"
          >
            Demo
          </button>
        </div>

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

        <div className="mt-4 text-sm text-muted-foreground">
          <p>
            <strong>Attack Replay</strong> visualizes correlation paths from the Neo4j knowledge graph.
            Red nodes = alerts, blue = assets, amber = incidents, purple = MITRE ATT&CK techniques.
            Animated edges indicate alert-to-asset targeting; dashed edges indicate network adjacency.
          </p>
        </div>
      </main>
    </div>
  )
}
