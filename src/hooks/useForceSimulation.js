import { useState, useEffect, useRef } from 'react';

/**
 * Force-directed graph simulation: returns positions map { nodeId: { x, y, vx, vy } }.
 */
export function useForceSimulation(nodes, edges, width, height) {
  const [positions, setPositions] = useState({});
  const simulationRef = useRef(null);

  useEffect(() => {
    if (nodes.length === 0) return;

    const nodePositions = {};
    nodes.forEach((node, i) => {
      if (node.is_gateway) {
        nodePositions[node.id] = { x: width / 2, y: height / 2, vx: 0, vy: 0 };
      } else {
        const angle = (i / nodes.length) * 2 * Math.PI;
        const radius = Math.min(width, height) * 0.35;
        nodePositions[node.id] = {
          x: width / 2 + radius * Math.cos(angle),
          y: height / 2 + radius * Math.sin(angle),
          vx: 0,
          vy: 0,
        };
      }
    });

    const edgeMap = {};
    edges.forEach((e) => {
      if (!edgeMap[e.source]) edgeMap[e.source] = [];
      if (!edgeMap[e.target]) edgeMap[e.target] = [];
      edgeMap[e.source].push(e.target);
      edgeMap[e.target].push(e.source);
    });

    const simulate = () => {
      const alpha = 0.1;
      const repulsion = 5000;
      const attraction = 0.01;
      const damping = 0.85;

      nodes.forEach((node) => {
        const pos = nodePositions[node.id];
        let fx = 0,
          fy = 0;

        nodes.forEach((other) => {
          if (node.id === other.id) return;
          const otherPos = nodePositions[other.id];
          const dx = pos.x - otherPos.x;
          const dy = pos.y - otherPos.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = repulsion / (dist * dist);
          fx += (dx / dist) * force;
          fy += (dy / dist) * force;
        });

        const connected = edgeMap[node.id] || [];
        connected.forEach((otherId) => {
          const otherPos = nodePositions[otherId];
          if (!otherPos) return;
          const dx = otherPos.x - pos.x;
          const dy = otherPos.y - pos.y;
          fx += dx * attraction;
          fy += dy * attraction;
        });

        fx += (width / 2 - pos.x) * 0.001;
        fy += (height / 2 - pos.y) * 0.001;

        pos.vx = (pos.vx + fx * alpha) * damping;
        pos.vy = (pos.vy + fy * alpha) * damping;

        if (node.is_gateway) {
          pos.vx *= 0.1;
          pos.vy *= 0.1;
        }
      });

      nodes.forEach((node) => {
        const pos = nodePositions[node.id];
        pos.x += pos.vx;
        pos.y += pos.vy;
        pos.x = Math.max(50, Math.min(width - 50, pos.x));
        pos.y = Math.max(50, Math.min(height - 50, pos.y));
      });

      setPositions({ ...nodePositions });
    };

    simulationRef.current = setInterval(simulate, 30);
    return () => {
      if (simulationRef.current) clearInterval(simulationRef.current);
    };
  }, [nodes, edges, width, height]);

  return positions;
}
