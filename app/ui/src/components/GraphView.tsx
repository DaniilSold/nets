import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { GraphSnapshot } from '../types/ui';

interface GraphViewProps {
  graph: GraphSnapshot;
}

interface PositionedNode {
  id: string;
  x: number;
  y: number;
  label: string;
  risk?: string | null;
  kind: 'Process' | 'Endpoint';
}

export function GraphView({ graph }: GraphViewProps) {
  const { t } = useTranslation();
  const width = 720;
  const height = 400;

  const nodes = useMemo<PositionedNode[]>(() => {
    if (!graph.nodes.length) return [];
    const radius = Math.min(width, height) / 2 - 60;
    return graph.nodes.map((node, index) => {
      const angle = (index / graph.nodes.length) * Math.PI * 2;
      return {
        id: node.id,
        x: width / 2 + radius * Math.cos(angle),
        y: height / 2 + radius * Math.sin(angle),
        label: node.label,
        risk: node.risk,
        kind: node.kind
      };
    });
  }, [graph.nodes]);

  const edges = graph.links.map((link) => {
    const source = nodes.find((node) => node.id === link.source);
    const target = nodes.find((node) => node.id === link.target);
    return source && target ? { ...link, source, target } : null;
  }).filter(Boolean) as Array<typeof graph.links[number] & { source: PositionedNode; target: PositionedNode }>;

  return (
    <div className="graph-view">
      <h3>{t('graph.title')}</h3>
      <p>{t('graph.subtitle')}</p>
      <svg width={width} height={height} className="graph-canvas" role="img" aria-label={t('graph.title')}>
        <defs>
          <marker id="arrow" markerWidth="10" markerHeight="10" refX="10" refY="5" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L10,5 L0,10 z" fill="rgba(58,122,254,0.6)" />
          </marker>
        </defs>
        {edges.map((edge) => (
          <g key={edge.id}>
            <line
              x1={edge.source.x}
              y1={edge.source.y}
              x2={edge.target.x}
              y2={edge.target.y}
              stroke="rgba(58,122,254,0.3)"
              strokeWidth={Math.min(8, Math.max(2, Math.log(edge.volume + 1)))}
              markerEnd="url(#arrow)"
            />
            <text
              x={(edge.source.x + edge.target.x) / 2}
              y={(edge.source.y + edge.target.y) / 2 - 8}
              fill="var(--color-muted)"
              fontSize={12}
              textAnchor="middle"
            >
              {edge.protocol}
            </text>
          </g>
        ))}
        {nodes.map((node) => (
          <g key={node.id}>
            <circle
              cx={node.x}
              cy={node.y}
              r={24}
              fill={node.kind === 'Process' ? 'rgba(58, 122, 254, 0.35)' : 'rgba(70, 201, 136, 0.35)'}
              stroke={node.risk === 'high' ? 'var(--color-danger)' : node.risk === 'medium' ? 'var(--color-warning)' : 'rgba(58,122,254,0.4)'}
              strokeWidth={3}
            />
            <text x={node.x} y={node.y + 40} fontSize={12} textAnchor="middle" fill="var(--color-text)">
              {node.label}
            </text>
          </g>
        ))}
      </svg>
      <div className="legend">
        <span>{t('graph.legend.process')}</span>
        <span>{t('graph.legend.endpoint')}</span>
      </div>
    </div>
  );
}
