import React from 'react';
import { EntityGraphData } from '../types';

interface EntityGraphViewProps {
  graphData: EntityGraphData | null;
}

export const EntityGraphView: React.FC<EntityGraphViewProps> = ({ graphData }) => {
  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="bg-gray-900 rounded-lg p-6 border border-gray-800 text-center text-gray-500 text-sm">
        No entity relationships mapped for this case yet.
      </div>
    );
  }

  const getNodeColor = (type: string) => {
    switch (type) {
      case 'case':
        return 'bg-cyan-500/20 text-cyan-300 border-cyan-500';
      case 'incident':
        return 'bg-red-500/20 text-red-300 border-red-500';
      case 'alert':
        return 'bg-amber-500/20 text-amber-300 border-amber-500';
      case 'ip':
        return 'bg-blue-500/20 text-blue-300 border-blue-500';
      case 'user':
        return 'bg-purple-500/20 text-purple-300 border-purple-500';
      case 'file_hash':
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500';
      case 'evidence':
        return 'bg-indigo-500/20 text-indigo-300 border-indigo-500';
      default:
        return 'bg-gray-700/20 text-gray-300 border-gray-600';
    }
  };

  return (
    <div className="bg-gray-900 rounded-lg p-5 border border-gray-800">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-bold text-white flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>
          Entity Graph ({graphData.nodes_count} Nodes, {graphData.edges_count} Edges)
        </h3>
        <span className="text-xs text-gray-400 font-mono">Case: {graphData.case_id}</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Nodes Grid */}
        <div className="bg-gray-950/80 p-3 rounded border border-gray-800">
          <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
            Discovered Entities (Nodes)
          </h4>
          <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
            {graphData.nodes.map((node) => (
              <div
                key={node.id}
                className={`p-2 rounded border text-xs flex items-center justify-between ${getNodeColor(
                  node.type
                )}`}
              >
                <div>
                  <span className="font-semibold">{node.label}</span>
                  <span className="ml-2 opacity-70 text-[10px] uppercase font-mono">
                    [{node.type}]
                  </span>
                </div>
                {node.properties?.severity && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-black/40 uppercase">
                    {node.properties.severity}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Relationships List */}
        <div className="bg-gray-950/80 p-3 rounded border border-gray-800">
          <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
            Multi-Hop Relationships (Edges)
          </h4>
          <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
            {graphData.edges.length === 0 ? (
              <div className="text-gray-500 text-xs py-4 text-center">
                No direct edges formed.
              </div>
            ) : (
              graphData.edges.map((edge, idx) => (
                <div
                  key={idx}
                  className="p-2 rounded bg-gray-900 border border-gray-800 text-xs text-gray-300 flex items-center gap-2 justify-between"
                >
                  <span className="font-mono text-cyan-400 truncate max-w-[120px]">
                    {edge.source.split(':')[1] || edge.source}
                  </span>
                  <span className="text-[11px] px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-mono">
                    --[{edge.relationship}]--&gt;
                  </span>
                  <span className="font-mono text-emerald-400 truncate max-w-[120px]">
                    {edge.target.split(':')[1] || edge.target}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
