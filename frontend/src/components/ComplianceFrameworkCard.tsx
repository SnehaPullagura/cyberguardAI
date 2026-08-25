import React, { useState } from 'react';
import { ComplianceEvaluationData } from '../api/reports';

interface ComplianceFrameworkCardProps {
  evaluation: ComplianceEvaluationData;
  onReevaluate: () => void;
  isLoading?: boolean;
}

export const ComplianceFrameworkCard: React.FC<ComplianceFrameworkCardProps> = ({
  evaluation,
  onReevaluate,
  isLoading = false,
}) => {
  const [expanded, setExpanded] = useState(false);

  const getScoreColor = (score: number) => {
    if (score >= 85) return 'text-emerald-400 border-emerald-500';
    if (score >= 60) return 'text-amber-400 border-amber-500';
    return 'text-red-400 border-red-500';
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'compliant':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-700';
      case 'needs_attention':
        return 'bg-amber-950/80 text-amber-300 border-amber-700';
      default:
        return 'bg-red-950/80 text-red-300 border-red-700';
    }
  };

  const getControlBadge = (status: string) => {
    switch (status) {
      case 'PASS':
        return 'bg-emerald-900/60 text-emerald-300 border-emerald-700';
      case 'WARNING':
        return 'bg-amber-900/60 text-amber-300 border-amber-700';
      default:
        return 'bg-red-900/60 text-red-300 border-red-700';
    }
  };

  return (
    <div className="bg-gray-900 rounded-lg p-5 border border-gray-800 space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2.5">
            <h3 className="text-lg font-bold text-white">
              {evaluation.summary_json.framework_name}
            </h3>
            <span
              className={`text-xs px-2 py-0.5 rounded border uppercase font-mono font-semibold ${getStatusBadge(
                evaluation.status
              )}`}
            >
              {evaluation.status.replace('_', ' ')}
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            {evaluation.summary_json.framework_description}
          </p>
        </div>

        <div className="flex items-center gap-4">
          {/* Circular Score Gauge */}
          <div
            className={`w-14 h-14 rounded-full border-2 flex flex-col items-center justify-center bg-gray-950 font-bold ${getScoreColor(
              evaluation.overall_score
            )}`}
          >
            <span className="text-base leading-none">{evaluation.overall_score}%</span>
            <span className="text-[9px] uppercase font-normal opacity-70">Score</span>
          </div>

          <button
            onClick={onReevaluate}
            disabled={isLoading}
            className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs rounded border border-gray-700 font-semibold transition-colors"
          >
            {isLoading ? 'Auditing...' : 'Audit Telemetry'}
          </button>
        </div>
      </div>

      {/* Control Summary Breakdown */}
      <div className="grid grid-cols-4 gap-2 pt-2 border-t border-gray-800 text-center text-xs">
        <div className="bg-gray-950 p-2 rounded border border-gray-800">
          <span className="text-gray-400 block text-[10px] uppercase">Total Controls</span>
          <span className="font-bold text-white font-mono">{evaluation.total_controls}</span>
        </div>
        <div className="bg-gray-950 p-2 rounded border border-gray-800">
          <span className="text-emerald-400 block text-[10px] uppercase">Passed</span>
          <span className="font-bold text-emerald-400 font-mono">{evaluation.passed_controls}</span>
        </div>
        <div className="bg-gray-950 p-2 rounded border border-gray-800">
          <span className="text-amber-400 block text-[10px] uppercase">Warning</span>
          <span className="font-bold text-amber-400 font-mono">{evaluation.warning_controls}</span>
        </div>
        <div className="bg-gray-950 p-2 rounded border border-gray-800">
          <span className="text-red-400 block text-[10px] uppercase">Failed</span>
          <span className="font-bold text-red-400 font-mono">{evaluation.failed_controls}</span>
        </div>
      </div>

      {/* Toggle Control Matrix */}
      <div>
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1"
        >
          {expanded ? '▲ Hide Control Matrix' : '▼ View Control Matrix & Evidence'}
        </button>

        {expanded && (
          <div className="mt-3 space-y-2 max-h-72 overflow-y-auto pr-1">
            {evaluation.summary_json.controls.map((control) => (
              <div
                key={control.id}
                className="p-3 bg-gray-950 rounded border border-gray-800/80 text-xs space-y-1"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-cyan-400 font-bold">{control.id}</span>
                    <span className="font-semibold text-white">{control.name}</span>
                  </div>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded border uppercase font-mono font-bold ${getControlBadge(
                      control.status
                    )}`}
                  >
                    {control.status}
                  </span>
                </div>
                <p className="text-gray-400 text-[11px]">{control.description}</p>
                <div className="text-[11px] text-gray-500 font-mono bg-black/40 p-1.5 rounded">
                  <span className="text-gray-400">Live Telemetry Evidence: </span>
                  <span>{control.evidence}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
