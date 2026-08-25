import React, { useState, useEffect } from 'react';
import { Playbook, ResponseExecution, ResponseApproval, RealtimeEventEnvelope } from '../types';
import { getPlaybooks } from '../api/playbooks';
import { getResponses, getPendingApprovals, approveResponse, rejectResponse } from '../api/responses';

interface PlaybookResponsePanelProps {
  realtimeEvents?: RealtimeEventEnvelope[];
}

export const PlaybookResponsePanel: React.FC<PlaybookResponsePanelProps> = ({ realtimeEvents = [] }) => {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [executions, setExecutions] = useState<ResponseExecution[]>([]);
  const [approvals, setApprovals] = useState<ResponseApproval[]>([]);
  const [loading, setLoading] = useState(false);
  const [actionReason, setActionReason] = useState<{ [key: string]: string }>({});

  const fetchData = async () => {
    try {
      setLoading(true);
      const [pbData, execData, appData] = await Promise.all([
        getPlaybooks(),
        getResponses(),
        getPendingApprovals(),
      ]);
      setPlaybooks(pbData);
      setExecutions(execData);
      setApprovals(appData);
    } catch (err) {
      console.error('Failed to fetch response engine telemetry:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Update real-time state when response websocket envelopes arrive
  useEffect(() => {
    if (!realtimeEvents || realtimeEvents.length === 0) return;
    const latest = realtimeEvents[0];
    if (
      latest.type.startsWith('playbook_') ||
      latest.type.startsWith('approval_') ||
      latest.type.startsWith('response_')
    ) {
      fetchData();
    }
  }, [realtimeEvents]);

  const handleApprove = async (executionId: string) => {
    try {
      const reason = actionReason[executionId] || 'Approved via SOC Dashboard';
      await approveResponse(executionId, reason);
      fetchData();
    } catch (err: any) {
      alert(`Approval failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  const handleReject = async (executionId: string) => {
    try {
      const reason = actionReason[executionId] || 'Rejected via SOC Dashboard';
      await rejectResponse(executionId, reason);
      fetchData();
    } catch (err: any) {
      alert(`Rejection failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  const getStatusBadge = (status: string, mode: string) => {
    if (mode === 'dry_run' || status === 'simulated') {
      return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-cyan-900/60 text-cyan-300 border border-cyan-700">SIMULATED (DRY-RUN)</span>;
    }
    switch (status) {
      case 'pending_approval':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-amber-900/60 text-amber-300 border border-amber-700 animate-pulse">PENDING APPROVAL</span>;
      case 'approved':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-900/60 text-emerald-300 border border-emerald-700">APPROVED</span>;
      case 'running':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-blue-900/60 text-blue-300 border border-blue-700">RUNNING</span>;
      case 'success':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-900/60 text-emerald-300 border border-emerald-700">SUCCESS</span>;
      case 'failed':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-rose-900/60 text-rose-300 border border-rose-700">FAILED</span>;
      case 'rejected':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-purple-900/60 text-purple-300 border border-purple-700">REJECTED</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-gray-800 text-gray-300 border border-gray-700">{status.toUpperCase()}</span>;
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg space-y-6">
      <div className="flex justify-between items-center border-b border-gray-800 pb-3">
        <div>
          <h2 className="text-lg font-bold text-gray-100 flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-indigo-500 animate-pulse"></span>
            Automated Playbook & Defensive Response Engine
          </h2>
          <p className="text-xs text-gray-400">Strictly allowlisted action execution, safe simulation adapters, and human-in-the-loop approval gates.</p>
        </div>
        <button
          onClick={fetchData}
          disabled={loading}
          className="text-xs px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 transition"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {/* Pending Approvals Section */}
      {approvals.length > 0 && (
        <div className="bg-amber-950/30 border border-amber-800/60 rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold text-amber-300 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping"></span>
            Pending Approval Requests ({approvals.length})
          </h3>
          <div className="space-y-3">
            {approvals.map((app) => (
              <div key={app.id} className="bg-gray-950/80 border border-amber-900/40 rounded p-3 text-xs flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
                <div>
                  <div className="font-mono font-bold text-amber-200">{app.approval_id} • Action: {app.action_type}</div>
                  <div className="text-gray-400 mt-0.5">Risk Level: <span className="font-semibold text-rose-400">{app.risk_level.toUpperCase()}</span> | Incident: {app.incident_id || 'N/A'}</div>
                </div>
                <div className="flex items-center gap-2 w-full md:w-auto">
                  <input
                    type="text"
                    placeholder="Approval reason..."
                    value={actionReason[app.execution_id] || ''}
                    onChange={(e) => setActionReason({ ...actionReason, [app.execution_id]: e.target.value })}
                    className="bg-gray-900 border border-gray-700 text-gray-200 px-2 py-1 rounded text-xs focus:outline-none focus:border-indigo-500 flex-1 md:w-48"
                  />
                  <button
                    onClick={() => handleApprove(app.execution_id)}
                    className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded transition"
                  >
                    Approve
                  </button>
                  <button
                    onClick={() => handleReject(app.execution_id)}
                    className="px-3 py-1 bg-rose-700 hover:bg-rose-600 text-white font-semibold rounded transition"
                  >
                    Reject
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Grid: Active Playbooks & Recent Executions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Active Playbooks */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-gray-300">Configured Playbooks ({playbooks.length})</h3>
          <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
            {playbooks.length === 0 ? (
              <div className="text-xs text-gray-500 italic p-3 bg-gray-950/40 rounded">No active playbooks found.</div>
            ) : (
              playbooks.map((pb) => (
                <div key={pb.id} className="bg-gray-950/60 border border-gray-800/80 rounded p-3 text-xs space-y-1">
                  <div className="flex justify-between items-center">
                    <span className="font-semibold text-gray-200">{pb.name}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] ${pb.enabled ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-gray-800 text-gray-400'}`}>
                      {pb.enabled ? 'ENABLED' : 'DISABLED'}
                    </span>
                  </div>
                  <div className="text-gray-400">{pb.description || 'No description provided.'}</div>
                  <div className="text-[11px] text-gray-500 flex gap-3 pt-1">
                    <span>Mode: <strong className="text-cyan-400 font-mono">{pb.response_mode}</strong></span>
                    <span>Min Severity: <strong className="text-amber-400">{pb.severity_threshold}</strong></span>
                    <span>Risk Threshold: <strong className="text-rose-400">{pb.risk_score_threshold}</strong></span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Recent Executions History */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-gray-300">Recent Response Executions ({executions.length})</h3>
          <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
            {executions.length === 0 ? (
              <div className="text-xs text-gray-500 italic p-3 bg-gray-950/40 rounded">No response executions logged yet.</div>
            ) : (
              executions.slice(0, 10).map((exec) => (
                <div key={exec.id} className="bg-gray-950/60 border border-gray-800/80 rounded p-3 text-xs space-y-1">
                  <div className="flex justify-between items-center">
                    <span className="font-mono font-bold text-gray-200">{exec.execution_id}</span>
                    {getStatusBadge(exec.status, exec.mode)}
                  </div>
                  <div className="text-gray-400 text-[11px]">
                    Triggered by: {exec.triggered_by} | Duration: {exec.duration_ms.toFixed(1)}ms
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
