import React, { useEffect, useState } from 'react';
import { ShieldCheck, Play, CheckCircle, Clock, AlertOctagon, RefreshCw } from 'lucide-react';
import { apiClient } from '../api/client';

interface Playbook {
  id: string;
  playbook_id: string;
  name: string;
  enabled: boolean;
  severity_threshold: string;
  risk_score_threshold: number;
  approval_required: bool;
  action_sequence: string[];
}

interface ResponseExecution {
  id: string;
  execution_id: string;
  playbook_id: string;
  status: string;
  mode: string;
  started_at: string;
  verification_status: string;
}

export const PlaybookResponsePanel: React.FC = () => {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [executions, setExecutions] = useState<ResponseExecution[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [pbRes, execRes] = await Promise.all([
        apiClient.get('/playbooks'),
        apiClient.get('/responses'),
      ]);
      setPlaybooks(pbRes.data);
      setExecutions(execRes.data);
    } catch (err) {
      console.error('Failed to load response engine data', err);
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (execId: string) => {
    try {
      await apiClient.post(`/responses/${execId}/approve`, { reason: 'Approved by SOC Analyst' });
      fetchData();
    } catch (err) {
      console.error('Failed to approve execution', err);
    }
  };

  const handleReject = async (execId: string) => {
    try {
      await apiClient.post(`/responses/${execId}/reject`, { reason: 'Rejected by SOC Analyst' });
      fetchData();
    } catch (err) {
      console.error('Failed to reject execution', err);
    }
  };

  if (loading) {
    return <div className="text-sm text-slate-400">Loading Response Engine...</div>;
  }

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-slate-100 flex items-center space-x-2">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <span>Automated Playbooks & Defensive Response Engine</span>
        </h2>
        <button
          onClick={fetchData}
          className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Grid: Active Playbooks & Recent Executions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Playbook List */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold uppercase text-slate-400 tracking-wider">Active Playbooks</h3>
          <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
            {playbooks.map((pb) => (
              <div key={pb.id} className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold text-slate-200">{pb.name}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      pb.enabled ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {pb.enabled ? 'ACTIVE' : 'DISABLED'}
                  </span>
                </div>
                <div className="mt-2 flex items-center justify-between text-xs text-slate-400">
                  <span>Threshold: Risk &ge; {pb.risk_score_threshold}</span>
                  <span className="font-mono">{pb.action_sequence.length} Actions</span>
                </div>
              </div>
            ))}
            {playbooks.length === 0 && (
              <div className="text-xs text-slate-500 py-4 text-center">No active response playbooks configured.</div>
            )}
          </div>
        </div>

        {/* Execution Log & Approvals */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold uppercase text-slate-400 tracking-wider">Response Executions & Approvals</h3>
          <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
            {executions.map((ex) => (
              <div key={ex.id} className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-medium text-indigo-300">{ex.execution_id}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      ex.status === 'pending_approval'
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        : ex.status === 'simulated'
                        ? 'bg-cyan-500/20 text-cyan-400'
                        : 'bg-emerald-500/20 text-emerald-400'
                    }`}
                  >
                    {ex.status}
                  </span>
                </div>

                {ex.status === 'pending_approval' && (
                  <div className="mt-2.5 flex items-center space-x-2">
                    <button
                      onClick={() => handleApprove(ex.id)}
                      className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold transition"
                    >
                      Approve Action
                    </button>
                    <button
                      onClick={() => handleReject(ex.id)}
                      className="px-2.5 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs font-semibold transition"
                    >
                      Reject
                    </button>
                  </div>
                )}
              </div>
            ))}
            {executions.length === 0 && (
              <div className="text-xs text-slate-500 py-4 text-center">No recent response executions.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
