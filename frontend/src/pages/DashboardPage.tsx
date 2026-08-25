import React, { useEffect, useState } from 'react';
import { ShieldAlert, Activity, AlertTriangle, Zap, Download, Radio } from 'lucide-react';
import { apiClient } from '../api/client';
import { DashboardSummary } from '../types';
import { useWebSocket } from '../hooks/useWebSocket';

import { PlaybookResponsePanel } from '../components/PlaybookResponsePanel';

export const DashboardPage: React.FC = () => {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const { status, liveEvents, liveAlerts, liveMetrics } = useWebSocket();

  useEffect(() => {
    fetchSummary();
  }, []);

  const fetchSummary = async () => {
    try {
      const res = await apiClient.get('/dashboard/summary');
      setSummary(res.data);
    } catch (err) {
      console.error('Failed to load dashboard metrics', err);
    } finally {
      setLoading(false);
    }
  };

  const handleExportPDF = () => {
    window.open('/api/v1/reports/export/pdf', '_blank');
  };

  if (loading) {
    return <div className="p-8 text-slate-400">Loading CyberGuard AI Metrics...</div>;
  }

  const totalEvents = (summary?.total_events_processed || 0) + liveMetrics.eventsCount;
  const totalOpenAlerts = (summary?.open_alerts || 0) + liveMetrics.alertsCount;

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center space-x-3">
            <h1 className="text-2xl font-bold text-slate-100">SOC Security Dashboard</h1>
            <span
              className={`inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-semibold border ${
                status === 'CONNECTED'
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : status === 'CONNECTING' || status === 'RECONNECTING'
                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                  : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
              }`}
            >
              <Radio className="w-3.5 h-3.5 animate-pulse" />
              <span>{status}</span>
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">Real-time WebSocket event streaming and AI threat detection</p>
        </div>

        <button
          onClick={handleExportPDF}
          className="flex items-center space-x-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium transition"
        >
          <Download className="w-4 h-4" />
          <span>Export Executive PDF</span>
        </button>
      </div>

      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-400">Events Processed</span>
            <Activity className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="mt-3 text-3xl font-extrabold text-slate-100">
            {totalEvents.toLocaleString()}
          </div>
          <div className="mt-1 text-xs text-emerald-400 font-medium">
            Live WebSocket Stream Active
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-400">Active Incidents</span>
            <AlertTriangle className="w-5 h-5 text-amber-400" />
          </div>
          <div className="mt-3 text-3xl font-extrabold text-slate-100">
            {summary?.total_active_incidents}
          </div>
          <div className="mt-1 text-xs text-amber-400 font-medium">
            Requires Analyst Triage
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-400">Critical Incidents</span>
            <ShieldAlert className="w-5 h-5 text-rose-500" />
          </div>
          <div className="mt-3 text-3xl font-extrabold text-rose-400">
            {summary?.critical_incidents}
          </div>
          <div className="mt-1 text-xs text-rose-400 font-medium">
            Immediate Response Required
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-400">Open Alerts</span>
            <Zap className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="mt-3 text-3xl font-extrabold text-slate-100">
            {totalOpenAlerts}
          </div>
          <div className="mt-1 text-xs text-cyan-400 font-medium">
            Rule & AI Detections
          </div>
        </div>
      </div>

      {/* Grid: Live Events Stream & Real-Time Alert Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Live Security Log Stream */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-slate-100 flex items-center space-x-2">
              <Activity className="w-5 h-5 text-indigo-400" />
              <span>Live Security Event Stream</span>
            </h2>
            <span className="text-xs text-slate-400 font-mono">
              {liveEvents.length} Buffered Events
            </span>
          </div>

          <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-950/80 font-mono text-xs max-h-96 overflow-y-auto">
            {liveEvents.length > 0 ? (
              <table className="w-full text-left text-slate-300">
                <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] border-b border-slate-800 sticky top-0">
                  <tr>
                    <th className="py-2.5 px-3">Time</th>
                    <th className="py-2.5 px-3">Collector</th>
                    <th className="py-2.5 px-3">Action</th>
                    <th className="py-2.5 px-3">Source IP</th>
                    <th className="py-2.5 px-3">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {liveEvents.map((ev, idx) => (
                    <tr key={idx} className="hover:bg-slate-900/50 transition">
                      <td className="py-2 px-3 text-slate-400">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-2 px-3 text-indigo-300 font-semibold">{ev.source_type}</td>
                      <td className="py-2 px-3 text-slate-200">{ev.action}</td>
                      <td className="py-2 px-3 text-slate-400">{ev.source_ip || '-'}</td>
                      <td className="py-2 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            ev.severity === 'critical'
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                              : ev.severity === 'high'
                              ? 'bg-amber-500/20 text-amber-400'
                              : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {ev.severity}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="py-12 text-center text-slate-500 font-sans text-sm">
                Waiting for incoming real-time security events...
              </div>
            )}
          </div>
        </div>

        {/* Live Alerts Notifications */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-slate-100 flex items-center space-x-2">
              <Zap className="w-5 h-5 text-cyan-400" />
              <span>Real-Time Alert Feed</span>
            </h2>
          </div>

          <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
            {liveAlerts.length > 0 ? (
              liveAlerts.map((alert, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg hover:border-slate-700 transition"
                >
                  <div className="flex items-start justify-between">
                    <span className="text-xs font-semibold text-slate-200">{alert.title}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        alert.severity === 'critical'
                          ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                          : 'bg-amber-500/20 text-amber-400'
                      }`}
                    >
                      {alert.severity}
                    </span>
                  </div>
                  <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
                    <span>Source: {alert.source_entity || 'System'}</span>
                    <span className="font-mono text-cyan-400">Risk: {alert.risk_score}</span>
                  </div>
                </div>
              ))
            ) : (
              <div className="py-12 text-center text-slate-500 font-sans text-sm">
                No new real-time alerts.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Phase 6 Automated Playbook & Response Engine Panel */}
      <PlaybookResponsePanel />
    </div>
  );
};

