import React, { useEffect, useState } from 'react';
import { ShieldAlert, Activity, AlertTriangle, Zap, Download } from 'lucide-react';
import { apiClient } from '../api/client';
import { DashboardSummary } from '../types';

export const DashboardPage: React.FC = () => {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);

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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">SOC Security Dashboard</h1>
          <p className="text-sm text-slate-400">Real-time event stream monitoring and AI threat detection</p>
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
            {summary?.total_events_processed.toLocaleString()}
          </div>
          <div className="mt-1 text-xs text-emerald-400 font-medium">
            {summary?.events_per_second} EPS Active
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
            {summary?.open_alerts}
          </div>
          <div className="mt-1 text-xs text-slate-400">
            Rule & AI Detections
          </div>
        </div>
      </div>

      {/* High Risk Entities Section */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
        <h2 className="text-lg font-semibold text-slate-100 mb-4">Highest Risk Entity Rankings</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-800/60 text-slate-400 uppercase text-xs">
              <tr>
                <th className="py-3 px-4">Entity Identifier</th>
                <th className="py-3 px-4">Entity Type</th>
                <th className="py-3 px-4">Alert Count</th>
                <th className="py-3 px-4">Calculated Risk Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {summary?.high_risk_entities.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-800/30">
                  <td className="py-3 px-4 font-mono font-medium text-slate-200">{item.entity_name}</td>
                  <td className="py-3 px-4 text-slate-400">Host / IP</td>
                  <td className="py-3 px-4">{item.alert_count} Alerts</td>
                  <td className="py-3 px-4">
                    <span className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                      item.risk_score > 70 ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-amber-500/20 text-amber-400'
                    }`}>
                      {item.risk_score} / 100
                    </span>
                  </td>
                </tr>
              ))}
              {(!summary?.high_risk_entities || summary.high_risk_entities.length === 0) && (
                <tr>
                  <td colSpan={4} className="py-4 text-center text-slate-500">No high-risk entities detected.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
