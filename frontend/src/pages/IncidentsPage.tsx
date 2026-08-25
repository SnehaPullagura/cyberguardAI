import React, { useEffect, useState } from 'react';
import { CheckCircle2 } from 'lucide-react';
import { apiClient } from '../api/client';
import { Incident } from '../types';

export const IncidentsPage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchIncidents();
  }, []);

  const fetchIncidents = async () => {
    try {
      const res = await apiClient.get('/incidents');
      setIncidents(res.data);
    } catch (err) {
      console.error('Failed to load incidents', err);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateStatus = async (id: string, newStatus: string) => {
    try {
      await apiClient.patch(`/incidents/${id}`, { status: newStatus });
      fetchIncidents();
    } catch (err) {
      console.error('Failed to update status', err);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Correlated Incident Board</h1>
        <p className="text-sm text-slate-400">Automated multi-event correlation cases & triage workflow</p>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {incidents.map((inc) => (
          <div key={inc.id} className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl flex flex-col md:flex-row items-start md:items-center justify-between space-y-4 md:space-y-0">
            <div className="space-y-2">
              <div className="flex items-center space-x-3">
                <span className="font-mono text-xs text-indigo-400 font-bold px-2 py-0.5 bg-indigo-500/10 rounded border border-indigo-500/20">
                  {inc.incident_id}
                </span>
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase ${
                  inc.severity === 'critical' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-amber-500/20 text-amber-400'
                }`}>
                  {inc.severity}
                </span>
                <span className="text-xs text-slate-500">Created: {new Date(inc.created_at).toLocaleString()}</span>
              </div>
              <h3 className="text-lg font-semibold text-slate-100">{inc.title}</h3>
              <p className="text-sm text-slate-400">{inc.description || 'Automated correlation case'}</p>
            </div>

            <div className="flex items-center space-x-4">
              <div className="text-right">
                <div className="text-xs text-slate-400 font-medium">Risk Score</div>
                <div className="text-lg font-bold text-rose-400">{inc.risk_score} / 100</div>
              </div>
              <div className="flex space-x-2">
                {inc.status !== 'closed' ? (
                  <button
                    onClick={() => handleUpdateStatus(inc.id, 'closed')}
                    className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium rounded-lg transition flex items-center space-x-1"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Resolve Case</span>
                  </button>
                ) : (
                  <span className="text-xs text-emerald-400 font-semibold px-3 py-1.5 bg-emerald-500/10 rounded-lg">
                    RESOLVED
                  </span>
                )}
              </div>
            </div>
          </div>
        ))}

        {incidents.length === 0 && !loading && (
          <div className="p-12 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
            No active correlated security incidents requiring triage.
          </div>
        )}
      </div>
    </div>
  );
};
