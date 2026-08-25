import React, { useEffect, useState } from 'react';
import { Search, RefreshCw } from 'lucide-react';
import { apiClient } from '../api/client';
import { SecurityEvent } from '../types';

export const EventsPage: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => {
    fetchEvents();
  }, []);

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const res = await apiClient.get('/events', { params: { search } });
      setEvents(res.data);
    } catch (err) {
      console.error('Failed to load events', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Security Events Stream</h1>
          <p className="text-sm text-slate-400">Normalized ECS/OCSF compliance audit trail</p>
        </div>
        <button
          onClick={fetchEvents}
          className="flex items-center space-x-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-sm transition"
        >
          <RefreshCw className="w-4 h-4" />
          <span>Refresh</span>
        </button>
      </div>

      <div className="flex items-center space-x-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
        <Search className="w-5 h-5 text-slate-400 ml-2" />
        <input
          type="text"
          placeholder="Filter by raw payload, action, or IP..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && fetchEvents()}
          className="bg-transparent text-sm text-slate-200 placeholder-slate-500 focus:outline-none w-full"
        />
        <button
          onClick={fetchEvents}
          className="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium"
        >
          Search
        </button>
      </div>

      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-slate-800/80 text-slate-400 uppercase text-xs">
            <tr>
              <th className="py-3.5 px-4">Timestamp</th>
              <th className="py-3.5 px-4">Source Type</th>
              <th className="py-3.5 px-4">Category</th>
              <th className="py-3.5 px-4">Action</th>
              <th className="py-3.5 px-4">Severity</th>
              <th className="py-3.5 px-4">Source IP</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {events.map((ev) => (
              <tr key={ev.id} className="hover:bg-slate-800/40 font-mono text-xs">
                <td className="py-3 px-4 text-slate-400">{new Date(ev.timestamp).toLocaleString()}</td>
                <td className="py-3 px-4 uppercase text-indigo-400 font-semibold">{ev.source_type}</td>
                <td className="py-3 px-4">{ev.category}</td>
                <td className="py-3 px-4 text-slate-200 font-bold">{ev.action}</td>
                <td className="py-3 px-4">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase ${
                    ev.severity === 'critical' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' :
                    ev.severity === 'high' ? 'bg-amber-500/20 text-amber-400' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {ev.severity}
                  </span>
                </td>
                <td className="py-3 px-4 text-cyan-400">{ev.source_ip || '-'}</td>
              </tr>
            ))}
            {events.length === 0 && !loading && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-500">
                  No normalized security events found. Ingest logs via API to populate stream.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
