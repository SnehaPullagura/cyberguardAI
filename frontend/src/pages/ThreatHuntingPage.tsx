import React, { useState, useEffect } from 'react';
import { Crosshair, Play, BookOpen, Terminal, CheckCircle2, AlertTriangle, ShieldAlert, Clock } from 'lucide-react';
import { threatHuntingApi, HuntQueryResult, ThreatHuntingPlaybook } from '../api/hunting';

export const ThreatHuntingPage: React.FC = () => {
  const [query, setQuery] = useState<string>("SecurityEvent | where Category == 'network' | summarize count() by SourceIP, Action | take 20");
  const [queryType, setQueryType] = useState<string>('kql');
  const [executing, setExecuting] = useState<boolean>(false);
  const [result, setResult] = useState<HuntQueryResult | null>(null);
  const [playbooks, setPlaybooks] = useState<ThreatHuntingPlaybook[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<ThreatHuntingPlaybook | null>(null);
  const [activeTab, setActiveTab] = useState<'console' | 'playbooks'>('console');

  useEffect(() => {
    loadPlaybooks();
  }, []);

  const loadPlaybooks = async () => {
    try {
      const data = await threatHuntingApi.listPlaybooks();
      setPlaybooks(data);
    } catch (err) {
      console.error('Failed to load hunting playbooks', err);
    }
  };

  const handleExecute = async () => {
    setExecuting(true);
    try {
      const res = await threatHuntingApi.executeQuery(query, queryType);
      setResult(res);
    } catch (err: any) {
      setResult({
        status: 'error',
        query,
        query_type: queryType,
        error_message: err?.response?.data?.detail || err.message,
      });
    } finally {
      setExecuting(false);
    }
  };

  const handleRunPlaybook = (pb: ThreatHuntingPlaybook) => {
    setSelectedPlaybook(pb);
    setQuery(pb.kql_query);
    setQueryType('kql');
    setActiveTab('console');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center space-x-3">
            <Crosshair className="w-7 h-7 text-indigo-400" />
            <span>Threat Hunting & Query Workbench</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Execute hypothesis-driven hunts using KQL (Kusto) or Splunk SPL with real-time translation & retrospective search.
          </p>
        </div>
        <div className="flex bg-slate-900 border border-slate-800 rounded-lg p-1">
          <button
            onClick={() => setActiveTab('console')}
            className={`px-4 py-1.5 rounded-md text-xs font-semibold flex items-center space-x-2 transition ${
              activeTab === 'console' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Query Console</span>
          </button>
          <button
            onClick={() => setActiveTab('playbooks')}
            className={`px-4 py-1.5 rounded-md text-xs font-semibold flex items-center space-x-2 transition ${
              activeTab === 'playbooks' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <BookOpen className="w-4 h-4" />
            <span>Hypothesis Library ({playbooks.length})</span>
          </button>
        </div>
      </div>

      {activeTab === 'console' && (
        <div className="space-y-6">
          {/* Query Editor Box */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <span className="text-xs font-semibold text-slate-400">Language:</span>
                <select
                  value={queryType}
                  onChange={(e) => setQueryType(e.target.value)}
                  className="bg-slate-800 text-slate-200 text-xs px-3 py-1.5 rounded-md border border-slate-700 focus:outline-none focus:border-indigo-500"
                >
                  <option value="kql">KQL (Kusto Query Language)</option>
                  <option value="spl">Splunk SPL (Search Processing Language)</option>
                </select>
              </div>

              <button
                onClick={handleExecute}
                disabled={executing}
                className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white px-5 py-2 rounded-lg text-xs font-bold flex items-center space-x-2 transition shadow-lg shadow-indigo-600/30"
              >
                <Play className="w-4 h-4 fill-white" />
                <span>{executing ? 'Executing Hunt...' : 'Run Hunt Query'}</span>
              </button>
            </div>

            <div className="relative">
              <textarea
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                rows={4}
                className="w-full bg-slate-950 font-mono text-sm text-slate-200 p-4 rounded-lg border border-slate-800 focus:outline-none focus:border-indigo-500/80 focus:ring-1 focus:ring-indigo-500/50"
                placeholder="Enter KQL or SPL query..."
              />
            </div>

            {selectedPlaybook && (
              <div className="p-3 bg-indigo-950/40 border border-indigo-500/30 rounded-lg flex items-center justify-between text-xs">
                <div className="flex items-center space-x-2 text-indigo-300">
                  <ShieldAlert className="w-4 h-4 text-indigo-400" />
                  <span>Loaded Hypothesis: <strong>{selectedPlaybook.title}</strong> ({selectedPlaybook.mitre_tactic})</span>
                </div>
                <button
                  onClick={() => setSelectedPlaybook(null)}
                  className="text-slate-400 hover:text-slate-200"
                >
                  Clear
                </button>
              </div>
            )}
          </div>

          {/* Results Output */}
          {result && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center space-x-4">
                  <span className="text-sm font-bold text-slate-200">Query Results</span>
                  {result.status === 'success' ? (
                    <span className="flex items-center space-x-1.5 text-xs text-emerald-400 bg-emerald-500/10 px-2.5 py-0.5 rounded-full border border-emerald-500/20">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>{result.total_matches} Matched Records</span>
                    </span>
                  ) : (
                    <span className="flex items-center space-x-1.5 text-xs text-rose-400 bg-rose-500/10 px-2.5 py-0.5 rounded-full border border-rose-500/20">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      <span>Execution Error</span>
                    </span>
                  )}
                </div>
                {result.execution_time_ms !== undefined && (
                  <span className="text-xs text-slate-400 flex items-center space-x-1">
                    <Clock className="w-3.5 h-3.5 text-slate-500" />
                    <span>{result.execution_time_ms} ms</span>
                  </span>
                )}
              </div>

              {result.sql_executed && (
                <div className="text-xs font-mono text-slate-400 bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <span className="text-indigo-400 font-bold">SQL Transpiled:</span> {result.sql_executed}
                </div>
              )}

              {result.error_message ? (
                <div className="p-4 bg-rose-950/40 border border-rose-800 text-rose-300 text-xs rounded-lg font-mono">
                  {result.error_message}
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left">
                    <thead className="bg-slate-950 text-slate-400 uppercase font-mono">
                      <tr>
                        {result.columns?.map((col) => (
                          <th key={col} className="px-4 py-2.5 border-b border-slate-800">{col}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                      {result.results?.length ? (
                        result.results.map((row, idx) => (
                          <tr key={idx} className="hover:bg-slate-800/40">
                            {result.columns?.map((col) => (
                              <td key={col} className="px-4 py-2 whitespace-nowrap">
                                {typeof row[col] === 'object' ? JSON.stringify(row[col]) : String(row[col] ?? '-')}
                              </td>
                            ))}
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={result.columns?.length || 1} className="text-center py-6 text-slate-500">
                            No security events matched the hunt criteria.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === 'playbooks' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {playbooks.map((pb) => (
            <div key={pb.hunt_id} className="bg-slate-900/70 border border-slate-800 p-5 rounded-xl space-y-3 hover:border-slate-700 transition flex flex-col justify-between">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-indigo-400 px-2 py-0.5 bg-indigo-500/10 rounded">
                    {pb.hunt_id} • {pb.mitre_technique}
                  </span>
                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold ${
                    pb.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400' : 'bg-amber-500/20 text-amber-400'
                  }`}>
                    {pb.severity}
                  </span>
                </div>
                <h3 className="text-base font-bold text-slate-200">{pb.title}</h3>
                <p className="text-xs text-slate-400 leading-relaxed">{pb.hypothesis}</p>
                <div className="bg-slate-950 p-2.5 rounded-md font-mono text-xs text-slate-300 overflow-x-auto">
                  {pb.kql_query}
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-xs text-slate-500">Tactic: <strong className="text-slate-300">{pb.mitre_tactic}</strong></span>
                <button
                  onClick={() => handleRunPlaybook(pb)}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-3 py-1.5 rounded-md flex items-center space-x-1.5 transition"
                >
                  <Play className="w-3.5 h-3.5 fill-white" />
                  <span>Load into Console</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
