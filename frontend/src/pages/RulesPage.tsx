import React, { useEffect, useState } from 'react';
import { Check, X } from 'lucide-react';
import { apiClient } from '../api/client';
import { DetectionRule } from '../types';

export const RulesPage: React.FC = () => {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchRules();
  }, []);

  const fetchRules = async () => {
    setLoading(true);
    try {
      const res = await apiClient.get('/rules');
      setRules(res.data);
    } catch (err) {
      console.error('Failed to load rules', err);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleRule = async (rule: DetectionRule) => {
    try {
      await apiClient.put(`/rules/${rule.id}`, { enabled: !rule.enabled });
      fetchRules();
    } catch (err) {
      console.error('Failed to toggle rule', err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Rule-Based Detection Engine</h1>
          <p className="text-sm text-slate-400">Sigma & custom YAML real-time detection rule catalog</p>
        </div>
      </div>

      {loading ? (
        <div className="text-center py-10 text-slate-500 text-sm">Loading detection rules...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {rules.map((r) => (
            <div key={r.id} className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-indigo-400 px-2 py-0.5 bg-indigo-500/10 rounded">
                  {r.rule_id}
                </span>
                <button
                  onClick={() => handleToggleRule(r)}
                  className={`px-3 py-1 rounded-full text-xs font-semibold flex items-center space-x-1 ${
                    r.enabled ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {r.enabled ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                  <span>{r.enabled ? 'Enabled' : 'Disabled'}</span>
                </button>
              </div>
              <h3 className="text-base font-bold text-slate-200">{r.title}</h3>
              <p className="text-xs text-slate-400">{r.description || 'No description provided.'}</p>
              <div className="flex items-center justify-between text-xs text-slate-500 pt-2 border-t border-slate-800/80">
                <span>Category: <strong className="text-slate-300 capitalize">{r.category}</strong></span>
                <span className="uppercase font-bold text-amber-400">{r.severity}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
