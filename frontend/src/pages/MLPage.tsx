import React, { useEffect, useState } from 'react';
import { Play } from 'lucide-react';
import { apiClient } from '../api/client';

export const MLPage: React.FC = () => {
  const [models, setModels] = useState<any[]>([]);
  const [training, setTraining] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    fetchModels();
  }, []);

  const fetchModels = async () => {
    try {
      const res = await apiClient.get('/ml/models');
      setModels(res.data);
    } catch (err) {
      console.error('Failed to load ML models', err);
    }
  };

  const handleTrain = async (algorithm: string) => {
    setTraining(true);
    setMessage(`Training ${algorithm} model on historical event features...`);
    try {
      await apiClient.post('/ml/train', { algorithm });
      setMessage(`Model ${algorithm} trained successfully!`);
      fetchModels();
    } catch (err: any) {
      setMessage(`Training failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setTraining(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">AI & Machine Learning Anomaly Pipeline</h1>
        <p className="text-sm text-slate-400">Unsupervised Isolation Forest & PyTorch Autoencoders for zero-day threat detection</p>
      </div>

      <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl space-y-4">
        <h2 className="text-lg font-semibold text-slate-200">Model Training Control Room</h2>
        <div className="flex flex-wrap gap-4">
          <button
            onClick={() => handleTrain('isolation_forest')}
            disabled={training}
            className="flex items-center space-x-2 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium rounded-lg disabled:opacity-50 transition"
          >
            <Play className="w-4 h-4" />
            <span>Train Isolation Forest</span>
          </button>
          <button
            onClick={() => handleTrain('autoencoder')}
            disabled={training}
            className="flex items-center space-x-2 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium rounded-lg disabled:opacity-50 transition"
          >
            <Play className="w-4 h-4" />
            <span>Train PyTorch Autoencoder</span>
          </button>
        </div>
        {message && <div className="text-xs font-mono text-cyan-400 mt-2">{message}</div>}
      </div>

      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 font-semibold text-slate-200">Model Catalog</div>
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-slate-800/80 text-slate-400 uppercase text-xs">
            <tr>
              <th className="py-3 px-4">Model Name</th>
              <th className="py-3 px-4">Algorithm</th>
              <th className="py-3 px-4">Version</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Trained At</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {models.map((m) => (
              <tr key={m.id} className="hover:bg-slate-800/40">
                <td className="py-3 px-4 font-semibold text-slate-200">{m.model_name}</td>
                <td className="py-3 px-4 uppercase text-indigo-400 text-xs font-mono">{m.algorithm}</td>
                <td className="py-3 px-4 text-xs font-mono text-slate-400">{m.version}</td>
                <td className="py-3 px-4">
                  {m.is_active ? (
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                      ACTIVE INFERENCE
                    </span>
                  ) : (
                    <span className="text-xs text-slate-500">Archived</span>
                  )}
                </td>
                <td className="py-3 px-4 text-xs text-slate-400">{new Date(m.trained_at).toLocaleString()}</td>
              </tr>
            ))}
            {models.length === 0 && (
              <tr>
                <td colSpan={5} className="py-6 text-center text-slate-500">No trained ML models registered yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
