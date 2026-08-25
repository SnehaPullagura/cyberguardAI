import React, { useState, useEffect } from 'react';
import {
  InvestigationCase,
  CaseEvidence,
  CaseTimelineEvent,
  CaseNote,
  EntityGraphData,
} from '../types';
import {
  fetchCases,
  fetchCase,
  fetchCaseEvidence,
  fetchCaseTimeline,
  fetchCaseNotes,
  fetchCaseGraph,
  createCase,
} from '../api/investigations';
import { InvestigationWorkspace } from '../components/InvestigationWorkspace';
import { InvestigationTimeline } from '../components/InvestigationTimeline';
import { EntityGraphView } from '../components/EntityGraphView';

export const InvestigationPage: React.FC = () => {
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [activeCase, setActiveCase] = useState<InvestigationCase | null>(null);
  const [evidenceList, setEvidenceList] = useState<CaseEvidence[]>([]);
  const [timeline, setTimeline] = useState<CaseTimelineEvent[]>([]);
  const [notesList, setNotesList] = useState<CaseNote[]>([]);
  const [graphData, setGraphData] = useState<EntityGraphData | null>(null);
  const [activeTab, setActiveTab] = useState<'workspace' | 'timeline' | 'graph'>('workspace');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newPriority, setNewPriority] = useState('P2');
  const [newSeverity, setNewSeverity] = useState('high');

  const loadCases = async () => {
    try {
      const data = await fetchCases();
      setCases(data);
      if (data.length > 0 && !selectedCaseId) {
        setSelectedCaseId(data[0].id);
      }
    } catch (err) {
      console.error('Failed to fetch cases:', err);
    }
  };

  const loadActiveCaseData = async (caseId: string) => {
    try {
      const [c, ev, tl, nt, gr] = await Promise.all([
        fetchCase(caseId),
        fetchCaseEvidence(caseId),
        fetchCaseTimeline(caseId),
        fetchCaseNotes(caseId),
        fetchCaseGraph(caseId),
      ]);
      setActiveCase(c);
      setEvidenceList(ev);
      setTimeline(tl);
      setNotesList(nt);
      setGraphData(gr);
    } catch (err) {
      console.error('Failed to load active case details:', err);
    }
  };

  useEffect(() => {
    loadCases();
  }, []);

  useEffect(() => {
    if (selectedCaseId) {
      loadActiveCaseData(selectedCaseId);
    }
  }, [selectedCaseId]);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    try {
      const created = await createCase({
        title: newTitle,
        priority: newPriority,
        severity: newSeverity,
      });
      setShowCreateModal(false);
      setNewTitle('');
      await loadCases();
      setSelectedCaseId(created.id);
    } catch (err) {
      console.error(err);
    }
  };

  const getPriorityBadge = (p: string) => {
    switch (p) {
      case 'P1':
        return 'bg-red-950 text-red-400 border-red-800';
      case 'P2':
        return 'bg-amber-950 text-amber-400 border-amber-800';
      case 'P3':
        return 'bg-blue-950 text-blue-400 border-blue-800';
      default:
        return 'bg-gray-800 text-gray-400 border-gray-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            SOC Investigation Workspace
          </h1>
          <p className="text-sm text-gray-400">
            Case lifecycle management, multi-hop entity graphs, and chronological investigation timelines.
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded-md text-sm transition-colors"
        >
          + New Investigation Case
        </button>
      </div>

      {/* Main Layout */}
      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
        {/* Left Side: Case Queue */}
        <div className="xl:col-span-1 bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-gray-800">
            <h3 className="font-bold text-white text-sm">Active Cases ({cases.length})</h3>
            <span className="text-xs text-gray-500 font-mono">Queue</span>
          </div>

          <div className="space-y-2 max-h-[700px] overflow-y-auto pr-1">
            {cases.length === 0 ? (
              <div className="text-gray-500 text-xs py-8 text-center">
                No active investigation cases.
              </div>
            ) : (
              cases.map((c) => (
                <div
                  key={c.id}
                  onClick={() => setSelectedCaseId(c.id)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all ${
                    selectedCaseId === c.id
                      ? 'bg-cyan-950/40 border-cyan-500/80 shadow-sm'
                      : 'bg-gray-950 border-gray-800/80 hover:border-gray-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[11px] font-mono text-cyan-400 font-bold">
                      {c.case_id}
                    </span>
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold border ${getPriorityBadge(
                        c.priority
                      )}`}
                    >
                      {c.priority}
                    </span>
                  </div>
                  <h4 className="text-xs font-semibold text-white truncate mb-1">{c.title}</h4>
                  <div className="flex items-center justify-between text-[10px] text-gray-500 font-mono">
                    <span className="uppercase">{c.status}</span>
                    <span>{new Date(c.created_at).toLocaleDateString()}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Side: Active Workspace */}
        <div className="xl:col-span-3 space-y-4">
          {activeCase ? (
            <>
              {/* Navigation Tabs */}
              <div className="flex items-center gap-2 border-b border-gray-800 pb-2">
                <button
                  onClick={() => setActiveTab('workspace')}
                  className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                    activeTab === 'workspace'
                      ? 'bg-cyan-600 text-white'
                      : 'text-gray-400 hover:text-white bg-gray-900'
                  }`}
                >
                  Case Overview & Evidence
                </button>
                <button
                  onClick={() => setActiveTab('timeline')}
                  className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                    activeTab === 'timeline'
                      ? 'bg-cyan-600 text-white'
                      : 'text-gray-400 hover:text-white bg-gray-900'
                  }`}
                >
                  Timeline ({timeline.length})
                </button>
                <button
                  onClick={() => setActiveTab('graph')}
                  className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                    activeTab === 'graph'
                      ? 'bg-cyan-600 text-white'
                      : 'text-gray-400 hover:text-white bg-gray-900'
                  }`}
                >
                  Entity Graph
                </button>
              </div>

              {/* Tab Contents */}
              {activeTab === 'workspace' && (
                <InvestigationWorkspace
                  activeCase={activeCase}
                  evidenceList={evidenceList}
                  notesList={notesList}
                  onRefresh={() => loadActiveCaseData(activeCase.id)}
                />
              )}

              {activeTab === 'timeline' && <InvestigationTimeline timeline={timeline} />}

              {activeTab === 'graph' && <EntityGraphView graphData={graphData} />}
            </>
          ) : (
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-12 text-center text-gray-500">
              Select or create an investigation case from the left panel.
            </div>
          )}
        </div>
      </div>

      {/* Create Case Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 max-w-md w-full space-y-4">
            <h3 className="text-lg font-bold text-white">Create Investigation Case</h3>
            <form onSubmit={handleCreateCase} className="space-y-3">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Case Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Cobalt Strike Beaconing Investigation"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-700 text-xs text-white rounded p-2 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-gray-400 block mb-1">Priority</label>
                  <select
                    value={newPriority}
                    onChange={(e) => setNewPriority(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-700 text-xs text-white rounded p-2"
                  >
                    <option value="P1">P1 - Critical</option>
                    <option value="P2">P2 - High</option>
                    <option value="P3">P3 - Medium</option>
                    <option value="P4">P4 - Low</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs text-gray-400 block mb-1">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-700 text-xs text-white rounded p-2"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-gray-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3 py-1.5 rounded text-xs text-gray-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded"
                >
                  Create Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
