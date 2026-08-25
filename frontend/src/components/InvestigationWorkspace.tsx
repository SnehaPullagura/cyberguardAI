import React, { useState } from 'react';
import { InvestigationCase, CaseEvidence, CaseNote } from '../types';
import { updateCase, attachEvidence, addCaseNote } from '../api/investigations';

interface InvestigationWorkspaceProps {
  activeCase: InvestigationCase;
  evidenceList: CaseEvidence[];
  notesList: CaseNote[];
  onRefresh: () => void;
}

export const InvestigationWorkspace: React.FC<InvestigationWorkspaceProps> = ({
  activeCase,
  evidenceList,
  notesList,
  onRefresh,
}) => {
  const [newNote, setNewNote] = useState('');
  const [evidenceTitle, setEvidenceTitle] = useState('');
  const [evidenceType, setEvidenceType] = useState('ioc');
  const [evidenceData, setEvidenceData] = useState('{"ioc_type": "ip", "value": "198.51.100.22"}');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleStatusChange = async (newStatus: any) => {
    try {
      await updateCase(activeCase.id, { status: newStatus });
      onRefresh();
    } catch (e) {
      console.error(e);
    }
  };

  const handlePriorityChange = async (newPriority: any) => {
    try {
      await updateCase(activeCase.id, { priority: newPriority });
      onRefresh();
    } catch (e) {
      console.error(e);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    setIsSubmitting(true);
    try {
      await addCaseNote(activeCase.id, newNote);
      setNewNote('');
      onRefresh();
    } catch (err) {
      console.error(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleAttachEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!evidenceTitle.trim()) return;
    setIsSubmitting(true);
    try {
      let parsedData = {};
      try {
        parsedData = JSON.parse(evidenceData);
      } catch {
        parsedData = { raw: evidenceData };
      }
      await attachEvidence(activeCase.id, {
        title: evidenceTitle,
        evidence_type: evidenceType,
        data: parsedData,
      });
      setEvidenceTitle('');
      onRefresh();
    } catch (err) {
      console.error(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Info */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono text-cyan-400 font-bold px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800">
                {activeCase.case_id}
              </span>
              <h2 className="text-xl font-bold text-white">{activeCase.title}</h2>
            </div>
            {activeCase.description && (
              <p className="text-sm text-gray-400 mt-1">{activeCase.description}</p>
            )}
          </div>

          <div className="flex items-center gap-3">
            {/* Status Selector */}
            <select
              value={activeCase.status}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="bg-gray-950 border border-gray-700 text-xs text-white rounded px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
            >
              <option value="open">OPEN</option>
              <option value="investigating">INVESTIGATING</option>
              <option value="contained">CONTAINED</option>
              <option value="closed">CLOSED</option>
              <option value="false_positive">FALSE POSITIVE</option>
            </select>

            {/* Priority Selector */}
            <select
              value={activeCase.priority}
              onChange={(e) => handlePriorityChange(e.target.value)}
              className="bg-gray-950 border border-gray-700 text-xs text-white rounded px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
            >
              <option value="P1">P1 - CRITICAL</option>
              <option value="P2">P2 - HIGH</option>
              <option value="P3">P3 - MEDIUM</option>
              <option value="P4">P4 - LOW</option>
            </select>
          </div>
        </div>

        {/* MITRE Tags */}
        {activeCase.mitre_tactics && activeCase.mitre_tactics.length > 0 && (
          <div className="flex items-center gap-2 mt-4 pt-3 border-t border-gray-800">
            <span className="text-xs text-gray-400 font-semibold">MITRE ATT&CK:</span>
            {activeCase.mitre_tactics.map((tac, i) => (
              <span
                key={i}
                className="text-[11px] px-2 py-0.5 rounded bg-red-950/50 text-red-300 border border-red-800 font-mono"
              >
                {tac}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Two Column Grid: Evidence & Notes */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Evidence Vault */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
          <h3 className="text-base font-bold text-white flex items-center justify-between">
            <span>Evidence Vault ({evidenceList.length})</span>
            <span className="text-xs text-gray-500 font-normal">Artifacts & Logs</span>
          </h3>

          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {evidenceList.length === 0 ? (
              <div className="text-gray-500 text-xs py-4 text-center">
                No evidence items attached yet.
              </div>
            ) : (
              evidenceList.map((ev) => (
                <div key={ev.id} className="p-3 bg-gray-950 rounded border border-gray-800 text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold text-white">{ev.title}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-300 uppercase font-mono">
                      {ev.evidence_type}
                    </span>
                  </div>
                  <pre className="text-[11px] text-gray-400 font-mono overflow-x-auto bg-black/40 p-1.5 rounded">
                    {JSON.stringify(ev.data, null, 2)}
                  </pre>
                </div>
              ))
            )}
          </div>

          {/* Add Evidence Form */}
          <form onSubmit={handleAttachEvidence} className="space-y-2 pt-2 border-t border-gray-800">
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Evidence title..."
                value={evidenceTitle}
                onChange={(e) => setEvidenceTitle(e.target.value)}
                className="flex-1 bg-gray-950 border border-gray-700 text-xs text-white rounded px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
              />
              <select
                value={evidenceType}
                onChange={(e) => setEvidenceType(e.target.value)}
                className="bg-gray-950 border border-gray-700 text-xs text-white rounded px-2 py-1.5"
              >
                <option value="ioc">IoC</option>
                <option value="event">Event</option>
                <option value="file_hash">File Hash</option>
                <option value="raw_log">Raw Log</option>
              </select>
            </div>
            <textarea
              placeholder='Evidence JSON payload e.g. {"ip": "10.0.0.1"}'
              value={evidenceData}
              onChange={(e) => setEvidenceData(e.target.value)}
              rows={2}
              className="w-full bg-gray-950 border border-gray-700 text-xs text-white rounded p-2 focus:outline-none focus:border-cyan-500 font-mono"
            />
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold"
            >
              Attach Evidence
            </button>
          </form>
        </div>

        {/* Analyst Notes */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
          <h3 className="text-base font-bold text-white flex items-center justify-between">
            <span>Analyst Notes ({notesList.length})</span>
            <span className="text-xs text-gray-500 font-normal">Collaborative Findings</span>
          </h3>

          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {notesList.length === 0 ? (
              <div className="text-gray-500 text-xs py-4 text-center">
                No analyst notes added yet.
              </div>
            ) : (
              notesList.map((note) => (
                <div key={note.id} className="p-3 bg-gray-950 rounded border border-gray-800 text-xs">
                  <p className="text-gray-200 mb-1">{note.content}</p>
                  <span className="text-[10px] text-gray-500 font-mono">
                    {new Date(note.created_at).toLocaleString()}
                  </span>
                </div>
              ))
            )}
          </div>

          {/* Add Note Form */}
          <form onSubmit={handleAddNote} className="space-y-2 pt-2 border-t border-gray-800">
            <textarea
              placeholder="Add investigation findings or triage notes..."
              value={newNote}
              onChange={(e) => setNewNote(e.target.value)}
              rows={3}
              className="w-full bg-gray-950 border border-gray-700 text-xs text-white rounded p-2 focus:outline-none focus:border-cyan-500"
            />
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold"
            >
              Post Note
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
