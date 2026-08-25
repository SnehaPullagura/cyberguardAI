import React, { useState, useEffect } from 'react';
import {
  ComplianceEvaluationData,
  ReportScheduleData,
  fetchComplianceEvaluation,
  evaluateCompliance,
  fetchReportSchedules,
  deleteReportSchedule,
} from '../api/reports';
import { ComplianceFrameworkCard } from '../components/ComplianceFrameworkCard';
import { ReportScheduleModal } from '../components/ReportScheduleModal';

export const ComplianceReportsPage: React.FC = () => {
  const [activeFramework, setActiveFramework] = useState<string>('soc2');
  const [evaluations, setEvaluations] = useState<Record<string, ComplianceEvaluationData>>({});
  const [schedules, setSchedules] = useState<ReportScheduleData[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [showScheduleModal, setShowScheduleModal] = useState(false);

  const frameworksList = [
    { key: 'soc2', name: 'SOC 2 Type II' },
    { key: 'iso27001', name: 'ISO/IEC 27001' },
    { key: 'nist_csf', name: 'NIST CSF 2.0' },
    { key: 'pci_dss', name: 'PCI-DSS 4.0' },
    { key: 'hipaa', name: 'HIPAA Security' },
  ];

  const loadFrameworkData = async (fw: string) => {
    setIsLoading(true);
    try {
      const data = await fetchComplianceEvaluation(fw);
      setEvaluations((prev) => ({ ...prev, [fw]: data }));
    } catch (err) {
      console.error('Failed to load compliance data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleReevaluate = async (fw: string) => {
    setIsLoading(true);
    try {
      const data = await evaluateCompliance(fw);
      setEvaluations((prev) => ({ ...prev, [fw]: data }));
    } catch (err) {
      console.error('Failed to re-evaluate compliance:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const loadSchedules = async () => {
    try {
      const data = await fetchReportSchedules();
      setSchedules(data);
    } catch (err) {
      console.error('Failed to load schedules:', err);
    }
  };

  const handleDeleteSchedule = async (id: string) => {
    try {
      await deleteReportSchedule(id);
      loadSchedules();
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    loadFrameworkData(activeFramework);
    loadSchedules();
  }, [activeFramework]);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Enterprise Compliance & Executive Reporting
          </h1>
          <p className="text-sm text-gray-400">
            Real-time compliance evaluations, automated evidence collection, and scheduled report delivery.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-3">
          <a
            href="/api/v1/reports/export/pdf?report_type=executive"
            target="_blank"
            rel="noreferrer"
            className="px-3.5 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded-md text-xs font-semibold border border-gray-700 transition-colors flex items-center gap-1.5"
          >
            <span>📄</span> Executive PDF
          </a>
          <a
            href={`/api/v1/reports/export/pdf?report_type=compliance&framework=${activeFramework}`}
            target="_blank"
            rel="noreferrer"
            className="px-3.5 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded-md text-xs font-semibold border border-gray-700 transition-colors flex items-center gap-1.5"
          >
            <span>📜</span> Compliance PDF
          </a>
          <a
            href="/api/v1/reports/export/csv?report_type=incidents"
            target="_blank"
            rel="noreferrer"
            className="px-3.5 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded-md text-xs font-semibold border border-gray-700 transition-colors flex items-center gap-1.5"
          >
            <span>📊</span> Incidents CSV
          </a>
          <button
            onClick={() => setShowScheduleModal(true)}
            className="px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-md text-xs font-semibold transition-colors"
          >
            + Schedule Report
          </button>
        </div>
      </div>

      {/* Framework Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-gray-800 pb-2 overflow-x-auto">
        {frameworksList.map((fw) => (
          <button
            key={fw.key}
            onClick={() => setActiveFramework(fw.key)}
            className={`px-4 py-2 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors ${
              activeFramework === fw.key
                ? 'bg-cyan-600 text-white shadow-sm'
                : 'bg-gray-900 text-gray-400 hover:text-white'
            }`}
          >
            {fw.name}
          </button>
        ))}
      </div>

      {/* Main Compliance Evaluation Card */}
      {evaluations[activeFramework] ? (
        <ComplianceFrameworkCard
          evaluation={evaluations[activeFramework]}
          onReevaluate={() => handleReevaluate(activeFramework)}
          isLoading={isLoading}
        />
      ) : (
        <div className="bg-gray-900 rounded-lg p-10 text-center text-gray-500 border border-gray-800">
          Loading {activeFramework.toUpperCase()} compliance audit...
        </div>
      )}

      {/* Scheduled Reports Table */}
      <div className="bg-gray-900 rounded-lg p-5 border border-gray-800 space-y-3">
        <h3 className="text-base font-bold text-white flex items-center justify-between">
          <span>Automated Report Delivery Schedules ({schedules.length})</span>
          <span className="text-xs text-gray-500 font-normal">Recurring Delivery</span>
        </h3>

        {schedules.length === 0 ? (
          <div className="text-gray-500 text-xs py-6 text-center">
            No recurring report schedules configured. Click &quot;+ Schedule Report&quot; to set up automated email digests.
          </div>
        ) : (
          <div className="space-y-2">
            {schedules.map((sched) => (
              <div
                key={sched.id}
                className="p-3 bg-gray-950 rounded border border-gray-800 flex items-center justify-between text-xs"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-white">{sched.name}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-300 uppercase font-mono">
                      {sched.frequency}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 uppercase font-mono">
                      {sched.report_type}
                    </span>
                  </div>
                  <div className="text-[11px] text-gray-500 mt-1 font-mono">
                    Recipients: {sched.recipients.join(', ') || 'None'} | Channel: {sched.delivery_channel}
                  </div>
                </div>

                <button
                  onClick={() => handleDeleteSchedule(sched.id)}
                  className="text-red-400 hover:text-red-300 text-xs px-2.5 py-1 rounded bg-red-950/40 border border-red-800/80"
                >
                  Delete
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Schedule Modal */}
      {showScheduleModal && (
        <ReportScheduleModal
          onClose={() => setShowScheduleModal(false)}
          onSuccess={loadSchedules}
        />
      )}
    </div>
  );
};
