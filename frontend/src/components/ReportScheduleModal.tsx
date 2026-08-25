import React, { useState } from 'react';
import { createReportSchedule } from '../api/reports';

interface ReportScheduleModalProps {
  onClose: () => void;
  onSuccess: () => void;
}

export const ReportScheduleModal: React.FC<ReportScheduleModalProps> = ({
  onClose,
  onSuccess,
}) => {
  const [name, setName] = useState('');
  const [reportType, setReportType] = useState('executive');
  const [framework, setFramework] = useState('soc2');
  const [frequency, setFrequency] = useState('weekly');
  const [recipients, setRecipients] = useState('ciso@enterprise.local, secops@enterprise.local');
  const [channel, setChannel] = useState('email');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    setIsSubmitting(true);
    try {
      const recipientList = recipients
        .split(',')
        .map((r) => r.trim())
        .filter((r) => r.length > 0);

      await createReportSchedule({
        name,
        report_type: reportType,
        framework: reportType === 'compliance' ? framework : undefined,
        frequency,
        recipients: recipientList,
        delivery_channel: channel,
      });
      onSuccess();
      onClose();
    } catch (err) {
      console.error(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 max-w-md w-full space-y-4">
        <h3 className="text-lg font-bold text-white">Schedule Automated Security Report</h3>

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="text-xs text-gray-400 block mb-1">Schedule Name</label>
            <input
              type="text"
              required
              placeholder="e.g. Weekly CISO Executive Digest"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-gray-950 border border-gray-700 text-xs text-white rounded p-2 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1">Report Type</label>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value)}
                className="w-full bg-gray-950 border border-gray-700 text-xs text-white rounded p-2"
              >
                <option value="executive">Executive Summary</option>
                <option value="compliance">Compliance Audit</option>
                <option value="incidents">Incident Ledger</option>
                <option value="audit">Audit Log Trail</option>
              </select>
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Frequency</label>
              <select
                value={frequency}
                onChange={(e) => setFrequency(e.target.value)}
                className="w-full bg-gray-950 border border-gray-700 text-xs text-white rounded p-2"
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>
          </div>

          {reportType === 'compliance' && (
            <div>
              <label className="text-xs text-gray-400 block mb-1">Compliance Framework</label>
              <select
                value={framework}
                onChange={(e) => setFramework(e.target.value)}
                className="w-full bg-gray-950 border border-gray-700 text-xs text-white rounded p-2"
              >
                <option value="soc2">SOC 2 Type II</option>
                <option value="iso27001">ISO/IEC 27001:2022</option>
                <option value="nist_csf">NIST CSF 2.0</option>
                <option value="pci_dss">PCI-DSS 4.0</option>
                <option value="hipaa">HIPAA Security Rule</option>
              </select>
            </div>
          )}

          <div>
            <label className="text-xs text-gray-400 block mb-1">Delivery Channel</label>
            <select
              value={channel}
              onChange={(e) => setChannel(e.target.value)}
              className="w-full bg-gray-950 border border-gray-700 text-xs text-white rounded p-2"
            >
              <option value="email">Email Digest</option>
              <option value="webhook">SIEM / SOC Webhook</option>
              <option value="s3">Secure Cloud Storage Bucket</option>
            </select>
          </div>

          <div>
            <label className="text-xs text-gray-400 block mb-1">
              Recipients (comma-separated emails)
            </label>
            <input
              type="text"
              placeholder="analyst@secops.local, ciso@secops.local"
              value={recipients}
              onChange={(e) => setRecipients(e.target.value)}
              className="w-full bg-gray-950 border border-gray-700 text-xs text-white rounded p-2 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="flex items-center justify-end gap-2 pt-3 border-t border-gray-800">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded text-xs text-gray-400 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded"
            >
              Save Schedule
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
