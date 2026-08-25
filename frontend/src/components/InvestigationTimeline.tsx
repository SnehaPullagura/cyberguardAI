import React from 'react';
import { CaseTimelineEvent } from '../types';

interface InvestigationTimelineProps {
  timeline: CaseTimelineEvent[];
}

export const InvestigationTimeline: React.FC<InvestigationTimelineProps> = ({ timeline }) => {
  const getEventBadge = (type: string) => {
    switch (type) {
      case 'status_change':
        return 'bg-purple-900/60 text-purple-300 border-purple-700';
      case 'evidence':
        return 'bg-amber-900/60 text-amber-300 border-amber-700';
      case 'note':
        return 'bg-blue-900/60 text-blue-300 border-blue-700';
      case 'alert':
        return 'bg-red-900/60 text-red-300 border-red-700';
      case 'response_action':
        return 'bg-emerald-900/60 text-emerald-300 border-emerald-700';
      default:
        return 'bg-gray-800 text-gray-300 border-gray-700';
    }
  };

  return (
    <div className="bg-gray-900 rounded-lg p-5 border border-gray-800">
      <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
        <span className="w-2.5 h-2.5 rounded-full bg-cyan-400"></span>
        Investigation Timeline ({timeline.length} events)
      </h3>

      {timeline.length === 0 ? (
        <div className="text-gray-500 py-8 text-center text-sm">
          No timeline events recorded yet.
        </div>
      ) : (
        <div className="relative border-l border-gray-800 ml-4 space-y-6">
          {timeline.map((event) => (
            <div key={event.id} className="relative pl-6">
              {/* Dot */}
              <div className="absolute -left-1.5 top-1.5 w-3 h-3 rounded-full bg-cyan-500 border-2 border-gray-950"></div>
              
              <div className="bg-gray-950/80 p-3 rounded-md border border-gray-800/80">
                <div className="flex items-center justify-between gap-2 mb-1">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xs px-2 py-0.5 rounded border uppercase font-mono ${getEventBadge(
                        event.event_type
                      )}`}
                    >
                      {event.event_type}
                    </span>
                    <span className="font-semibold text-white text-sm">
                      {event.title}
                    </span>
                  </div>
                  <span className="text-xs text-gray-500 font-mono">
                    {new Date(event.timestamp).toLocaleTimeString([], {
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                    })}
                  </span>
                </div>

                {event.description && (
                  <p className="text-xs text-gray-300 mb-1">{event.description}</p>
                )}

                {event.actor && (
                  <div className="text-[11px] text-gray-500 flex items-center gap-1">
                    <span>Actor:</span>
                    <span className="text-gray-400 font-mono">{event.actor}</span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
