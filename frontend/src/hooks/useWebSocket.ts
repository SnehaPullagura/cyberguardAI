import { useEffect, useState, useCallback } from 'react';
import { ConnectionStatus, RealtimeEventEnvelope, SecurityEvent, SecurityAlert } from '../types';
import { realtimeWsClient } from '../api/websocket';

export const useWebSocket = () => {
  const [status, setStatus] = useState<ConnectionStatus>('DISCONNECTED');
  const [liveEvents, setLiveEvents] = useState<SecurityEvent[]>([]);
  const [liveAlerts, setLiveAlerts] = useState<SecurityAlert[]>([]);
  const [liveMetrics, setLiveMetrics] = useState<{ eventsCount: number; alertsCount: number }>({
    eventsCount: 0,
    alertsCount: 0,
  });

  const connect = useCallback((token: string) => {
    realtimeWsClient.connect(token);
  }, []);

  const disconnect = useCallback(() => {
    realtimeWsClient.disconnect();
  }, []);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      realtimeWsClient.connect(token);
    }

    const unsubStatus = realtimeWsClient.onStatus((newStatus) => {
      setStatus(newStatus);
    });

    const unsubMsg = realtimeWsClient.onMessage((envelope: RealtimeEventEnvelope) => {
      if (envelope.type === 'security_event') {
        const evData: SecurityEvent = {
          id: envelope.data.id || envelope.message_id,
          event_id: envelope.data.event_id || 'evt-stream',
          timestamp: envelope.data.timestamp || new Date().toISOString(),
          source_type: envelope.data.source_type || 'syslog',
          category: envelope.data.category || 'general',
          action: envelope.data.action || 'event',
          severity: envelope.data.severity || 'info',
          source_ip: envelope.data.source_ip,
          risk_score: envelope.data.risk_score,
          anomaly_score: envelope.data.anomaly_score,
        };

        setLiveEvents((prev) => [evData, ...prev.slice(0, 49)]);
        setLiveMetrics((prev) => ({ ...prev, eventsCount: prev.eventsCount + 1 }));
      } else if (envelope.type === 'alert_created') {
        const alertData: SecurityAlert = {
          id: envelope.data.id || envelope.message_id,
          alert_id: envelope.data.id || 'alert-live',
          timestamp: envelope.timestamp || new Date().toISOString(),
          title: envelope.data.title || 'Security Alert',
          severity: envelope.data.severity || 'high',
          risk_score: envelope.data.risk_score || 75.0,
          status: 'open',
          source_entity: envelope.data.source_entity,
          detection_source: envelope.data.detection_source || 'rule',
        };

        setLiveAlerts((prev) => [alertData, ...prev.slice(0, 19)]);
        setLiveMetrics((prev) => ({ ...prev, alertsCount: prev.alertsCount + 1 }));
      }
    });

    return () => {
      unsubStatus();
      unsubMsg();
    };
  }, []);

  return {
    status,
    liveEvents,
    liveAlerts,
    liveMetrics,
    connect,
    disconnect,
  };
};
