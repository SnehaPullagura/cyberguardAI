import { ConnectionStatus, RealtimeEventEnvelope } from '../types';

type MessageListener = (event: RealtimeEventEnvelope) => void;
type StatusListener = (status: ConnectionStatus) => void;

export class ReconnectingWebSocketClient {
  private socket: WebSocket | null = null;
  private url: string;
  private token: string | null = null;
  private status: ConnectionStatus = 'DISCONNECTED';
  private messageListeners: Set<MessageListener> = new Set();
  private statusListeners: Set<StatusListener> = new Set();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectIntervalMs = 2000;
  private heartbeatTimer: any = null;

  constructor(url: string) {
    self_assign_url(this, url);
  }

  public connect(token: string) {
    this.token = token;
    this.reconnectAttempts = 0;
    this.initSocket();
  }

  private initSocket() {
    if (!this.token) return;

    this.setStatus('CONNECTING');
    const wsUrl = `${this.url}?token=${encodeURIComponent(this.token)}`;

    try {
      this.socket = new WebSocket(wsUrl);

      this.socket.onopen = () => {
        this.reconnectAttempts = 0;
        this.setStatus('CONNECTED');
        this.startHeartbeat();
      };

      this.socket.onmessage = (event) => {
        try {
          const envelope: RealtimeEventEnvelope = JSON.parse(event.data);
          this.messageListeners.forEach((listener) => listener(envelope));
        } catch (err) {
          console.warn('Failed to parse WebSocket message', err);
        }
      };

      this.socket.onclose = (event) => {
        this.stopHeartbeat();
        if (event.code === 4008 || event.code === 4001) {
          this.setStatus('DISCONNECTED');
          return;
        }
        this.handleReconnect();
      };

      this.socket.onerror = (err) => {
        console.warn('WebSocket connection error:', err);
      };
    } catch (e) {
      this.handleReconnect();
    }
  }

  private handleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.setStatus('DISCONNECTED');
      return;
    }

    this.setStatus('RECONNECTING');
    this.reconnectAttempts++;
    const delay = Math.min(10000, this.reconnectIntervalMs * Math.pow(1.5, this.reconnectAttempts));
    setTimeout(() => {
      this.initSocket();
    }, delay);
  }

  private startHeartbeat() {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.socket && this.socket.readyState === WebSocket.OPEN) {
        this.socket.send(JSON.stringify({ type: 'ping' }));
      }
    }, 15000);
  }

  private stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  public disconnect() {
    this.stopHeartbeat();
    this.token = null;
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.setStatus('DISCONNECTED');
  }

  private setStatus(status: ConnectionStatus) {
    this.status = status;
    this.statusListeners.forEach((listener) => listener(status));
  }

  public onMessage(listener: MessageListener) {
    this.messageListeners.add(listener);
    return () => {
      this.messageListeners.delete(listener);
    };
  }

  public onStatus(listener: StatusListener) {
    this.statusListeners.add(listener);
    listener(this.status);
    return () => {
      this.statusListeners.delete(listener);
    };
  }

  public getStatus(): ConnectionStatus {
    return this.status;
  }
}

function self_assign_url(instance: ReconnectingWebSocketClient, url: string) {
  (instance as any).url = url;
}

const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsHost = window.location.hostname || 'localhost';
export const realtimeWsClient = new ReconnectingWebSocketClient(`${wsProtocol}//${wsHost}:8000/api/v1/ws`);
