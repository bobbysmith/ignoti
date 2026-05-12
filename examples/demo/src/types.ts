export interface SessionInfo {
  sessionId: string;
  userId: string;
  deviceId: string;
  expiresAt: number;
}

export type AuthView = 'login' | 'signup' | 'recover';
