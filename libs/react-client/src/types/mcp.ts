export interface IMcp {
  name: string;
  tools: [{ name: string }];
  status: 'connected' | 'connecting' | 'failed';
  clientType: 'sse' | 'stdio' | 'streamable-http';
  command?: string;
  url?: string;
  /** Optional HTTP headers used when connecting (SSE or streamable-http) */
  headers?: Record<string, string>;
  /** OAuth configuration for re-authentication */
  oauthConfig?: {
    discoveryUrl: string;
    clientId: string;
    tokenType: 'id_token' | 'access_token';
  };
}
