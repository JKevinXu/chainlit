import { useContext, useState } from 'react';
import { useRecoilValue, useSetRecoilState } from 'recoil';
import { toast } from 'sonner';

import {
  ChainlitContext,
  mcpState,
  sessionIdState
} from '@chainlit/react-client';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '@/components/ui/select';
import { Translator } from 'components/i18n';

interface McpAddFormProps {
  onSuccess: () => void;
  onCancel: () => void;
  allowStdio?: boolean;
  allowSse?: boolean;
  allowHttp?: boolean;
}

export const McpAddForm = ({
  onSuccess,
  onCancel,
  allowStdio,
  allowSse,
  allowHttp
}: McpAddFormProps) => {
  const apiClient = useContext(ChainlitContext);
  const sessionId = useRecoilValue(sessionIdState);
  const setMcps = useSetRecoilState(mcpState);

  const [serverName, setServerName] = useState('');
  // Pick the first protocol enabled by the parent component.
  const defaultType: 'stdio' | 'sse' | 'streamable-http' = allowStdio
    ? 'stdio'
    : allowSse
    ? 'sse'
    : allowHttp
    ? 'streamable-http'
    : 'stdio';

  const [serverType, setServerType] = useState<
    'stdio' | 'sse' | 'streamable-http'
  >(defaultType);
  const [serverUrl, setServerUrl] = useState('');
  const [httpUrl, setHttpUrl] = useState('');
  const [serverCommand, setServerCommand] = useState('');
  const [headersInput, setHeadersInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  // OAuth configuration fields
  const [discoveryUrl, setDiscoveryUrl] = useState('');
  const [allowedAudience, setAllowedAudience] = useState('');
  const [tokenType, setTokenType] = useState<'id_token' | 'access_token'>(
    'id_token'
  );

  // Form validation function
  const isFormValid = () => {
    if (!serverName.trim()) return false;

    if (serverType === 'stdio') {
      return !!serverCommand.trim();
    } else if (serverType === 'sse') {
      return !!serverUrl.trim();
    } else if (serverType === 'streamable-http') {
      return !!httpUrl.trim();
    }
    return false;
  };

  const resetForm = () => {
    setServerName('');
    setServerType(defaultType);
    setServerUrl('');
    setServerCommand('');
    setHttpUrl('');
    setHeadersInput('');
    setDiscoveryUrl('');
    setAllowedAudience('');
    setTokenType('id_token');
  };

  const addMcp = () => {
    setIsLoading(true);

    // Helper to parse the optional headers JSON
    let headersObj: Record<string, string> | undefined;
    if (headersInput.trim()) {
      try {
        headersObj = JSON.parse(headersInput.trim());
      } catch (_err) {
        toast.error('Headers must be valid JSON');
        setIsLoading(false);
        return;
      }
    }

    // Add OAuth configuration as headers metadata (for backend processing)
    if (discoveryUrl && allowedAudience) {
      if (!headersObj) {
        headersObj = {};
      }
      // Store OAuth config in special headers for backend to process
      headersObj['X-OAuth-Discovery-Url'] = discoveryUrl;
      headersObj['X-OAuth-Allowed-Audience'] = allowedAudience;
      headersObj['X-OAuth-Token-Type'] = tokenType;
    }

    if (serverType === 'stdio') {
      toast.promise(
        apiClient
          .connectStdioMCP(sessionId, serverName, serverCommand)
          .then(async (resp: any) => {
            const { success, mcp } = resp;
            if (success && mcp) {
              setMcps((prev) => [...prev, { ...mcp, status: 'connected' }]);
            }
            resetForm();
            onSuccess();
          })
          .finally(() => setIsLoading(false)),
        {
          loading: 'Adding MCP...',
          success: () => 'MCP added!',
          error: (err) => <span>{err.message}</span>
        }
      );
    } else if (serverType === 'sse') {
      toast.promise(
        (apiClient as any)
          .connectSseMCP(sessionId, serverName, serverUrl, headersObj)
          .then(async (resp: any) => {
            const { success, mcp } = resp;
            if (success && mcp) {
              setMcps((prev) => [...prev, { ...mcp, status: 'connected' }]);
            }
            resetForm();
            onSuccess();
          })
          .finally(() => setIsLoading(false)),
        {
          loading: 'Adding MCP...',
          success: () => 'MCP added!',
          error: (err) => <span>{err.message}</span>
        }
      );
    } else if (serverType === 'streamable-http') {
      toast.promise(
        (apiClient as any)
          .connectStreamableHttpMCP(sessionId, serverName, httpUrl, headersObj)
          .then(async (resp: any) => {
            const { success, mcp } = resp;
            if (success && mcp) {
              setMcps((prev) => [...prev, { ...mcp, status: 'connected' }]);
            }
            resetForm();
            onSuccess();
          })
          .finally(() => setIsLoading(false)),
        {
          loading: 'Adding MCP...',
          success: () => 'MCP added!',
          error: (err) => <span>{err.message}</span>
        }
      );
    }
  };

  return (
    <>
      <div className="flex flex-col gap-4">
        <div className="flex gap-2 w-full">
          <div className="flex flex-col flex-grow gap-2">
            <Label htmlFor="server-name" className="text-foreground/70 text-sm">
              Name *
            </Label>
            <Input
              id="server-name"
              placeholder="Example: Stripe"
              className="w-full bg-background text-foreground border-input"
              value={serverName}
              onChange={(e) => setServerName(e.target.value)}
              required
              disabled={isLoading}
            />
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="server-type" className="text-foreground/70 text-sm">
              Type *
            </Label>
            <Select
              value={serverType}
              onValueChange={setServerType as any}
              disabled={isLoading}
            >
              <SelectTrigger
                id="server-type"
                className="w-full bg-background text-foreground border-input"
              >
                <SelectValue placeholder="Type" />
              </SelectTrigger>
              <SelectContent>
                {allowSse ? <SelectItem value="sse">sse</SelectItem> : null}
                {allowStdio ? (
                  <SelectItem value="stdio">stdio</SelectItem>
                ) : null}
                {allowHttp ? (
                  <SelectItem value="streamable-http">
                    streamable-http
                  </SelectItem>
                ) : null}
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="flex flex-col gap-2">
          {serverType === 'stdio' && (
            <>
              <Label
                htmlFor="server-command"
                className="text-foreground/70 text-sm"
              >
                Command *
              </Label>
              <Input
                id="server-command"
                placeholder="Example: npx -y @stripe/mcp --tools=all --api-key=YOUR_STRIPE_SECRET_KEY"
                className="w-full bg-background text-foreground border-input"
                value={serverCommand}
                onChange={(e) => setServerCommand(e.target.value)}
                required
                disabled={isLoading}
              />
            </>
          )}
          {serverType === 'sse' && (
            <>
              <Label
                htmlFor="server-url"
                className="text-foreground/70 text-sm"
              >
                Server URL *
              </Label>
              <Input
                id="server-url"
                placeholder="Example: http://localhost:5000"
                className="w-full bg-background text-foreground border-input"
                value={serverUrl}
                onChange={(e) => setServerUrl(e.target.value)}
                required
                disabled={isLoading}
              />
            </>
          )}
          {serverType === 'streamable-http' && (
            <>
              <Label htmlFor="http-url" className="text-foreground/70 text-sm">
                HTTP URL *
              </Label>
              <Input
                id="http-url"
                placeholder="Example: http://localhost:8000/mcp"
                className="w-full bg-background text-foreground border-input"
                value={httpUrl}
                onChange={(e) => setHttpUrl(e.target.value)}
                required
                disabled={isLoading}
              />
            </>
          )}
          {(serverType === 'sse' || serverType === 'streamable-http') && (
            <>
              <Label htmlFor="headers" className="text-foreground/70 text-sm">
                Headers (JSON, optional)
              </Label>
              <Input
                id="headers"
                placeholder='Example: {"Authorization": "Bearer TOKEN"}'
                className="w-full bg-background text-foreground border-input font-mono"
                value={headersInput}
                onChange={(e) => setHeadersInput(e.target.value)}
                disabled={isLoading}
              />
            </>
          )}
        </div>

        {/* OAuth Configuration Section */}
        {(serverType === 'sse' || serverType === 'streamable-http') && (
          <div className="flex flex-col gap-4 border-t border-border pt-4">
            <div className="flex items-center gap-2">
              <Label className="text-foreground font-semibold text-sm">
                🔐 OAuth Configuration (Optional)
              </Label>
            </div>

            <div className="flex flex-col gap-2">
              <Label
                htmlFor="discovery-url"
                className="text-foreground/70 text-sm"
              >
                Discovery URL
              </Label>
              <Input
                id="discovery-url"
                placeholder="https://cognito-idp.us-east-1.amazonaws.com/.../.well-known/openid-configuration"
                className="w-full bg-background text-foreground border-input font-mono text-xs"
                value={discoveryUrl}
                onChange={(e) => setDiscoveryUrl(e.target.value)}
                disabled={isLoading}
              />
              <p className="text-xs text-muted-foreground">
                OpenID Connect discovery endpoint for token validation
              </p>
            </div>

            <div className="flex gap-2">
              <div className="flex flex-col flex-grow gap-2">
                <Label
                  htmlFor="allowed-audience"
                  className="text-foreground/70 text-sm"
                >
                  Allowed Audience
                </Label>
                <Input
                  id="allowed-audience"
                  placeholder="your_client_id_here"
                  className="w-full bg-background text-foreground border-input"
                  value={allowedAudience}
                  onChange={(e) => setAllowedAudience(e.target.value)}
                  disabled={isLoading}
                />
                <p className="text-xs text-muted-foreground">
                  Expected audience (client ID) in the OAuth token
                </p>
              </div>

              <div className="flex flex-col gap-2">
                <Label
                  htmlFor="token-type"
                  className="text-foreground/70 text-sm"
                >
                  Token Type
                </Label>
                <Select
                  value={tokenType}
                  onValueChange={(value) =>
                    setTokenType(value as 'id_token' | 'access_token')
                  }
                  disabled={isLoading}
                >
                  <SelectTrigger
                    id="token-type"
                    className="w-32 bg-background text-foreground border-input"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="id_token">ID Token</SelectItem>
                    <SelectItem value="access_token">Access Token</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {discoveryUrl && allowedAudience && (
              <div className="bg-blue-500/10 border border-blue-500/20 rounded-md p-3">
                <p className="text-xs text-blue-400">
                  ✓ OAuth configuration set. Token will be automatically generated from Cognito on connection.
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex justify-end items-center gap-2 mt-auto">
        <Button variant="outline" onClick={onCancel} disabled={isLoading}>
          <Translator path="common.actions.cancel" />
        </Button>
        <Button
          variant="default"
          onClick={addMcp}
          disabled={!isFormValid() || isLoading}
        >
          <Translator path="common.actions.confirm" />
        </Button>
      </div>
    </>
  );
};
