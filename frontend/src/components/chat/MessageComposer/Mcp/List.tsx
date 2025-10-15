import { cn } from '@/lib/utils';
import { Link, RefreshCw, SquareTerminal, Trash2, Wrench } from 'lucide-react';
import { useContext, useState } from 'react';
import { useRecoilState, useRecoilValue, useSetRecoilState } from 'recoil';
import { toast } from 'sonner';

import {
  ChainlitContext,
  IMcp,
  mcpState,
  sessionIdState
} from '@chainlit/react-client';

import CopyButton from '@/components/CopyButton';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger
} from '@/components/ui/alert-dialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Translator } from 'components/i18n';

interface McpListProps {
  onAddNewClick: () => void;
}

export const McpList = ({ onAddNewClick }: McpListProps) => {
  const apiClient = useContext(ChainlitContext);
  const sessionId = useRecoilValue(sessionIdState);
  const [mcps, setMcps] = useRecoilState(mcpState);
  const [isLoading, setIsLoading] = useState(false);

  const deleteMcp = (mcp: IMcp) => {
    if (mcp.status === 'connected') {
      setIsLoading(true);

      toast.promise(
        apiClient
          .disconnectMcp(sessionId, mcp.name)
          .then(() => {})
          .finally(() => setIsLoading(false)),
        {
          loading: 'Removing MCP...',
          success: () => 'MCP removed!',
          error: (err) => <span>{err.message}</span>
        }
      );
    }

    setMcps((prev) => prev.filter((_mcp) => _mcp.name !== mcp.name));
  };

  if (!mcps || mcps.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <p>No MCP servers connected</p>
        <Button variant="outline" className="mt-4" onClick={onAddNewClick}>
          Add your first MCP server
        </Button>
      </div>
    );
  }

  return (
    <>
      {mcps.map((mcp, index) => (
        <McpItem
          key={index}
          mcp={mcp}
          onDelete={deleteMcp}
          isLoading={isLoading}
        />
      ))}
    </>
  );
};

interface McpItemProps {
  mcp: IMcp;
  onDelete: (mcp: IMcp) => void;
  isLoading: boolean;
}

const McpItem = ({ mcp, onDelete, isLoading }: McpItemProps) => {
  return (
    <div className="border rounded-lg p-4 flex flex-col gap-3">
      <div className="flex justify-between items-center">
        <div className="flex items-center gap-2">
          <div
            className={cn(
              'h-2 w-2 rounded-full',
              mcp.status === 'connected' && 'bg-green-500',
              mcp.status === 'connecting' && 'bg-yellow-500',
              mcp.status === 'failed' && 'bg-red-500'
            )}
          />
          <h3 className="font-medium">{mcp.name}</h3>
          <Badge variant="outline">{mcp.clientType}</Badge>
        </div>
        <div className="flex items-center">
          <ReconnectMcpButton mcp={mcp} />
          <DeleteMcpButton mcp={mcp} onDelete={onDelete} disabled={isLoading} />
        </div>
      </div>

      <div className="flex gap-2 flex-wrap">
        <div className="font-medium text-sm text-muted-foreground flex items-center">
          {mcp.clientType === 'stdio' ? (
            <SquareTerminal className="h-4 w-4 mr-2" />
          ) : mcp.clientType === 'streamable-http' ? (
            <Link className="h-4 w-4 mr-2 text-blue-500" />
          ) : (
            <Link className="h-4 w-4 mr-2" />
          )}
          {mcp.clientType === 'stdio'
            ? 'Command'
            : mcp.clientType === 'streamable-http'
            ? 'HTTP URL'
            : 'URL'}
        </div>
        <div className="flex items-center w-full bg-accent px-3 py-1 rounded gap-2">
          <pre className="text-sm font-mono flex-grow truncate">
            {mcp.command || mcp.url || 'N/A'}
          </pre>
          <CopyButton content={mcp.command || mcp.url} />
        </div>
      </div>

      <div className="font-medium text-sm text-muted-foreground flex items-center">
        <Wrench className="h-4 w-4 mr-2" />
        Tools
      </div>
      <div className="flex flex-wrap gap-2">
        {mcp.tools &&
          mcp.tools.map((tool, toolIndex) => (
            <Badge key={toolIndex} variant="secondary">
              {tool.name}
            </Badge>
          ))}
      </div>
    </div>
  );
};

interface DeleteMcpButtonProps {
  mcp: IMcp;
  onDelete: (mcp: IMcp) => void;
  disabled: boolean;
}

const DeleteMcpButton = ({ mcp, onDelete, disabled }: DeleteMcpButtonProps) => {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="text-destructive"
          disabled={disabled}
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Are you sure?</AlertDialogTitle>
          <AlertDialogDescription>
            This will disconnect the MCP server "{mcp.name}". This action cannot
            be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>
            <Translator path="common.actions.cancel" />
          </AlertDialogCancel>
          <AlertDialogAction
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            onClick={() => onDelete(mcp)}
          >
            <Translator path="common.actions.confirm" />
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
};

const ReconnectMcpButton = ({ mcp }: { mcp: IMcp }) => {
  const apiClient = useContext(ChainlitContext);
  const setMcps = useSetRecoilState(mcpState);
  const sessionId = useRecoilValue(sessionIdState);
  const [isLoading, setIsLoading] = useState(false);

  const reconnectMcp = async () => {
    setIsLoading(true);

    // Check if this MCP has OAuth configuration
    const hasOAuth = !!mcp.oauthConfig;

    // If OAuth is configured, trigger re-authentication
    if (hasOAuth) {
      try {
        toast.info('Re-authenticating with OAuth...');

        const { discoveryUrl, clientId, tokenType } = mcp.oauthConfig!;

        // Get authorization URL from backend
        const params = new URLSearchParams({
          discovery_url: discoveryUrl,
          client_id: clientId,
          redirect_uri: `${window.location.origin}/mcp/oauth/callback`
        });

        const response = await fetch(`/mcp/oauth/authorize?${params}`);
        if (!response.ok) {
          throw new Error('Failed to get authorization URL');
        }

        const { authorization_url } = await response.json();

        // Open OAuth popup
        const popup = window.open(
          authorization_url,
          'OAuth Re-authentication',
          'width=500,height=700,left=100,top=100'
        );

        if (!popup) {
          toast.error('Popup blocked! Please allow popups for this site.');
          setIsLoading(false);
          return;
        }

        // Wait for OAuth token from popup
        const token = await new Promise<string>((resolve, reject) => {
          const messageHandler = (event: MessageEvent) => {
            if (event.data.type === 'oauth_success') {
              const tokens = event.data.tokens;
              const token =
                tokenType === 'id_token' ? tokens.id_token : tokens.access_token;
              window.removeEventListener('message', messageHandler);
              resolve(token);
            } else if (event.data.type === 'oauth_error') {
              window.removeEventListener('message', messageHandler);
              reject(new Error(event.data.error || 'Authentication failed'));
            }
          };

          window.addEventListener('message', messageHandler);

          // Check if popup was closed without completing auth
          const checkPopup = setInterval(() => {
            if (popup.closed) {
              clearInterval(checkPopup);
              window.removeEventListener('message', messageHandler);
              reject(new Error('Login window was closed'));
            }
          }, 1000);
        });

        // Update MCP with fresh token
        const headers = (mcp as any).headers || {};
        headers['Authorization'] = `Bearer ${token}`;

        // Update stored MCP with new headers (preserve OAuth config)
        setMcps((prev) =>
          prev.map((existingMcp) => {
            if (existingMcp.name === mcp.name) {
              return {
                ...existingMcp,
                headers: headers,
                oauthConfig: mcp.oauthConfig // Preserve OAuth config
              };
            }
            return existingMcp;
          })
        );

        toast.success('Re-authentication successful!');
      } catch (error: any) {
        toast.error(`Re-authentication failed: ${error.message}`);
        setIsLoading(false);
        return;
      }
    }

    setMcps((prev) =>
      prev.map((existingMcp) => {
        if (existingMcp.name === mcp.name) {
          return {
            ...existingMcp,
            status: 'connecting'
          };
        }
        return existingMcp;
      })
    );

    const updateMcpStatus = (success: boolean, updatedMcp?: any) => {
      setMcps((prev) =>
        prev.map((existingMcp) => {
          if (existingMcp.name === mcp.name) {
            return {
              ...existingMcp,
              status: success ? 'connected' : 'failed',
              tools: updatedMcp ? updatedMcp.tools : existingMcp.tools
            };
          }
          return existingMcp;
        })
      );
    };

    if (mcp.clientType === 'stdio') {
      toast.promise(
        apiClient
          .connectStdioMCP(sessionId, mcp.name, mcp.command!)
          .then(async (resp: any) => {
            const { success, mcp: updatedMcp } = resp;
            updateMcpStatus(success, updatedMcp);
          })
          .catch(() => {
            updateMcpStatus(false);
          })
          .finally(() => setIsLoading(false)),
        {
          loading: 'Reconnecting MCP...',
          success: () => 'MCP reconnected!',
          error: (err) => <span>{err.message}</span>
        }
      );
    } else if (mcp.clientType === 'streamable-http') {
      toast.promise(
        (apiClient as any)
          .connectStreamableHttpMCP(
            sessionId,
            mcp.name,
            mcp.url!,
            (mcp as any).headers
          )
          .then(async (resp: any) => {
            const { success, mcp: updatedMcp } = resp;
            updateMcpStatus(success, updatedMcp);
          })
          .catch(() => {
            updateMcpStatus(false);
          })
          .finally(() => setIsLoading(false)),
        {
          loading: 'Reconnecting MCP...',
          success: () => 'MCP reconnected!',
          error: (err) => <span>{err.message}</span>
        }
      );
    } else {
      toast.promise(
        (apiClient as any)
          .connectSseMCP(sessionId, mcp.name, mcp.url!, (mcp as any).headers)
          .then(async (resp: any) => {
            const { success, mcp: updatedMcp } = resp;
            updateMcpStatus(success, updatedMcp);
          })
          .catch(() => {
            updateMcpStatus(false);
          })
          .finally(() => setIsLoading(false)),
        {
          loading: 'Reconnecting MCP...',
          success: () => 'MCP reconnected!',
          error: (err) => <span>{err.message}</span>
        }
      );
    }
  };

  return (
    <Button
      variant="ghost"
      size="icon"
      disabled={isLoading}
      onClick={reconnectMcp}
    >
      <RefreshCw className="h-4 w-4" />
    </Button>
  );
};
