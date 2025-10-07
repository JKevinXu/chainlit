# TODO

## MCP Server Authentication

### ID Token Rotation Before Expiring (MCP OAuth Flow)

**Priority:** High  
**Status:** Pending  
**Created:** 2025-10-07  
**Scope:** MCP Server OAuth authentication only

---

## Problem Statement

Currently, the MCP (Model Context Protocol) server OAuth flow has the following limitations:

1. **No token management**: After initial authentication, tokens (id_token, access_token, refresh_token) are sent to the frontend but never refreshed
2. **No refresh mechanism**: When tokens expire, MCP servers must re-authenticate through the full OAuth flow
3. **MCP connection interruption**: When ID tokens expire, MCP server connections fail and must be manually re-established
4. **Poor developer experience**: Users see authentication errors when tokens expire, disrupting MCP interactions

This results in interrupted MCP server connections when tokens expire (typically after 1 hour).

---

## Current MCP OAuth Architecture

### Current Flow (`/mcp/oauth/*`)
```
1. Frontend calls /mcp/oauth/authorize
   ↓
2. Server generates PKCE challenge + authorization URL
   ↓
3. User authenticates on Cognito Hosted UI
   ↓
4. Cognito redirects to /mcp/oauth/callback with code
   ↓
5. Server exchanges code for tokens:
   - id_token
   - access_token  
   - refresh_token ✅ (received but not managed)
   ↓
6. Tokens returned to frontend via:
   - postMessage to opener window, OR
   - sessionStorage for retrieval
   ↓
7. Frontend stores tokens and uses for MCP authentication
   ↓
8. When tokens expire (1 hour) → MCP connection fails ❌
   User must manually re-authenticate
```

**Key Issue:** No mechanism to refresh tokens before expiration

---

## Proposed Solution (MCP-Specific)

### Architecture: Backend Token Refresh with Frontend Integration

**Design Decision:** Implement server-side token refresh endpoint that frontend can call proactively.

```
Frontend (MCP Client)
   ↓
Stores: {id_token, access_token, refresh_token, expires_at}
   ↓
Before token expires (5 min buffer)
   ↓
POST /mcp/oauth/refresh {refresh_token}
   ↓
Backend refreshes with Cognito
   ↓
Returns: {new_id_token, new_access_token, new_refresh_token, expires_at}
   ↓
Frontend updates stored tokens
   ↓
MCP connection continues seamlessly
```

---

### Phase 1: Backend Token Refresh Endpoint

#### 1.1 Create MCP Token Refresh Endpoint

**File:** `backend/chainlit/server.py`

Add new endpoint after existing `/mcp/oauth/callback`:

```python
@router.post("/mcp/oauth/refresh")
async def mcp_oauth_refresh(
    refresh_token: str = Body(..., embed=True),
    discovery_url: str = Body(...),
    client_id: str = Body(...)
):
    """
    Refresh MCP OAuth tokens using refresh token.
    
    Request body:
    {
        "refresh_token": "...",
        "discovery_url": "https://cognito-idp.{region}.amazonaws.com/{pool}/.well-known/openid-configuration",
        "client_id": "..."
    }
    
    Returns:
    {
        "id_token": "...",
        "access_token": "...",
        "refresh_token": "...",  (may be rotated)
        "expires_in": 3600,
        "expires_at": 1234567890
    }
    """
    from chainlit.oauth_hosted_ui import HostedUIProvider
    import os
    import time
    
    try:
        # Get optional client secret
        client_secret = os.getenv("COGNITO_CLIENT_SECRET")
        
        # Refresh tokens
        tokens = await HostedUIProvider.refresh_tokens(
            discovery_url=discovery_url,
            client_id=client_id,
            refresh_token=refresh_token,
            client_secret=client_secret
        )
        
        if not tokens:
            raise HTTPException(
                status_code=401,
                detail="Failed to refresh tokens. Refresh token may be expired."
            )
        
        # Add expires_at timestamp for frontend
        tokens["expires_at"] = int(time.time() + tokens.get("expires_in", 3600))
        
        return JSONResponse(content=tokens)
        
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Token refresh failed: {e!s}"
        )
```

#### 1.2 Implement Token Refresh Logic

**File:** `backend/chainlit/oauth_hosted_ui.py`

Add new method to `HostedUIProvider` class:

```python
@classmethod
async def refresh_tokens(
    cls,
    discovery_url: str,
    client_id: str,
    refresh_token: str,
    client_secret: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Use refresh token to get new ID and access tokens from Cognito.
    
    Args:
        discovery_url: OIDC discovery URL
        client_id: OAuth client ID
        refresh_token: Valid refresh token
        client_secret: Optional client secret for confidential clients
        
    Returns:
        Token response dict with id_token, access_token, and possibly new refresh_token
    """
    try:
        # Parse Cognito domain from discovery URL
        parts = discovery_url.split('/')
        if len(parts) >= 4 and 'cognito-idp' in discovery_url:
            region = parts[2].split('.')[1]
            user_pool_id = parts[3]
            
            cognito_domain = os.getenv("COGNITO_DOMAIN")
            if not cognito_domain:
                cognito_domain = f"{user_pool_id}.auth.{region}.amazoncognito.com"
        else:
            raise ValueError("Invalid discovery URL format")
        
        # Token endpoint
        token_url = f"https://{cognito_domain}/oauth2/token"
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        # Add client authentication if secret is provided
        if client_secret:
            auth_string = f"{client_id}:{client_secret}"
            auth_b64 = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')
            headers['Authorization'] = f'Basic {auth_b64}'
            print(f"🔐 Using client secret for token refresh")
        
        # Prepare request body for refresh token grant
        body = {
            'grant_type': 'refresh_token',
            'client_id': client_id,
            'refresh_token': refresh_token
        }
        
        print(f"🔄 Refreshing tokens for MCP OAuth...")
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                headers=headers,
                data=body
            )
            
            if response.status_code != 200:
                print(f"❌ Token refresh failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return None
            
            tokens = response.json()
            
            print(f"✅ Successfully refreshed MCP OAuth tokens")
            if 'id_token' in tokens:
                print(f"   New ID token: {tokens['id_token'][:50]}...")
            if 'access_token' in tokens:
                print(f"   New access token: {tokens['access_token'][:50]}...")
            if 'refresh_token' in tokens:
                print(f"   New refresh token received (token rotation enabled)")
            
            return tokens
            
    except Exception as e:
        print(f"❌ Error refreshing tokens: {e}")
        return None
```

---

### Phase 2: Frontend Token Management (Implementation Guidance)

#### 2.1 Update Frontend MCP Token Storage

**File:** `frontend/src/components/chat/MessageComposer/Mcp/AddForm.tsx`

The frontend should:

1. **Store full token response** including `expires_at`:
```typescript
interface MCPTokens {
  id_token: string;
  access_token: string;
  refresh_token: string;
  expires_at: number;  // Unix timestamp
  token_type: string;
}

// Store in state or context
const [mcpTokens, setMcpTokens] = useState<MCPTokens | null>(null);
```

2. **Check token expiration before use**:
```typescript
const isTokenExpiringSoon = (expiresAt: number, bufferSeconds = 300) => {
  const now = Math.floor(Date.now() / 1000);
  return (expiresAt - now) <= bufferSeconds;
};
```

3. **Proactively refresh tokens**:
```typescript
const refreshMCPTokens = async () => {
  if (!mcpTokens) return;
  
  try {
    const response = await fetch('/mcp/oauth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        refresh_token: mcpTokens.refresh_token,
        discovery_url: mcpConfig.discovery_url,
        client_id: mcpConfig.client_id
      })
    });
    
    if (!response.ok) {
      // Refresh failed - need to re-authenticate
      console.error('Token refresh failed');
      return null;
    }
    
    const newTokens = await response.json();
    setMcpTokens(newTokens);
    
    // Update any active MCP connections with new tokens
    updateActiveMCPConnections(newTokens);
    
    return newTokens;
  } catch (error) {
    console.error('Token refresh error:', error);
    return null;
  }
};
```

4. **Set up automatic refresh timer**:
```typescript
useEffect(() => {
  if (!mcpTokens) return;
  
  const checkAndRefresh = async () => {
    if (isTokenExpiringSoon(mcpTokens.expires_at)) {
      const refreshed = await refreshMCPTokens();
      if (!refreshed) {
        // Refresh failed - show re-authentication prompt
        setShowReauthPrompt(true);
      }
    }
  };
  
  // Check every minute
  const interval = setInterval(checkAndRefresh, 60000);
  
  return () => clearInterval(interval);
}, [mcpTokens]);
```

#### 2.2 Update OAuth Callback Handler

Update the OAuth callback handler to extract and store `expires_in`:

```typescript
// In postMessage handler
window.addEventListener('message', (event) => {
  if (event.data.type === 'oauth_success') {
    const tokens = event.data.tokens;
    
    // Calculate expires_at if not provided
    const expiresAt = tokens.expires_at || 
      (Math.floor(Date.now() / 1000) + (tokens.expires_in || 3600));
    
    setMcpTokens({
      ...tokens,
      expires_at: expiresAt
    });
  }
});
```

---

### Phase 3: Enhanced Token Response

#### 3.1 Update Callback to Include Expiration

**File:** `backend/chainlit/oauth_hosted_ui.py`

Update `exchange_code_for_token()` to include expiration timestamp:

```python
tokens = response.json()

# Add expires_at for frontend convenience
import time
expires_at = int(time.time() + tokens.get('expires_in', 3600))
tokens['expires_at'] = expires_at

print(f"✅ Successfully obtained tokens from Hosted UI")
print(f"   Expires at: {expires_at} ({tokens.get('expires_in', 3600)}s from now)")

return tokens
```

#### 3.2 Update Callback HTML Response

**File:** `backend/chainlit/server.py`

Update `/mcp/oauth/callback` to include `expires_at` in the response:

```python
# After token exchange succeeds
import time
if 'expires_at' not in tokens:
    tokens['expires_at'] = int(time.time() + tokens.get('expires_in', 3600))

# Return HTML page with tokens including expires_at
html_content = f"""
<script>
    if (window.opener) {{
        window.opener.postMessage({{
            type: 'oauth_success',
            tokens: {json.dumps(tokens)}  // Now includes expires_at
        }}, '*');
        window.close();
    }} else {{
        sessionStorage.setItem('mcp_oauth_tokens', JSON.stringify({json.dumps(tokens)}));
        setTimeout(() => {{ window.location.href = '/'; }}, 2000);
    }}
</script>
```

---

## Implementation Checklist (MCP-Specific)

### Backend - Token Refresh Endpoint
- [ ] Add `POST /mcp/oauth/refresh` endpoint in `backend/chainlit/server.py`
- [ ] Implement `HostedUIProvider.refresh_tokens()` method in `backend/chainlit/oauth_hosted_ui.py`
- [ ] Add `expires_at` calculation to token responses
- [ ] Handle client secret authentication for refresh requests
- [ ] Add proper error handling for expired/invalid refresh tokens

### Backend - Enhanced Token Response  
- [ ] Update `HostedUIProvider.exchange_code_for_token()` to include `expires_at`
- [ ] Update `/mcp/oauth/callback` HTML response to pass `expires_at` to frontend
- [ ] Ensure all token fields are passed through (id_token, access_token, refresh_token, expires_in, expires_at)

### Frontend - Token Storage & Management
- [ ] Define `MCPTokens` interface with all required fields
- [ ] Update OAuth callback handler to store `expires_at`
- [ ] Implement `isTokenExpiringSoon()` helper function
- [ ] Create `refreshMCPTokens()` function to call backend refresh endpoint
- [ ] Set up automatic token refresh timer (check every 60s)
- [ ] Update active MCP connections with refreshed tokens

### Frontend - Error Handling
- [ ] Handle refresh token expiration (show re-auth prompt)
- [ ] Handle network errors during refresh
- [ ] Show user-friendly error messages
- [ ] Implement re-authentication flow when refresh fails

### Configuration
- [ ] Document required Cognito app client settings
- [ ] Document environment variables (COGNITO_CLIENT_SECRET, COGNITO_DOMAIN)
- [ ] Add token refresh buffer configuration (default: 300s)

---

## Testing Requirements (MCP-Specific)

### Backend Unit Tests
- [ ] Test `HostedUIProvider.refresh_tokens()` with valid refresh token
- [ ] Test refresh with invalid/expired refresh tokens (should return None)
- [ ] Test refresh with client secret authentication
- [ ] Test refresh without client secret (public client)
- [ ] Test `expires_at` calculation is correct
- [ ] Test token refresh endpoint returns proper error codes

### Backend Integration Tests
- [ ] Test `/mcp/oauth/refresh` endpoint with valid refresh token
- [ ] Test endpoint returns 401 when refresh token is expired
- [ ] Test endpoint returns 400 on malformed requests
- [ ] Test token rotation (new refresh token returned by Cognito)
- [ ] Test refresh with various Cognito configurations

### Frontend Unit Tests
- [ ] Test `isTokenExpiringSoon()` with various timestamps
- [ ] Test token storage and retrieval from state
- [ ] Test `refreshMCPTokens()` function with mocked API
- [ ] Test automatic refresh timer triggers correctly
- [ ] Test refresh failure shows re-auth prompt

### E2E Tests
- [ ] Test complete MCP OAuth flow stores tokens with `expires_at`
- [ ] Test tokens are automatically refreshed before expiration
- [ ] Test MCP connection remains active across token refresh
- [ ] Test refresh failure prompts for re-authentication
- [ ] Test user can re-authenticate when refresh token expires

### Edge Cases
- [ ] Network failure during token refresh (should show error, allow retry)
- [ ] Cognito returns error on refresh (invalid_grant, expired token)
- [ ] Multiple browser tabs refreshing tokens simultaneously
- [ ] Token refresh while MCP server is actively being used
- [ ] Clock skew between client/server (token appears expired but isn't)
- [ ] Refresh token rotates (new refresh token returned)
- [ ] Page refresh during active MCP session (tokens persisted?)

---

## Configuration Options (MCP-Specific)

### Environment Variables

```bash
# Required for MCP OAuth
COGNITO_CLIENT_SECRET=your-client-secret     # Optional, only if app client has secret
COGNITO_DOMAIN=your-domain.auth.region.amazoncognito.com  # Optional, auto-detected from discovery URL

# Frontend Configuration (in MCP config)
TOKEN_REFRESH_BUFFER_SECONDS=300    # Refresh 5 min before expiry (default)
```

### Cognito App Client Requirements

In AWS Cognito Console, configure your app client:

1. **OAuth 2.0 Grant Types** - Enable:
   - ✅ Authorization code grant
   - ✅ Refresh token grant

2. **Token Expiration Settings**:
   - ID token expiration: 1 hour (recommended)
   - Access token expiration: 1 hour (recommended)
   - Refresh token expiration: 30 days (or as needed)

3. **Advanced Security Configuration**:
   - Enable refresh token rotation (recommended for better security)
   - This will return a new refresh token with each refresh

4. **OAuth Scopes** - Ensure these are enabled:
   - `openid`
   - `email`
   - `profile`

5. **App Client Type**:
   - Public client: No client secret needed
   - Confidential client: Set `COGNITO_CLIENT_SECRET` env var

---

## Security Considerations (MCP-Specific)

### Token Storage in Frontend
- ⚠️ **Refresh tokens are long-lived** (30 days default) - store securely
- Consider using browser's secure storage (IndexedDB with encryption)
- Never log refresh tokens or expose them in URLs
- Clear all tokens on logout/disconnect
- Consider storing tokens only in memory (more secure, but lost on refresh)

### Refresh Token Rotation
- Cognito can be configured to rotate refresh tokens
- When rotation is enabled, each refresh returns a new refresh token
- **Frontend must update stored refresh token** after each refresh
- Old refresh token becomes invalid after rotation

### API Security
- `/mcp/oauth/refresh` endpoint doesn't require authentication (stateless)
- Rate limit the refresh endpoint to prevent abuse (e.g., 10 requests/min per IP)
- Consider adding CORS restrictions for production
- Log all refresh attempts with client_id for audit trail

### Monitoring & Logging
- Log successful and failed token refresh attempts (backend)
- Monitor refresh token usage patterns
- Alert on anomalies:
  - Rapid refresh attempts (possible token leak)
  - High failure rates (Cognito misconfiguration)
  - Refresh from unexpected IPs (if tracking)

### Fallback Behavior
- If refresh fails → prompt user to re-authenticate
- If refresh token expired → clear stored tokens, show login prompt
- If network error → allow retry with exponential backoff
- If Cognito is unavailable → show error message, allow manual retry

---

## Related Files (MCP-Specific)

### Backend Files to Modify
- `backend/chainlit/server.py` - Add `/mcp/oauth/refresh` endpoint
- `backend/chainlit/oauth_hosted_ui.py` - Add `refresh_tokens()` method, update `exchange_code_for_token()`
- `backend/chainlit/oauth_utils.py` - Token validation (already handles ID tokens)

### Frontend Files to Modify
- `frontend/src/components/chat/MessageComposer/Mcp/AddForm.tsx` - Token storage & refresh logic
- `frontend/src/types/` - Add `MCPTokens` interface (if not exists)

### Files to Reference (No changes needed)
- `backend/chainlit/oauth_token_provider.py` - For reference on Cognito API calls
- `backend/chainlit/mcp.py` - To understand MCP server integration

---

## Documentation Requirements

- [ ] Document `/mcp/oauth/refresh` API endpoint in API docs
- [ ] Add MCP token refresh setup guide for developers
- [ ] Document Cognito app client configuration requirements
- [ ] Add troubleshooting guide for common token refresh issues
- [ ] Document token lifecycle (initial auth → use → refresh → expiration)
- [ ] Add security best practices for token storage in browser
- [ ] Document frontend integration examples

---

## Performance Considerations (MCP-Specific)

### Network Optimization
- Frontend checks expiration locally (no need to hit server)
- Refresh only happens when actually needed (5 min buffer)
- Single refresh request refreshes all tokens at once

### Error Handling
- Implement exponential backoff for refresh retries on network errors
- Avoid refresh request storms (only one refresh per token lifecycle)
- Cache should_refresh check result briefly to avoid repeated calculations

### Monitoring Metrics
- Token refresh success rate (should be >99%)
- Token refresh latency (target: <500ms p95)
- Number of MCP re-authentications (should be minimal)
- Refresh endpoint error rates
- Time saved by avoiding re-authentication flows

---

## Future Enhancements (MCP-Specific)

1. **Token refresh for other MCP auth methods** - Extend beyond Cognito
2. **Persistent token storage** - Store tokens in IndexedDB/localStorage for persistence across page reloads
3. **Multiple MCP servers** - Handle separate tokens for different MCP servers
4. **Token refresh notifications** - Show toast/notification when tokens are refreshed
5. **Advanced monitoring** - Dashboard showing MCP token health status
6. **Automatic reconnection** - Auto-reconnect MCP servers after token refresh

---

## Migration Path for Existing MCP Users

### Phase 1: Deploy Backend Changes (No Breaking Changes)
1. Deploy new `/mcp/oauth/refresh` endpoint
2. Update callback to include `expires_at`
3. Existing MCP connections continue working as before

### Phase 2: Deploy Frontend Changes
1. Update frontend to store `expires_at`
2. Implement automatic refresh logic
3. Existing users get prompted to re-authenticate (one-time)
4. New authentications automatically get refresh support

### Phase 3: User Communication
1. Notify users about improved MCP authentication
2. Document benefits (no more session interruptions)
3. Provide migration guide for developers using MCP

### Phase 4: Monitoring & Iteration
1. Monitor refresh success rates
2. Gather user feedback
3. Address any edge cases discovered
4. Optimize refresh timing if needed

---

## Success Metrics (MCP-Specific)

### Primary Goals
- ✅ MCP connections persist beyond initial token expiration (1 hour)
- ✅ Zero visible re-authentication prompts during active MCP usage
- ✅ Token refresh success rate > 99.5%
- ✅ Seamless MCP server interaction across token refresh

### Performance Targets
- Token refresh latency < 500ms (p95)
- Time to refresh decision < 10ms (local check)
- Zero MCP connection drops due to token refresh
- Reduced OAuth flow invocations (fewer full re-authentications)

### User Experience
- No visible interruption during token refresh
- Clear error messages when refresh fails
- Simple re-authentication flow when refresh token expires

---

## Questions to Resolve

1. **Token Storage**: Where should frontend store tokens? (State, Context, IndexedDB, localStorage?)
   - **Recommendation**: Start with React state, consider IndexedDB for persistence

2. **Refresh Buffer**: What's the appropriate buffer time? (5 min, 10 min, 15 min?)
   - **Recommendation**: 5 minutes (300 seconds) - balances safety and unnecessary refreshes

3. **Multiple MCP Servers**: How to handle tokens for multiple MCP servers?
   - **Consideration**: Store tokens keyed by `client_id` or server identifier

4. **Token Rotation**: How to handle refresh token rotation?
   - **Requirement**: Frontend must update stored refresh token after each refresh

5. **Rate Limiting**: Should `/mcp/oauth/refresh` endpoint be rate limited?
   - **Recommendation**: Yes, 10 requests/minute per IP or token

6. **Active Connections**: Do MCP server connections need to be notified of token refresh?
   - **Consideration**: Depends on how MCP client library handles token updates

---

## References

### AWS Cognito Documentation
- [Cognito Refresh Token](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html#amazon-cognito-user-pools-using-the-refresh-token)
- [Cognito Token Endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html)
- [Using Tokens with User Pools](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens.html)

### OAuth 2.0 Specifications
- [OAuth 2.0 Refresh Token Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-6)
- [OAuth 2.0 Token Endpoint](https://datatracker.ietf.org/doc/html/rfc6749#section-3.2)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)

### Model Context Protocol (MCP)
- [MCP Specification](https://spec.modelcontextprotocol.io/) - For understanding MCP authentication requirements

---

## Appendix: Example Cognito Token Refresh Request

### Request
```http
POST https://your-domain.auth.us-east-1.amazoncognito.com/oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=refresh_token&
client_id=your-client-id&
refresh_token=eyJjdHk...
```

### Response (Success)
```json
{
  "id_token": "eyJraWQ...",
  "access_token": "eyJraWQ...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Response (Refresh Token Rotation Enabled)
```json
{
  "id_token": "eyJraWQ...",
  "access_token": "eyJraWQ...",
  "refresh_token": "eyJjdHk...",  // NEW refresh token
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Response (Error)
```json
{
  "error": "invalid_grant",
  "error_description": "Refresh Token has expired"
}
```

