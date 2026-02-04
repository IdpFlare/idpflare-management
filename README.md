# @idpflare/management


**[Website](https://idpflare.com) | [GitHub](https://github.com/IdpFlare)**

Management API client for [IDPFlare](https://idpflare.com). Provides typed TypeScript functions for admin operations including user management, API keys, OAuth clients, audit logs, and statistics.

## Installation

```bash
npm install @idpflare/management
```

## Quick Start

```typescript
import { createManagementClient } from '@idpflare/management';

const management = createManagementClient({
  authority: 'https://auth.example.com',
  apiKey: 'idk_your_api_key_here',
});
```

## API Reference

### User Management

```typescript
// List users with pagination and filtering
const { users, total } = await management.listUsers({
  limit: 50,
  offset: 0,
  search: 'john@',
  role: 'admin',
  is_active: true,
  email_verified: true,
});

// Get a single user
const user = await management.getUser('user_id');

// Create a user
const newUser = await management.createUser({
  email: 'user@example.com',
  password: 'SecurePassword123!',
  given_name: 'John',
  family_name: 'Doe',
  roles: ['user'],
  email_verified: true,
});

// Update a user
const updated = await management.updateUser('user_id', {
  given_name: 'Jane',
  roles: ['admin'],
});

// Delete a user
await management.deleteUser('user_id');

// Update password
await management.updateUserPassword('user_id', 'newPassword123!');

// Block/unblock user
await management.blockUser('user_id', 'Suspicious activity');
await management.unblockUser('user_id');
```

### User Sessions

```typescript
// List sessions
const sessions = await management.listUserSessions('user_id');

// Revoke a session
await management.revokeUserSession('user_id', 'session_id');

// Revoke all sessions
const { sessions_revoked } = await management.revokeAllUserSessions('user_id');
```

### User MFA

```typescript
// Get MFA enrollments
const enrollments = await management.getUserMfaEnrollments('user_id');

// Reset MFA (all methods or specific)
await management.resetUserMfa('user_id');
await management.resetUserMfa('user_id', 'totp');
```

### User Identities (Social Connections)

```typescript
// List social connections
const identities = await management.listUserIdentities('user_id');

// Unlink a connection
await management.unlinkUserIdentity('user_id', 'identity_id');
```

### User Tokens

```typescript
// List refresh tokens
const tokens = await management.listUserTokens('user_id');

// Revoke all tokens
const { tokens_revoked } = await management.revokeAllUserTokens('user_id');
```

### API Keys

```typescript
// List API keys
const apiKeys = await management.listApiKeys({
  limit: 50,
  active_only: true,
});

// Create an API key
const { api_key, raw_key } = await management.createApiKey({
  name: 'Backend Service',
  scopes: ['users:read', 'users:write'],
});
// ⚠️ Store raw_key securely - it's only returned once!

// Revoke an API key
await management.revokeApiKey('key_id');
```

### OAuth Clients

```typescript
// List clients
const { clients, total } = await management.listClients({
  limit: 50,
  is_active: true,
});

// Get a client
const client = await management.getClient('client_id');

// Create a client
const { client: newClient, client_secret } = await management.createClient({
  name: 'My Application',
  redirect_uris: ['https://myapp.com/callback'],
  allowed_grant_types: ['authorization_code', 'refresh_token'],
  allowed_scopes: ['openid', 'profile', 'email'],
  require_pkce: true,
});

// Update a client
const updated = await management.updateClient('client_id', {
  name: 'Updated Name',
  redirect_uris: ['https://myapp.com/callback', 'https://myapp.com/auth'],
});

// Delete a client
await management.deleteClient('client_id');

// Rotate client secret
const { client_secret: newSecret } = await management.rotateClientSecret('client_id');
```

### Audit Logs

```typescript
// Query audit logs
const { entries, total } = await management.queryAuditLogs({
  limit: 100,
  event_type: 'login_success',
  status: 'success',
  start_date: Date.now() - 86400000, // Last 24 hours
});

// Get logs for a specific user
const userLogs = await management.getUserAuditLogs('user_id', {
  limit: 50,
});

// Get security events for a user
const securityEvents = await management.getUserSecurityEvents('user_id', 10);
```

### Statistics

```typescript
// Get user statistics
const stats = await management.getUserStats();
// { total: 1000, active: 950, verified: 800, mfa_enabled: 300 }
```

## Error Handling

```typescript
import { ManagementApiError } from '@idpflare/management';

try {
  await management.getUser('nonexistent');
} catch (error) {
  if (error instanceof ManagementApiError) {
    console.log(error.message); // "User not found"
    console.log(error.status);  // 404
  }
}
```

## Scopes

API keys require appropriate scopes for each operation:

| Scope | Operations |
|-------|------------|
| `users:read` | List users, get user, sessions, MFA, identities, tokens |
| `users:write` | Create/update users, password, block/unblock, revoke sessions/MFA/identities |
| `users:delete` | Delete users |
| `api-keys:read` | List API keys |
| `api-keys:write` | Create API keys |
| `api-keys:delete` | Revoke API keys |
| `clients:read` | List/get OAuth clients |
| `clients:write` | Create/update clients, rotate secret |
| `clients:delete` | Delete OAuth clients |
| `audit:read` | Query audit logs |
| `stats:read` | Get statistics |

## License

Polyform Strict 1.0.0
