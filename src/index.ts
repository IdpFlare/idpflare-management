/**
 * @idpflare/management
 * Management API client library for IDPFlare
 *
 * @example
 * ```typescript
 * import { createManagementClient } from '@idpflare/management';
 *
 * const management = createManagementClient({
 *   authority: 'https://auth.example.com',
 *   apiKey: 'idk_your_api_key_here',
 * });
 *
 * // List users
 * const { users, total } = await management.listUsers({ limit: 10 });
 *
 * // Create a user
 * const newUser = await management.createUser({
 *   email: 'user@example.com',
 *   password: 'SecurePassword123!',
 * });
 * ```
 */

// Client
export { IdPFlareManagementClient, createManagementClient } from "./client";

// Types
export type {
    ManagementClientConfig,
    User,
    CreateUserRequest,
    UpdateUserRequest,
    ListUsersOptions,
    PaginatedUsers,
    UserSession,
    MfaEnrollment,
    SocialIdentity,
    RefreshToken,
    ApiKey,
    CreateApiKeyRequest,
    CreateApiKeyResponse,
    OAuthClient,
    CreateClientRequest,
    UpdateClientRequest,
    PaginatedClients,
    AuditLogEntry,
    AuditLogQueryOptions,
    PaginatedAuditLogs,
    UserStats,
    ApiError,
} from "./types";

// Error class
export { ManagementApiError } from "./types";
