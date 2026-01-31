/**
 * @idpflare/management
 * Management API Client
 */

import type {
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
} from "./types";
import { ManagementApiError } from "./types";

/**
 * IDPFlare Management API Client
 * Provides typed methods for all management API operations
 */
export class IdPFlareManagementClient {
    private readonly authority: string;
    private readonly apiKey: string;

    constructor(config: ManagementClientConfig) {
        this.authority = config.authority.replace(/\/$/, "");
        this.apiKey = config.apiKey;
    }

    // ============================================================================
    // PRIVATE HELPERS
    // ============================================================================

    private async request<T>(
        method: string,
        path: string,
        body?: unknown,
        query?: Record<string, string | number | boolean | undefined>
    ): Promise<T> {
        const url = new URL(`${this.authority}/api/v1${path}`);

        if (query) {
            Object.entries(query).forEach(([key, value]) => {
                if (value !== undefined) {
                    url.searchParams.set(key, String(value));
                }
            });
        }

        const response = await fetch(url.toString(), {
            method,
            headers: {
                Authorization: `Bearer ${this.apiKey}`,
                "Content-Type": "application/json",
            },
            body: body ? JSON.stringify(body) : undefined,
        });

        if (!response.ok) {
            let errorMessage = `Request failed with status ${response.status}`;
            try {
                const errorBody = await response.json();
                if (errorBody.error) {
                    errorMessage = errorBody.error;
                }
            } catch {
                // Ignore JSON parse errors
            }
            throw new ManagementApiError(errorMessage, response.status);
        }

        // Handle 204 No Content
        if (response.status === 204) {
            return undefined as T;
        }

        return response.json();
    }

    // ============================================================================
    // USER MANAGEMENT
    // ============================================================================

    /**
     * List users with pagination and filtering
     */
    async listUsers(options: ListUsersOptions = {}): Promise<PaginatedUsers> {
        return this.request<PaginatedUsers>("GET", "/users", undefined, {
            limit: options.limit,
            offset: options.offset,
            search: options.search,
            role: options.role,
            is_active: options.is_active,
            email_verified: options.email_verified,
        });
    }

    /**
     * Get a single user by ID
     */
    async getUser(userId: string): Promise<User> {
        return this.request<User>("GET", `/users/${userId}`);
    }

    /**
     * Create a new user
     */
    async createUser(request: CreateUserRequest): Promise<User> {
        return this.request<User>("POST", "/users", request);
    }

    /**
     * Update an existing user
     */
    async updateUser(userId: string, request: UpdateUserRequest): Promise<User> {
        return this.request<User>("PATCH", `/users/${userId}`, request);
    }

    /**
     * Delete a user
     */
    async deleteUser(userId: string): Promise<void> {
        await this.request<void>("DELETE", `/users/${userId}`);
    }

    /**
     * Update a user's password
     */
    async updateUserPassword(userId: string, password: string): Promise<void> {
        await this.request<void>("PUT", `/users/${userId}/password`, { password });
    }

    /**
     * Block a user account
     */
    async blockUser(userId: string, reason?: string): Promise<void> {
        await this.request<void>("POST", `/users/${userId}/block`, { reason });
    }

    /**
     * Unblock a user account
     */
    async unblockUser(userId: string): Promise<void> {
        await this.request<void>("POST", `/users/${userId}/unblock`);
    }

    // ============================================================================
    // USER SESSIONS
    // ============================================================================

    /**
     * List active sessions for a user
     */
    async listUserSessions(userId: string): Promise<UserSession[]> {
        const response = await this.request<{ sessions: UserSession[] }>(
            "GET",
            `/users/${userId}/sessions`
        );
        return response.sessions;
    }

    /**
     * Revoke a specific session
     */
    async revokeUserSession(userId: string, sessionId: string): Promise<void> {
        await this.request<void>(
            "DELETE",
            `/users/${userId}/sessions/${sessionId}`
        );
    }

    /**
     * Revoke all sessions for a user
     */
    async revokeAllUserSessions(
        userId: string
    ): Promise<{ sessions_revoked: number }> {
        return this.request<{ sessions_revoked: number }>(
            "DELETE",
            `/users/${userId}/sessions`
        );
    }

    // ============================================================================
    // USER MFA
    // ============================================================================

    /**
     * Get MFA enrollments for a user
     */
    async getUserMfaEnrollments(userId: string): Promise<MfaEnrollment[]> {
        const response = await this.request<{ enrollments: MfaEnrollment[] }>(
            "GET",
            `/users/${userId}/mfa`
        );
        return response.enrollments;
    }

    /**
     * Reset MFA for a user
     * @param method Optional specific MFA method to reset, or all if omitted
     */
    async resetUserMfa(userId: string, method?: string): Promise<void> {
        await this.request<void>("DELETE", `/users/${userId}/mfa`, undefined, {
            method,
        });
    }

    // ============================================================================
    // USER IDENTITIES (SOCIAL CONNECTIONS)
    // ============================================================================

    /**
     * List social connections for a user
     */
    async listUserIdentities(userId: string): Promise<SocialIdentity[]> {
        const response = await this.request<{ identities: SocialIdentity[] }>(
            "GET",
            `/users/${userId}/identities`
        );
        return response.identities;
    }

    /**
     * Unlink a social connection from a user
     */
    async unlinkUserIdentity(
        userId: string,
        identityId: string
    ): Promise<void> {
        await this.request<void>(
            "DELETE",
            `/users/${userId}/identities/${identityId}`
        );
    }

    // ============================================================================
    // USER TOKENS
    // ============================================================================

    /**
     * List refresh tokens for a user
     */
    async listUserTokens(userId: string): Promise<RefreshToken[]> {
        const response = await this.request<{ tokens: RefreshToken[] }>(
            "GET",
            `/users/${userId}/tokens`
        );
        return response.tokens;
    }

    /**
     * Revoke all refresh tokens for a user
     */
    async revokeAllUserTokens(
        userId: string
    ): Promise<{ tokens_revoked: number }> {
        return this.request<{ tokens_revoked: number }>(
            "DELETE",
            `/users/${userId}/tokens`
        );
    }

    // ============================================================================
    // API KEYS
    // ============================================================================

    /**
     * List API keys
     */
    async listApiKeys(
        options: { limit?: number; offset?: number; active_only?: boolean } = {}
    ): Promise<ApiKey[]> {
        const response = await this.request<{ api_keys: ApiKey[] }>(
            "GET",
            "/api-keys",
            undefined,
            {
                limit: options.limit,
                offset: options.offset,
                active_only: options.active_only,
            }
        );
        return response.api_keys;
    }

    /**
     * Create a new API key
     * @returns The created API key including the raw key (only returned once)
     */
    async createApiKey(request: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
        return this.request<CreateApiKeyResponse>("POST", "/api-keys", request);
    }

    /**
     * Revoke an API key
     */
    async revokeApiKey(keyId: string): Promise<void> {
        await this.request<void>("DELETE", `/api-keys/${keyId}`);
    }

    // ============================================================================
    // OAUTH CLIENTS
    // ============================================================================

    /**
     * List OAuth clients with pagination
     */
    async listClients(
        options: { limit?: number; offset?: number; is_active?: boolean } = {}
    ): Promise<PaginatedClients> {
        return this.request<PaginatedClients>("GET", "/clients", undefined, {
            limit: options.limit,
            offset: options.offset,
            is_active: options.is_active,
        });
    }

    /**
     * Get a single OAuth client by ID
     */
    async getClient(clientId: string): Promise<OAuthClient> {
        return this.request<OAuthClient>("GET", `/clients/${clientId}`);
    }

    /**
     * Create a new OAuth client
     * @returns The created client and client_secret (for confidential clients)
     */
    async createClient(
        request: CreateClientRequest
    ): Promise<{ client: OAuthClient; client_secret?: string }> {
        return this.request<{ client: OAuthClient; client_secret?: string }>(
            "POST",
            "/clients",
            request
        );
    }

    /**
     * Update an OAuth client
     */
    async updateClient(
        clientId: string,
        request: UpdateClientRequest
    ): Promise<OAuthClient> {
        return this.request<OAuthClient>("PATCH", `/clients/${clientId}`, request);
    }

    /**
     * Delete an OAuth client
     */
    async deleteClient(clientId: string): Promise<void> {
        await this.request<void>("DELETE", `/clients/${clientId}`);
    }

    /**
     * Rotate the client secret for a confidential client
     */
    async rotateClientSecret(
        clientId: string
    ): Promise<{ client_secret: string }> {
        return this.request<{ client_secret: string }>(
            "POST",
            `/clients/${clientId}/rotate-secret`
        );
    }

    // ============================================================================
    // AUDIT LOGS
    // ============================================================================

    /**
     * Query audit logs with filters
     */
    async queryAuditLogs(
        options: AuditLogQueryOptions = {}
    ): Promise<PaginatedAuditLogs> {
        return this.request<PaginatedAuditLogs>("GET", "/audit-logs", undefined, {
            limit: options.limit,
            offset: options.offset,
            user_id: options.user_id,
            client_id: options.client_id,
            event_type: options.event_type,
            status: options.status,
            start_date: options.start_date,
            end_date: options.end_date,
        });
    }

    /**
     * Get audit logs for a specific user
     */
    async getUserAuditLogs(
        userId: string,
        options: { limit?: number; offset?: number } = {}
    ): Promise<{ entries: AuditLogEntry[]; total: number }> {
        return this.request<{ entries: AuditLogEntry[]; total: number }>(
            "GET",
            `/audit-logs/user/${userId}`,
            undefined,
            {
                limit: options.limit,
                offset: options.offset,
            }
        );
    }

    /**
     * Get recent security events for a user
     */
    async getUserSecurityEvents(
        userId: string,
        limit?: number
    ): Promise<AuditLogEntry[]> {
        const response = await this.request<{ entries: AuditLogEntry[] }>(
            "GET",
            `/audit-logs/user/${userId}/security`,
            undefined,
            { limit }
        );
        return response.entries;
    }

    // ============================================================================
    // STATISTICS
    // ============================================================================

    /**
     * Get user statistics
     */
    async getUserStats(): Promise<UserStats> {
        return this.request<UserStats>("GET", "/stats/users");
    }
}

/**
 * Create a new management client instance
 */
export function createManagementClient(
    config: ManagementClientConfig
): IdPFlareManagementClient {
    return new IdPFlareManagementClient(config);
}
