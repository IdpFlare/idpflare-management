/**
 * @idpflare/management
 * Management API types
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * Configuration for the management client
 */
export interface ManagementClientConfig {
    /**
     * The base URL of your IDPFlare instance
     * @example "https://auth.example.com"
     */
    authority: string;

    /**
     * API key for authentication (starts with 'idk_')
     */
    apiKey: string;
}

// ============================================================================
// USER MANAGEMENT
// ============================================================================

/**
 * User object returned by management API
 */
export interface User {
    id: string;
    email: string;
    email_verified: boolean;
    given_name: string | null;
    family_name: string | null;
    picture_url: string | null;
    locale: string;
    roles: string[];
    mfa_enabled: boolean;
    is_active: boolean;
    is_locked: boolean;
    failed_login_attempts: number;
    locked_until: number | null;
    metadata: Record<string, unknown> | null;
    created_at: number;
    updated_at: number;
    last_login_at: number | null;
    email_verified_at: number | null;
}

/**
 * Request body for creating a user
 */
export interface CreateUserRequest {
    email: string;
    password?: string;
    given_name?: string;
    family_name?: string;
    picture_url?: string;
    locale?: string;
    email_verified?: boolean;
    roles?: string[];
    is_active?: boolean;
    metadata?: Record<string, unknown>;
}

/**
 * Request body for updating a user
 */
export interface UpdateUserRequest {
    email?: string;
    given_name?: string;
    family_name?: string;
    picture_url?: string;
    locale?: string;
    email_verified?: boolean;
    roles?: string[];
    is_active?: boolean;
    is_locked?: boolean;
    mfa_enabled?: boolean;
    metadata?: Record<string, unknown>;
}

/**
 * Query options for listing users
 */
export interface ListUsersOptions {
    limit?: number;
    offset?: number;
    search?: string;
    role?: string;
    is_active?: boolean;
    email_verified?: boolean;
}

/**
 * Paginated response for users
 */
export interface PaginatedUsers {
    users: User[];
    total: number;
    limit: number;
    offset: number;
}

// ============================================================================
// USER SESSIONS
// ============================================================================

/**
 * User session object
 */
export interface UserSession {
    id: string;
    user_id: string;
    ip_address: string | null;
    user_agent: string | null;
    country: string | null;
    city: string | null;
    is_active: boolean;
    expires_at: number;
    created_at: number;
    last_activity_at: number;
}

// ============================================================================
// USER MFA
// ============================================================================

/**
 * MFA enrollment for a user
 */
export interface MfaEnrollment {
    method: string;
    is_enabled: boolean;
    is_primary: boolean;
    created_at: number;
    last_used_at: number | null;
}

// ============================================================================
// USER IDENTITIES (SOCIAL CONNECTIONS)
// ============================================================================

/**
 * Social identity/connection for a user
 */
export interface SocialIdentity {
    id: string;
    provider: string;
    provider_user_id: string;
    provider_email: string | null;
    created_at: number;
    updated_at: number;
}

// ============================================================================
// USER TOKENS
// ============================================================================

/**
 * Refresh token for a user
 */
export interface RefreshToken {
    id: string;
    client_id: string;
    scope: string;
    is_revoked: boolean;
    expires_at: number;
    ip_address: string | null;
    user_agent: string | null;
    created_at: number;
}

// ============================================================================
// API KEYS
// ============================================================================

/**
 * API key object
 */
export interface ApiKey {
    id: string;
    name: string;
    key_prefix: string;
    scopes: string[];
    created_by: string;
    is_active: boolean;
    last_used_at: number | null;
    expires_at: number | null;
    created_at: number;
}

/**
 * Request body for creating an API key
 */
export interface CreateApiKeyRequest {
    name: string;
    scopes?: string[];
}

/**
 * Response from creating an API key (includes raw key)
 */
export interface CreateApiKeyResponse {
    api_key: ApiKey;
    /** The raw API key - only returned once, store securely */
    raw_key: string;
}

// ============================================================================
// OAUTH CLIENTS
// ============================================================================

/**
 * OAuth client object
 */
export interface OAuthClient {
    id: string;
    name: string;
    description: string | null;
    logo_url: string | null;
    is_confidential: boolean;
    is_first_party: boolean;
    redirect_uris: string[];
    allowed_origins: string[] | null;
    post_logout_redirect_uris: string[] | null;
    allowed_grant_types: string[];
    allowed_scopes: string[];
    default_scopes: string[] | null;
    access_token_ttl: number;
    refresh_token_ttl: number;
    id_token_ttl: number;
    require_pkce: boolean;
    is_active: boolean;
    metadata: Record<string, unknown> | null;
    created_at: number;
    updated_at: number;
}

/**
 * Request body for creating an OAuth client
 */
export interface CreateClientRequest {
    name: string;
    description?: string;
    logo_url?: string;
    is_confidential?: boolean;
    is_first_party?: boolean;
    redirect_uris: string[];
    allowed_origins?: string[];
    post_logout_redirect_uris?: string[];
    allowed_grant_types?: string[];
    allowed_scopes?: string[];
    default_scopes?: string[];
    access_token_ttl?: number;
    refresh_token_ttl?: number;
    id_token_ttl?: number;
    require_pkce?: boolean;
    metadata?: Record<string, unknown>;
}

/**
 * Request body for updating an OAuth client
 */
export interface UpdateClientRequest {
    name?: string;
    description?: string;
    logo_url?: string;
    is_first_party?: boolean;
    redirect_uris?: string[];
    allowed_origins?: string[];
    post_logout_redirect_uris?: string[];
    allowed_grant_types?: string[];
    allowed_scopes?: string[];
    default_scopes?: string[];
    access_token_ttl?: number;
    refresh_token_ttl?: number;
    id_token_ttl?: number;
    require_pkce?: boolean;
    is_active?: boolean;
    metadata?: Record<string, unknown>;
}

/**
 * Paginated response for OAuth clients
 */
export interface PaginatedClients {
    clients: OAuthClient[];
    total: number;
    limit: number;
    offset: number;
}

// ============================================================================
// AUDIT LOGS
// ============================================================================

/**
 * Audit log entry
 */
export interface AuditLogEntry {
    id: string;
    user_id: string | null;
    client_id: string | null;
    event_type: string;
    status: "success" | "failure";
    ip_address: string | null;
    user_agent: string | null;
    country: string | null;
    city: string | null;
    details: Record<string, unknown> | null;
    created_at: number;
}

/**
 * Query options for audit logs
 */
export interface AuditLogQueryOptions {
    limit?: number;
    offset?: number;
    user_id?: string;
    client_id?: string;
    event_type?: string;
    status?: "success" | "failure";
    start_date?: number;
    end_date?: number;
}

/**
 * Paginated response for audit logs
 */
export interface PaginatedAuditLogs {
    entries: AuditLogEntry[];
    total: number;
    limit: number;
    offset: number;
}

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * User statistics
 */
export interface UserStats {
    total: number;
    active: number;
    verified: number;
    mfa_enabled: number;
    admins?: number;
}

// ============================================================================
// API ERROR
// ============================================================================

/**
 * Error response from the API
 */
export interface ApiError {
    error: string;
    status?: number;
}

/**
 * Error thrown by management client
 */
export class ManagementApiError extends Error {
    constructor(
        message: string,
        public status: number,
        public response?: unknown
    ) {
        super(message);
        this.name = "ManagementApiError";
    }
}
