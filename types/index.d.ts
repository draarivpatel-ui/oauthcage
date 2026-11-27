export type OAuthPolicyName = 'strict' | 'spa' | 'confidential' | 'native';
export type OAuthCageSeverity = 'info' | 'warning' | 'error' | 'critical';

export interface OAuthPolicy {
  readonly name: OAuthPolicyName;
  readonly allowLoopbackHttp: boolean;
  readonly allowLocalhostHttp: boolean;
  readonly allowCustomSchemes: boolean;
  readonly allowedRedirectSchemes: readonly string[];
  readonly allowedCustomSchemes: readonly string[];
  readonly requirePkce: boolean;
  readonly allowedPkceMethods: readonly string[];
  readonly requireState: boolean;
  readonly minStateLength: number;
  readonly minNonceLength: number;
  readonly requireIssuerInCallback: boolean;
  readonly requireRedirectAllowlist: boolean;
  readonly requirePar: boolean;
  readonly allowClientSecret: boolean;
  readonly allowedResponseTypes: readonly string[];
  readonly allowedGrantTypes: readonly string[];
  readonly maxUriLength: number;
  readonly maxParameterCount: number;
  readonly maxParameterLength: number;
  readonly maxInputLength: number;
  readonly minAuthorizationCodeLength: number;
  readonly maxAuthorizationCodeLength: number;
  readonly allowedEndpointPorts: readonly string[];
  readonly allowEndpointQueries: boolean;
  readonly maxDiscoveryBytes: number;
  readonly maxDiscoveryDepth: number;
  readonly maxDiscoveryKeys: number;
  readonly requireS256InDiscovery: boolean;
  readonly requireAsymmetricIdTokenAlgorithms: boolean;
}

export interface OAuthPolicyOverrides {
  readonly allowLoopbackHttp?: boolean;
  readonly allowLocalhostHttp?: boolean;
  readonly allowCustomSchemes?: boolean;
  readonly allowedRedirectSchemes?: readonly string[];
  readonly allowedCustomSchemes?: readonly string[];
  readonly requirePkce?: boolean;
  readonly allowedPkceMethods?: readonly string[];
  readonly requireState?: boolean;
  readonly minStateLength?: number;
  readonly minNonceLength?: number;
  readonly requireIssuerInCallback?: boolean;
  readonly requireRedirectAllowlist?: boolean;
  readonly requirePar?: boolean;
  readonly allowClientSecret?: boolean;
  readonly allowedResponseTypes?: readonly string[];
  readonly allowedGrantTypes?: readonly string[];
  readonly maxUriLength?: number;
  readonly maxParameterCount?: number;
  readonly maxParameterLength?: number;
  readonly maxInputLength?: number;
  readonly minAuthorizationCodeLength?: number;
  readonly maxAuthorizationCodeLength?: number;
  readonly allowedEndpointPorts?: readonly string[];
  readonly allowEndpointQueries?: boolean;
  readonly maxDiscoveryBytes?: number;
  readonly maxDiscoveryDepth?: number;
  readonly maxDiscoveryKeys?: number;
  readonly requireS256InDiscovery?: boolean;
  readonly requireAsymmetricIdTokenAlgorithms?: boolean;
}

export interface OAuthCageFinding {
  readonly code: string;
  readonly severity: OAuthCageSeverity;
  readonly message: string;
  readonly field: string;
}

export interface AuditBaseResult {
  readonly kind: string;
  readonly policy: OAuthPolicyName;
  readonly ok: boolean;
  readonly findings: readonly OAuthCageFinding[];
}

export interface RedirectMeta {
  readonly scheme: string;
  readonly customScheme: boolean;
  readonly hasAuthority: boolean;
  readonly hostKind: 'ipv4' | 'ipv6' | 'domain' | null;
  readonly loopback: boolean;
  readonly port: string | null;
  readonly hasQuery: boolean;
}

export interface RedirectAuditResult extends AuditBaseResult {
  readonly uri: string | null;
  readonly matched: boolean;
  readonly matchedUri: string | null;
  readonly meta: RedirectMeta | null;
}

export interface AuthRequestAuditResult extends AuditBaseResult {
  readonly flow: 'authorization_code' | null;
  readonly usesPar: boolean;
  readonly hasPkce: boolean;
  readonly hasState: boolean;
}

export interface CallbackAuditResult extends AuditBaseResult {
  readonly errorResponse: boolean;
  readonly hasCode: boolean;
  readonly hasIssuer: boolean;
  readonly hasState: boolean;
}

export interface TokenRequestAuditResult extends AuditBaseResult {
  readonly grantType: string | null;
  readonly usesPkce: boolean;
  readonly usesClientSecret: boolean;
}

export interface EndpointAuditResult extends AuditBaseResult {
  readonly canonical: string | null;
  readonly hostKind: 'ipv4' | 'ipv6' | 'domain' | null;
  readonly ipScope: string | null;
  readonly tunnel: string | null;
  readonly port: string;
}

export interface DiscoveryAuditResult extends AuditBaseResult {
  readonly issuerMatches: boolean;
  readonly requiredEndpointsPresent: boolean;
  readonly endpointsAudited: number;
}

export type RegisteredRedirectUris = string | readonly string[];
export type OAuthParameterInput = string | Readonly<Record<string, string | readonly string[]>>;

export interface PolicyOption {
  readonly policy?: OAuthPolicyName | OAuthPolicy;
}

export interface RedirectAuditOptions extends PolicyOption {
  readonly registeredRedirectUris?: RegisteredRedirectUris;
  readonly allowLoopbackHttp?: boolean;
  readonly allowLocalhostHttp?: boolean;
  readonly allowCustomSchemes?: boolean;
  readonly allowedCustomSchemes?: readonly string[];
  readonly maxUriLength?: number;
}

export interface ScopeAuditOptions {
  readonly allowedScopes?: readonly string[];
  readonly deniedScopes?: readonly string[];
  readonly requestedScope?: string;
  readonly expectedScope?: string;
}

export interface AuthRequestAuditOptions extends PolicyOption, ScopeAuditOptions {
  readonly registeredRedirectUris?: RegisteredRedirectUris;
}

export interface CallbackAuditOptions extends PolicyOption, ScopeAuditOptions {
  readonly expectedState?: string;
  readonly expectedIssuer?: string;
  readonly referer?: string;
  readonly referrer?: string;
}

export interface TokenRequestAuditOptions extends PolicyOption, ScopeAuditOptions {
  readonly registeredRedirectUris?: RegisteredRedirectUris;
  readonly expectedCodeChallenge?: string;
  readonly codeChallengeMethod?: string;
}

export interface EndpointAuditOptions extends PolicyOption {}

export interface DiscoveryAuditOptions extends PolicyOption {
  readonly expectedIssuer?: string;
}

export interface PkcePair {
  readonly verifier: string;
  readonly challenge: string;
  readonly method: 'S256';
}

export interface TokenLengthOptions {
  readonly minStateLength?: number;
  readonly minNonceLength?: number;
}

export interface OAuthCageErrorOptions {
  readonly field?: string;
  readonly cause?: unknown;
}

export class OAuthCageError extends Error {
  readonly code: string;
  readonly detail: string;
  readonly field?: string;
  constructor(code: string, detail: string, options?: OAuthCageErrorOptions);
  toJSON(): {
    readonly name: string;
    readonly code: string;
    readonly detail: string;
    readonly field?: string;
  };
}

export const OAUTHCAGE_VERSION: string;
export const OAUTHCAGE_ERROR_CODES: Readonly<Record<string, string>>;
export const OAUTHCAGE_SEVERITY: Readonly<{
  INFO: 'info';
  WARNING: 'warning';
  ERROR: 'error';
  CRITICAL: 'critical';
}>;
export const CODE: Readonly<Record<string, string>>;
export const OAUTHCAGE_POLICY_PRESETS: Readonly<Record<OAuthPolicyName, OAuthPolicy>>;

export function createOAuthPolicy(base?: OAuthPolicyName | OAuthPolicyOverrides, overrides?: OAuthPolicyOverrides): OAuthPolicy;
export function getPolicy(name?: OAuthPolicyName): OAuthPolicy;
export function auditRedirectUri(candidate: string, registeredRedirectUris: RegisteredRedirectUris, options?: RedirectAuditOptions): RedirectAuditResult;
export function validateRedirectUri(candidate: string, registeredRedirectUris: RegisteredRedirectUris, options?: RedirectAuditOptions): string;
export function createPkcePair(): PkcePair;
export function verifyPkce(verifier: string, challenge: string, method?: string, policy?: OAuthPolicy): true;
export function generateState(): string;
export function generateNonce(): string;
export function verifyState(expected: string, actual: string, options?: TokenLengthOptions): true;
export function verifyNonce(expected: string, actual: string, options?: TokenLengthOptions): true;
export function auditAuthRequest(input: OAuthParameterInput, options?: AuthRequestAuditOptions): AuthRequestAuditResult;
export function auditCallback(input: OAuthParameterInput, options?: CallbackAuditOptions): CallbackAuditResult;
export function auditTokenRequest(input: OAuthParameterInput, options?: TokenRequestAuditOptions): TokenRequestAuditResult;
export function auditEndpointUrl(endpoint: string, options?: EndpointAuditOptions): EndpointAuditResult;
export function auditDiscoveryMetadata(input: string | Readonly<Record<string, unknown>>, options?: DiscoveryAuditOptions): DiscoveryAuditResult;
export function neutralizeTerminal(text: string): string;
export function redactSensitiveText(text: string): string;

declare const oauthcage: Readonly<{
  OAUTHCAGE_VERSION: typeof OAUTHCAGE_VERSION;
  OAUTHCAGE_ERROR_CODES: typeof OAUTHCAGE_ERROR_CODES;
  OAUTHCAGE_SEVERITY: typeof OAUTHCAGE_SEVERITY;
  CODE: typeof CODE;
  OAuthCageError: typeof OAuthCageError;
  OAUTHCAGE_POLICY_PRESETS: typeof OAUTHCAGE_POLICY_PRESETS;
  createOAuthPolicy: typeof createOAuthPolicy;
  getPolicy: typeof getPolicy;
  auditRedirectUri: typeof auditRedirectUri;
  validateRedirectUri: typeof validateRedirectUri;
  createPkcePair: typeof createPkcePair;
  verifyPkce: typeof verifyPkce;
  generateState: typeof generateState;
  generateNonce: typeof generateNonce;
  verifyState: typeof verifyState;
  verifyNonce: typeof verifyNonce;
  auditAuthRequest: typeof auditAuthRequest;
  auditCallback: typeof auditCallback;
  auditTokenRequest: typeof auditTokenRequest;
  auditEndpointUrl: typeof auditEndpointUrl;
  auditDiscoveryMetadata: typeof auditDiscoveryMetadata;
  neutralizeTerminal: typeof neutralizeTerminal;
  redactSensitiveText: typeof redactSensitiveText;
}>;

export default oauthcage;
