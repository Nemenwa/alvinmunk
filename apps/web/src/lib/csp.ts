/**
 * Content-Security-Policy builder for the alvinmunk web client.
 *
 * The CSP is a critical second line of defense for a dApp that handles wallet
 * transactions, passkey credentials, and claim secrets. This pure function
 * builds the policy string from environment variables, making it testable and
 * ensuring the policy stays in sync with what the client actually loads.
 *
 * Rollout plan (see docs/SECURITY_REVIEW.md follow-up):
 * 1. Report-only mode: Content-Security-Policy-Report-Only header
 * 2. Monitor for violations for a week in preview + production
 * 3. Switch to enforcing mode: Content-Security-Policy header
 * 4. Add nonce-based script-src via middleware (future work)
 */

export interface CspConfig {
  /** The RPC URL for Soroban (NEXT_PUBLIC_RPC_URL) */
  rpcUrl?: string;
  /** The Horizon URL for Stellar (NEXT_PUBLIC_HORIZON_URL) */
  horizonUrl?: string;
  /** Anchor home domain (NEXT_PUBLIC_ANCHOR_HOME_DOMAIN) */
  anchorHomeDomain?: string;
  /** Anchor transfer server (NEXT_PUBLIC_ANCHOR_TRANSFER_SERVER) */
  anchorTransferServer?: string;
  /** Whether to use report-only mode (true) or enforcing mode (false) */
  reportOnly?: boolean;
  /** Report-to endpoint for CSP violations */
  reportEndpoint?: string;
}

/**
 * Extract the origin (scheme + host) from a URL.
 * Returns the origin if valid, otherwise undefined.
 */
function extractOrigin(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const parsed = new URL(url);
    return parsed.origin;
  } catch {
    return undefined;
  }
}

/**
 * Build a CSP policy string from the given configuration.
 *
 * The policy includes:
 * - connect-src: self, RPC, Horizon, Friendbot, Anchor domains
 * - script-src: self, unsafe-inline (for Next.js bootstrap scripts)
 * - worker-src: self (for service workers)
 * - frame-ancestors: none (prevent clickjacking)
 * - object-src: none (prevent plugins)
 * - base-uri: self
 * - form-action: self
 * - report-uri / report-to: violation reporting endpoint (if reportEndpoint provided)
 */
export function buildCspPolicy(config: CspConfig = {}): string {
  const {
    rpcUrl = process.env.NEXT_PUBLIC_RPC_URL,
    horizonUrl = process.env.NEXT_PUBLIC_HORIZON_URL,
    anchorHomeDomain = process.env.NEXT_PUBLIC_ANCHOR_HOME_DOMAIN,
    anchorTransferServer = process.env.NEXT_PUBLIC_ANCHOR_TRANSFER_SERVER,
    reportOnly = true,
    reportEndpoint = '/api/csp-report',
  } = config;

  // Extract origins from URLs
  const rpcOrigin = extractOrigin(rpcUrl);
  const horizonOrigin = extractOrigin(horizonUrl);
  const anchorHomeOrigin = extractOrigin(anchorHomeDomain);
  const anchorTransferOrigin = extractOrigin(anchorTransferServer);

  // Build connect-src: self + all Stellar/Anchor origins + Friendbot
  const connectSources = [
    "'self'",
    rpcOrigin,
    horizonOrigin,
    'https://friendbot.stellar.org',
    anchorHomeOrigin,
    anchorTransferOrigin,
  ]
    .filter(Boolean)
    .join(' ');

  // Build script-src: self + unsafe-inline (required for Next.js inline bootstrap scripts)
  // TODO: migrate to nonce-based script-src via middleware
  const scriptSources = "'self' 'unsafe-inline'";

  // Build worker-src: self (for service workers like sw.js)
  const workerSources = "'self'";

  // Build other restrictive directives
  const frameAncestors = "'none'";
  const objectSources = "'none'";
  const baseUri = "'self'";
  const formAction = "'self'";

  // Assemble the policy
  const directives = [
    `connect-src ${connectSources}`,
    `script-src ${scriptSources}`,
    `worker-src ${workerSources}`,
    `frame-ancestors ${frameAncestors}`,
    `object-src ${objectSources}`,
    `base-uri ${baseUri}`,
    `form-action ${formAction}`,
  ];

  // Add reporting directives if endpoint is provided
  if (reportEndpoint) {
    directives.push(`report-uri ${reportEndpoint}`);
    // report-to is the newer standard, but report-uri is still widely supported
    directives.push(`report-to csp-endpoint`);
  }

  return directives.join('; ');
}

/**
 * Get the CSP header name based on report-only mode.
 */
export function getCspHeaderName(reportOnly: boolean = true): string {
  return reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
}

/**
 * Get the full CSP header object for Next.js config.
 */
export function getCspHeader(config: CspConfig = {}): { name: string; value: string } {
  const { reportOnly = true } = config;
  return {
    name: getCspHeaderName(reportOnly),
    value: buildCspPolicy(config),
  };
}
