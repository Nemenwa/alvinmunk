/**
 * Content-Security-Policy builder for the alvinmunk dApp.
 *
 * This pure function generates a CSP policy from environment variables, making it
 * testable and ensuring the policy reflects the actual origins the app connects to.
 *
 * Phase 1: Report-only mode (Content-Security-Policy-Report-Only)
 * Phase 2: Enforcing mode (Content-Security-Policy) after a clean week in production
 *
 * See docs/CSP.md for deployment guidance.
 */

export interface CspConfig {
  /** The RPC URL for Stellar Soroban (NEXT_PUBLIC_RPC_URL) */
  rpcUrl?: string;
  /** The Horizon URL for Stellar (NEXT_PUBLIC_HORIZON_URL) */
  horizonUrl?: string;
  /** Anchor home domain (NEXT_PUBLIC_ANCHOR_HOME_DOMAIN) */
  anchorHomeDomain?: string;
  /** Anchor transfer server (NEXT_PUBLIC_ANCHOR_TRANSFER_SERVER) */
  anchorTransferServer?: string;
  /** Report endpoint for CSP violations */
  reportUri?: string;
  /** Whether to generate an enforcing policy (false = report-only) */
  enforce?: boolean;
}

/**
 * Extract the origin (scheme + host + port) from a URL.
 * Returns undefined if the input is not a valid URL.
 */
function getOrigin(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url);
    return u.origin;
  } catch {
    return undefined;
  }
}

/**
 * Build a CSP policy string from the given configuration.
 *
 * The policy is designed for a dApp that:
 * - Connects to Stellar RPC and Horizon endpoints
 * - Uses wallet extensions (Freighter, Albedo, Stellar Wallets Kit)
 * - Uses passkey/WebAuthn for wallet onboarding
 * - Reads claim secrets from URL fragments (no server exposure)
 * - Uses Vercel Analytics and Speed Insights
 *
 * @param config - CSP configuration from environment variables
 * @returns CSP policy string suitable for use in a header
 */
export function buildCspPolicy(config: CspConfig = {}): string {
  const {
    rpcUrl,
    horizonUrl,
    anchorHomeDomain,
    anchorTransferServer,
    reportUri = '/api/csp-report',
    enforce = false,
  } = config;

  // Extract origins from URLs
  const rpcOrigin = getOrigin(rpcUrl);
  const horizonOrigin = getOrigin(horizonUrl);
  const anchorHomeOrigin = getOrigin(anchorHomeDomain);
  const anchorTransferOrigin = getOrigin(anchorTransferServer);

  // Build connect-src: WebSocket and fetch targets
  const connectSources = [
    "'self'",
    rpcOrigin,
    horizonOrigin,
    'https://friendbot.stellar.org',
    anchorHomeOrigin,
    anchorTransferOrigin,
    // Vercel Analytics
    'https://*.vercel-analytics.com',
    'https://*.vercel-insights.com',
  ]
    .filter(Boolean)
    .join(' ');

  // Build script-src: inline scripts needed for Next.js bootstrap
  // TODO: Move to nonce-based script-src in Phase 2 via middleware
  const scriptSources = ["'self'", "'unsafe-inline'"].join(' ');

  // Build default-src: fallback for most directives
  const defaultSources = "'self'";

  // Build worker-src: for service workers (sw.js)
  const workerSources = "'self'";

  // Build frame-src: no frames allowed
  const frameSources = "'none'";

  // Build object-src: no plugins allowed
  const objectSources = "'none'";

  // Build base-uri: restrict base tag
  const baseUri = "'self'";

  // Build form-action: restrict form submissions
  const formAction = "'self'";

  // Build frame-ancestors: prevent framing
  const frameAncestors = "'none'";

  // Build report-uri: where to send violation reports
  const reportTo = reportUri;

  // Assemble the full policy
  const directives = [
    `default-src ${defaultSources}`,
    `connect-src ${connectSources}`,
    `script-src ${scriptSources}`,
    `worker-src ${workerSources}`,
    `frame-src ${frameSources}`,
    `object-src ${objectSources}`,
    `base-uri ${baseUri}`,
    `form-action ${formAction}`,
    `frame-ancestors ${frameAncestors}`,
    `report-uri ${reportTo}`,
  ];

  return directives.join('; ');
}

/**
 * Generate the CSP policy from process.env (for use in next.config.mjs).
 * This function reads the actual environment variables at build time.
 */
export function getCspPolicyFromEnv(enforce = false): string {
  return buildCspPolicy({
    rpcUrl: process.env.NEXT_PUBLIC_RPC_URL,
    horizonUrl: process.env.NEXT_PUBLIC_HORIZON_URL,
    anchorHomeDomain: process.env.NEXT_PUBLIC_ANCHOR_HOME_DOMAIN,
    anchorTransferServer: process.env.NEXT_PUBLIC_ANCHOR_TRANSFER_SERVER,
    enforce,
  });
}
