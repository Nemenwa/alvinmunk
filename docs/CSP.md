# Content-Security-Policy (CSP) Deployment Guide

## Overview

The alvinmunk dApp uses a Content-Security-Policy (CSP) as a second line of defense against XSS attacks. Since the client handles real money (USDC rewards, tips, treasury operations) and interacts with wallets, a CSP is critical for security.

## Implementation Phases

### Phase 1: Report-Only Mode (Current)

The CSP is deployed in report-only mode via the `Content-Security-Policy-Report-Only` header. This allows us to:

- Monitor violations without blocking any functionality
- Ensure all wallet providers (Freighter, Albedo, Stellar Wallets Kit, passkey) work correctly
- Verify the policy covers all necessary origins
- Collect data for a week before enforcing

**Current status**: Deployed in `next.config.mjs` with `getCspPolicyFromEnv(false)`.

### Phase 2: Enforcing Mode (Follow-up)

After a clean week in production with no violations from legitimate flows, switch to enforcing mode:

1. Change `next.config.mjs`:
   ```js
   const cspPolicy = getCspPolicyFromEnv(true); // was false
   ```
2. Change the header key:
   ```js
   { key: 'Content-Security-Policy', value: cspPolicy }
   ```
3. Deploy to preview first, then production

**TODO**: Document the exact date and commit when this switch happens.

## Policy Structure

The policy is built in `src/lib/csp.ts` from environment variables:

- **connect-src**: RPC, Horizon, Friendbot, Anchor domains, Vercel Analytics
- **script-src**: `'self' 'unsafe-inline'` (Next.js bootstrap requires inline scripts)
- **worker-src**: `'self'` (for service workers)
- **frame-src**: `'none'` (no frames allowed)
- **object-src**: `'none'` (no plugins)
- **base-uri**: `'self'` (restrict base tag)
- **form-action**: `'self'` (restrict form submissions)
- **frame-ancestors**: `'none'` (prevent framing)

### Environment Variables

The policy reads these variables from `process.env`:

- `NEXT_PUBLIC_RPC_URL`: Stellar Soroban RPC endpoint
- `NEXT_PUBLIC_HORIZON_URL`: Stellar Horizon endpoint
- `NEXT_PUBLIC_ANCHOR_HOME_DOMAIN`: Anchor home domain (optional)
- `NEXT_PUBLIC_ANCHOR_TRANSFER_SERVER`: Anchor transfer server (optional)

## Violation Reporting

Violations are reported to `/api/csp-report` via POST. The endpoint:

- Logs violations to console with relevant details (directive, blocked URI, document URI)
- Returns 204 No Content (never echoes the report body to prevent information leakage)
- Is safe to expose publicly (no secrets in the response)

### Monitoring

Monitor Vercel logs or your logging provider for:

```
[CSP Violation] { directive: '...', blockedUri: '...', documentUri: '...', ... }
```

### Common Violations

**Legitimate violations to expect during Phase 1:**

- None from wallet flows (Freighter, Albedo, passkey)
- None from claim page URL fragment reading (client-side only)
- None from Vercel Analytics or Speed Insights

**If you see unexpected violations:**

1. Check if the blocked URI is a legitimate third-party resource
2. If yes, add its origin to the appropriate directive in `src/lib/csp.ts`
3. If no, investigate potential XSS or injection

## Testing

Unit tests are in `src/lib/csp.test.ts`:

```bash
cd apps/web
npm test -- csp.test.ts
```

Tests verify:

- All required directives are present
- Origins are correctly extracted from URLs
- Invalid URLs are handled gracefully
- Environment variables are read correctly
- Policy structure matches expectations

## Security Considerations

### Why CSP Matters

The dApp handles:

- Wallet signatures for transactions
- Passkey credentials (WebAuthn)
- Claim secrets from URL fragments (client-side only)
- Real money operations (USDC rewards, tips, treasury)

Without CSP, an injected script could:

- Read claim secrets from `window.location.hash`
- Request wallet signatures from connected wallets
- Exfiltrate sensitive data

### Current Limitations

- **script-src uses 'unsafe-inline'**: Required for Next.js inline bootstrap scripts. Phase 2 should move to nonce-based script-src via middleware.
- **No nonce support yet**: Future work to tighten script-src further.

### Defense in Depth

CSP is the second line of defense. The first line is:

- Input validation and sanitization
- Secure coding practices
- Regular security audits (see `docs/SECURITY_REVIEW.md`)

## Rollback Procedure

If enforcing mode breaks legitimate functionality:

1. Revert to report-only mode in `next.config.mjs`
2. Deploy the fix immediately
3. Investigate the violation in logs
4. Update the policy if needed
5. Re-deploy enforcing mode after verification

## References

- [MDN: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
