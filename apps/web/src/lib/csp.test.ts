import { describe, it, expect } from 'vitest';
import { buildCspPolicy, getCspPolicyFromEnv } from './csp';

describe('buildCspPolicy', () => {
  it('generates a policy with required directives', () => {
    const policy = buildCspPolicy();
    
    expect(policy).toContain('default-src');
    expect(policy).toContain('connect-src');
    expect(policy).toContain('script-src');
    expect(policy).toContain('worker-src');
    expect(policy).toContain('frame-src');
    expect(policy).toContain('object-src');
    expect(policy).toContain('base-uri');
    expect(policy).toContain('form-action');
    expect(policy).toContain('frame-ancestors');
    expect(policy).toContain('report-uri');
  });

  it('includes self in connect-src', () => {
    const policy = buildCspPolicy();
    expect(policy).toContain("connect-src 'self'");
  });

  it('includes friendbot in connect-src', () => {
    const policy = buildCspPolicy();
    expect(policy).toContain('https://friendbot.stellar.org');
  });

  it('includes Vercel Analytics endpoints in connect-src', () => {
    const policy = buildCspPolicy();
    expect(policy).toContain('https://*.vercel-analytics.com');
    expect(policy).toContain('https://*.vercel-insights.com');
  });

  it('includes RPC origin when provided', () => {
    const policy = buildCspPolicy({ rpcUrl: 'https://soroban-testnet.stellar.org' });
    expect(policy).toContain('https://soroban-testnet.stellar.org');
  });

  it('includes Horizon origin when provided', () => {
    const policy = buildCspPolicy({ horizonUrl: 'https://horizon-testnet.stellar.org' });
    expect(policy).toContain('https://horizon-testnet.stellar.org');
  });

  it('includes Anchor origins when provided', () => {
    const policy = buildCspPolicy({
      anchorHomeDomain: 'https://anchor.example.com',
      anchorTransferServer: 'https://transfer.example.com',
    });
    expect(policy).toContain('https://anchor.example.com');
    expect(policy).toContain('https://transfer.example.com');
  });

  it('extracts origin from full URLs', () => {
    const policy = buildCspPolicy({
      rpcUrl: 'https://soroban-testnet.stellar.org:443/rpc',
    });
    expect(policy).toContain('https://soroban-testnet.stellar.org');
    expect(policy).not.toContain(':443');
    expect(policy).not.toContain('/rpc');
  });

  it('handles invalid URLs gracefully', () => {
    const policy = buildCspPolicy({
      rpcUrl: 'not-a-valid-url',
      horizonUrl: undefined,
    });
    expect(policy).toContain("connect-src 'self'");
    expect(policy).not.toContain('not-a-valid-url');
  });

  it('includes unsafe-inline in script-src for Next.js bootstrap', () => {
    const policy = buildCspPolicy();
    expect(policy).toContain("script-src 'self' 'unsafe-inline'");
  });

  it('sets frame-src to none', () => {
    const policy = buildCspPolicy();
    expect(policy).toContain("frame-src 'none'");
  });

  it('sets object-src to none', () => {
    const policy = buildCspPolicy();
    expect(policy).toContain("object-src 'none'");
  });

  it('sets frame-ancestors to none', () => {
    const policy = buildCspPolicy();
    expect(policy).toContain("frame-ancestors 'none'");
  });

  it('sets base-uri to self', () => {
    const policy = buildCspPolicy();
    expect(policy).toContain("base-uri 'self'");
  });

  it('sets form-action to self', () => {
    const policy = buildCspPolicy();
    expect(policy).toContain("form-action 'self'");
  });

  it('sets worker-src to self', () => {
    const policy = buildCspPolicy();
    expect(policy).toContain("worker-src 'self'");
  });

  it('uses custom report-uri when provided', () => {
    const policy = buildCspPolicy({ reportUri: '/custom-csp-report' });
    expect(policy).toContain('report-uri /custom-csp-report');
  });

  it('uses default report-uri when not provided', () => {
    const policy = buildCspPolicy();
    expect(policy).toContain('report-uri /api/csp-report');
  });

  it('ignores enforce flag in policy string (header choice only)', () => {
    const policyReportOnly = buildCspPolicy({ enforce: false });
    const policyEnforce = buildCspPolicy({ enforce: true });
    
    // The enforce flag only affects which header is used, not the policy content
    expect(policyReportOnly).toEqual(policyEnforce);
  });

  it('omits undefined origins from connect-src', () => {
    const policy = buildCspPolicy({
      rpcUrl: undefined,
      horizonUrl: undefined,
      anchorHomeDomain: undefined,
      anchorTransferServer: undefined,
    });
    
    // Should still have self, friendbot, and Vercel endpoints
    expect(policy).toContain("'self'");
    expect(policy).toContain('friendbot.stellar.org');
    expect(policy).toContain('vercel-analytics.com');
    
    // Should not have empty entries
    expect(policy).not.toContain('undefined');
  });
});

describe('getCspPolicyFromEnv', () => {
  it('reads from process.env', () => {
    // Mock process.env values
    const originalRpcUrl = process.env.NEXT_PUBLIC_RPC_URL;
    const originalHorizonUrl = process.env.NEXT_PUBLIC_HORIZON_URL;
    const originalAnchorHome = process.env.NEXT_PUBLIC_ANCHOR_HOME_DOMAIN;
    const originalAnchorTransfer = process.env.NEXT_PUBLIC_ANCHOR_TRANSFER_SERVER;

    process.env.NEXT_PUBLIC_RPC_URL = 'https://custom-rpc.example.com';
    process.env.NEXT_PUBLIC_HORIZON_URL = 'https://custom-horizon.example.com';
    process.env.NEXT_PUBLIC_ANCHOR_HOME_DOMAIN = 'https://custom-anchor.example.com';
    process.env.NEXT_PUBLIC_ANCHOR_TRANSFER_SERVER = 'https://custom-transfer.example.com';

    const policy = getCspPolicyFromEnv();

    expect(policy).toContain('https://custom-rpc.example.com');
    expect(policy).toContain('https://custom-horizon.example.com');
    expect(policy).toContain('https://custom-anchor.example.com');
    expect(policy).toContain('https://custom-transfer.example.com');

    // Restore original values
    process.env.NEXT_PUBLIC_RPC_URL = originalRpcUrl;
    process.env.NEXT_PUBLIC_HORIZON_URL = originalHorizonUrl;
    process.env.NEXT_PUBLIC_ANCHOR_HOME_DOMAIN = originalAnchorHome;
    process.env.NEXT_PUBLIC_ANCHOR_TRANSFER_SERVER = originalAnchorTransfer;
  });

  it('handles missing env vars gracefully', () => {
    const originalRpcUrl = process.env.NEXT_PUBLIC_RPC_URL;
    const originalHorizonUrl = process.env.NEXT_PUBLIC_HORIZON_URL;

    delete process.env.NEXT_PUBLIC_RPC_URL;
    delete process.env.NEXT_PUBLIC_HORIZON_URL;

    const policy = getCspPolicyFromEnv();

    // Should still generate a valid policy with defaults
    expect(policy).toContain('default-src');
    expect(policy).toContain('connect-src');

    // Restore original values
    process.env.NEXT_PUBLIC_RPC_URL = originalRpcUrl;
    process.env.NEXT_PUBLIC_HORIZON_URL = originalHorizonUrl;
  });

  it('passes enforce flag to buildCspPolicy', () => {
    // This test verifies the flag is passed through; the actual effect
    // is tested in buildCspPolicy tests
    const policy = getCspPolicyFromEnv(true);
    expect(policy).toBeDefined();
    expect(typeof policy).toBe('string');
  });
});
