/**
 * Unit tests for CSP policy generation.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { buildCspPolicy, getCspHeader, getCspHeaderName } from './csp';

describe('CSP policy builder', () => {
  beforeEach(() => {
    // Clear environment variables before each test
    delete process.env.NEXT_PUBLIC_RPC_URL;
    delete process.env.NEXT_PUBLIC_HORIZON_URL;
    delete process.env.NEXT_PUBLIC_ANCHOR_HOME_DOMAIN;
    delete process.env.NEXT_PUBLIC_ANCHOR_TRANSFER_SERVER;
  });

  describe('buildCspPolicy', () => {
    it('builds a basic policy with minimal config', () => {
      const policy = buildCspPolicy({});
      expect(policy).toContain("connect-src 'self'");
      expect(policy).toContain("script-src 'self' 'unsafe-inline'");
      expect(policy).toContain("worker-src 'self'");
      expect(policy).toContain("frame-ancestors 'none'");
      expect(policy).toContain("object-src 'none'");
      expect(policy).toContain("base-uri 'self'");
      expect(policy).toContain("form-action 'self'");
    });

    it('includes RPC origin when provided', () => {
      const policy = buildCspPolicy({ rpcUrl: 'https://soroban-testnet.stellar.org' });
      expect(policy).toContain('https://soroban-testnet.stellar.org');
    });

    it('includes Horizon origin when provided', () => {
      const policy = buildCspPolicy({ horizonUrl: 'https://horizon-testnet.stellar.org' });
      expect(policy).toContain('https://horizon-testnet.stellar.org');
    });

    it('includes Friendbot by default', () => {
      const policy = buildCspPolicy({});
      expect(policy).toContain('https://friendbot.stellar.org');
    });

    it('includes anchor origins when provided', () => {
      const policy = buildCspPolicy({
        anchorHomeDomain: 'https://anchor.example.com',
        anchorTransferServer: 'https://transfer.anchor.example.com',
      });
      expect(policy).toContain('https://anchor.example.com');
      expect(policy).toContain('https://transfer.anchor.example.com');
    });

    it('handles URLs with paths by extracting origin only', () => {
      const policy = buildCspPolicy({
        rpcUrl: 'https://soroban-testnet.stellar.org/rpc',
        horizonUrl: 'https://horizon-testnet.stellar.org/horizon',
      });
      expect(policy).toContain('https://soroban-testnet.stellar.org');
      expect(policy).toContain('https://horizon-testnet.stellar.org');
      expect(policy).not.toContain('/rpc');
      expect(policy).not.toContain('/horizon');
    });

    it('ignores invalid URLs gracefully', () => {
      const policy = buildCspPolicy({
        rpcUrl: 'not-a-valid-url',
        horizonUrl: 'also-invalid',
      });
      expect(policy).toContain("connect-src 'self'");
      expect(policy).toContain('https://friendbot.stellar.org');
      expect(policy).not.toContain('not-a-valid-url');
      expect(policy).not.toContain('also-invalid');
    });

    it('includes report-uri when reportEndpoint is provided', () => {
      const policy = buildCspPolicy({ reportEndpoint: '/api/csp-report' });
      expect(policy).toContain('report-uri /api/csp-report');
      expect(policy).toContain('report-to csp-endpoint');
    });

    it('omits reporting directives when reportEndpoint is empty', () => {
      const policy = buildCspPolicy({ reportEndpoint: '' });
      expect(policy).not.toContain('report-uri');
      expect(policy).not.toContain('report-to');
    });

    it('uses environment variables when config not provided', () => {
      process.env.NEXT_PUBLIC_RPC_URL = 'https://custom-rpc.example.com';
      process.env.NEXT_PUBLIC_HORIZON_URL = 'https://custom-horizon.example.com';
      const policy = buildCspPolicy({});
      expect(policy).toContain('https://custom-rpc.example.com');
      expect(policy).toContain('https://custom-horizon.example.com');
    });

    it('config overrides environment variables', () => {
      process.env.NEXT_PUBLIC_RPC_URL = 'https://env-rpc.example.com';
      const policy = buildCspPolicy({ rpcUrl: 'https://config-rpc.example.com' });
      expect(policy).toContain('https://config-rpc.example.com');
      expect(policy).not.toContain('https://env-rpc.example.com');
    });

    it('produces a valid CSP string format', () => {
      const policy = buildCspPolicy({});
      // CSP directives are separated by semicolons
      const directives = policy.split(';').map((d) => d.trim());
      expect(directives.length).toBeGreaterThan(0);
      // Each directive should have a name and value
      directives.forEach((directive) => {
        const [name, ...values] = directive.split(' ');
        expect(name).toBeTruthy();
        expect(values.length).toBeGreaterThan(0);
      });
    });
  });

  describe('getCspHeaderName', () => {
    it('returns report-only header name when reportOnly is true', () => {
      const name = getCspHeaderName(true);
      expect(name).toBe('Content-Security-Policy-Report-Only');
    });

    it('returns enforcing header name when reportOnly is false', () => {
      const name = getCspHeaderName(false);
      expect(name).toBe('Content-Security-Policy');
    });

    it('defaults to report-only mode', () => {
      const name = getCspHeaderName();
      expect(name).toBe('Content-Security-Policy-Report-Only');
    });
  });

  describe('getCspHeader', () => {
    it('returns a header object with correct structure', () => {
      const header = getCspHeader();
      expect(header).toHaveProperty('name');
      expect(header).toHaveProperty('value');
      expect(typeof header.name).toBe('string');
      expect(typeof header.value).toBe('string');
    });

    it('uses report-only mode by default', () => {
      const header = getCspHeader();
      expect(header.name).toBe('Content-Security-Policy-Report-Only');
    });

    it('uses enforcing mode when reportOnly is false', () => {
      const header = getCspHeader({ reportOnly: false });
      expect(header.name).toBe('Content-Security-Policy');
    });

    it('passes config through to buildCspPolicy', () => {
      const header = getCspHeader({
        rpcUrl: 'https://custom.example.com',
        reportOnly: false,
      });
      expect(header.value).toContain('https://custom.example.com');
      expect(header.name).toBe('Content-Security-Policy');
    });
  });

  describe('security directives', () => {
    const securityDirectives = [
      { name: 'frame-ancestors', value: "'none'" },
      { name: 'object-src', value: "'none'" },
      { name: 'base-uri', value: "'self'" },
      { name: 'form-action', value: "'self'" },
    ];

    securityDirectives.forEach(({ name, value }) => {
      it(`always includes restrictive ${name} ${value}`, () => {
        const policy = buildCspPolicy({});
        expect(policy).toContain(`${name} ${value}`);
      });
    });
  });
});
