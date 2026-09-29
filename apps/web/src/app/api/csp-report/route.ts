/**
 * CSP violation report endpoint.
 *
 * Receives Content-Security-Policy violation reports from the browser and logs them.
 * The report body is never echoed back to prevent information leakage.
 *
 * This endpoint is called automatically when the CSP-Report-Only header is present
 * and a violation occurs. The browser sends a JSON report with details about what
 * was blocked and why.
 *
 * See docs/CSP.md for monitoring guidance.
 */

import { withRoute } from '../../../lib/api-route';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

interface CspViolationReport {
  'csp-report': {
    'document-uri': string;
    'referrer': string;
    'violated-directive': string;
    'effective-directive': string;
    'original-policy': string;
    'disposition': string;
    'blocked-uri': string;
    'line-number'?: number;
    'column-number'?: number;
    'source-file'?: string;
    'status-code'?: number;
    'script-sample'?: string;
  };
}

export const POST = withRoute('POST /api/csp-report', async (req: Request): Promise<Response> => {
  try {
    const body = (await req.json()) as CspViolationReport;
    const report = body['csp-report'];

    // Log the violation for monitoring (never echo the body in the response)
    console.error(
      '[CSP Violation]',
      {
        directive: report['violated-directive'],
        effectiveDirective: report['effective-directive'],
        blockedUri: report['blocked-uri'],
        documentUri: report['document-uri'],
        sourceFile: report['source-file'],
        lineNumber: report['line-number'],
        columnNumber: report['column-number'],
      },
    );

    // Return 204 No Content - success without echoing any data
    return new Response(null, { status: 204 });
  } catch (err) {
    // If parsing fails, still return 204 to avoid leaking error details
    console.error('[CSP Report] Failed to parse violation report', err);
    return new Response(null, { status: 204 });
  }
});
