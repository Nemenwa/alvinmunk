/**
 * CSP violation report endpoint.
 *
 * Receives Content-Security-Policy violation reports from the browser and logs them.
 * The report body is never echoed back to prevent information leakage.
 *
 * This endpoint is called by the browser when a CSP violation occurs, as specified
 * by the report-uri or report-to directives in the CSP header.
 *
 * Expected body format (CSP Level 3):
 * {
 *   "csp-report": {
 *     "document-uri": "...",
 *     "referrer": "...",
 *     "violated-directive": "...",
 *     "effective-directive": "...",
 *     "original-policy": "...",
 *     "disposition": "report" | "enforce",
 *     "blocked-uri": "...",
 *     "line-number": ...,
 *     "column-number": ...,
 *     "source-file": "...",
 *     "status-code": ...,
 *     "script-sample": "..."
 *   }
 * }
 */

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

interface CspReport {
  'document-uri'?: string;
  referrer?: string;
  'violated-directive': string;
  'effective-directive'?: string;
  'original-policy'?: string;
  disposition?: 'report' | 'enforce';
  'blocked-uri'?: string;
  'line-number'?: number;
  'column-number'?: number;
  'source-file'?: string;
  'status-code'?: number;
  'script-sample'?: string;
}

interface CspReportBody {
  'csp-report': CspReport;
}

/**
 * Log a CSP violation to stderr with a structured format for log aggregation.
 */
function logViolation(report: CspReport): void {
  const logEntry = {
    timestamp: new Date().toISOString(),
    type: 'csp-violation',
    violatedDirective: report['violated-directive'],
    effectiveDirective: report['effective-directive'] || report['violated-directive'],
    blockedUri: report['blocked-uri'] || '(none)',
    documentUri: report['document-uri'] || '(none)',
    sourceFile: report['source-file'] || '(none)',
    lineNumber: report['line-number'] ?? null,
    columnNumber: report['column-number'] ?? null,
    disposition: report.disposition || 'unknown',
  };

  // Log to stderr for server-side logging (Vercel, etc.)
  console.error(JSON.stringify(logEntry));
}

export async function POST(request: Request): Promise<Response> {
  try {
    const body = (await request.json()) as CspReportBody;
    const report = body['csp-report'];

    if (!report) {
      // Malformed report - log but don't fail
      console.error('CSP report received without csp-report body');
      return new Response(null, { status: 204 });
    }

    logViolation(report);

    // Return 204 No Content - we've logged it, no need to send anything back
    // Never echo the report body to prevent information leakage
    return new Response(null, { status: 204 });
  } catch (error) {
    // If JSON parsing fails, log the error but don't fail the request
    // This prevents attackers from flooding logs with malformed reports
    console.error('Failed to parse CSP report:', error instanceof Error ? error.message : String(error));
    return new Response(null, { status: 204 });
  }
}
