/**
 * Sanitizes dynamic URLs to prevent javascript: protocol execution.
 * Only http: and https: protocols are permitted. Returns '#' as a safe fallback.
 */
export function sanitizeUrl(urlStr: string | undefined | null): string {
  if (!urlStr) return '#';
  try {
    const trimmed = urlStr.trim();
    // Validate if it is a absolute URL with safe protocols
    const url = new URL(trimmed);
    if (url.protocol === 'http:' || url.protocol === 'https:') {
      return trimmed;
    }
  } catch (_) {
    // If URL parsing fails, permit safe relative paths
    if (urlStr.startsWith('/') || urlStr.startsWith('./') || urlStr.startsWith('../')) {
      return urlStr;
    }
  }
  return '#';
}
