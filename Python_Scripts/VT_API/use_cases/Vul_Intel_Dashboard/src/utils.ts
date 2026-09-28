import { CveReport, RbvmBreakdown, RbvmConfig } from './types';

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

/**
 * Computes the Risk-Based Vulnerability Management (RBVM) score:
 *   Final Score = (W1 * S_vuln) + (W2 * S_asset) + (W3 * S_threat)
 *
 * Weights are normalized (each divided by their sum) so they always total 1.0,
 * keeping the final score on a 0-100 scale while preserving the user's ratios.
 *
 * Returns null if config.sAsset is null/undefined (so the UI only shows GTI/Mandiant intel),
 * or if all weights are zero (no valid ratio to normalize).
 */
export function calculateRbvmScore(
  report: CveReport,
  config: RbvmConfig
): RbvmBreakdown | null {
  if (config.sAsset === null || config.sAsset === undefined) {
    return null;
  }

  const rawW1 = Math.max(0, config.weights.w1 || 0);
  const rawW2 = Math.max(0, config.weights.w2 || 0);
  const rawW3 = Math.max(0, config.weights.w3 || 0);
  const weightSum = rawW1 + rawW2 + rawW3;
  if (weightSum <= 0) {
    return null;
  }
  const weightsNormalized = Math.abs(weightSum - 1) >= 0.005;
  const effectiveWeights = {
    w1: Math.round((rawW1 / weightSum) * 1000) / 1000,
    w2: Math.round((rawW2 / weightSum) * 1000) / 1000,
    w3: Math.round((rawW3 / weightSum) * 1000) / 1000,
  };

  // 1. S_vuln (0 - 100): CVSS Base Score (v4 prioritized, v3 fallback) * 10
  const sVuln = Math.min(100, Math.max(0, Math.round(((report.cvssScore ?? 0) * 10) * 10) / 10));

  // 2. S_asset (0 - 100): User-provided asset exposure & sensitivity score
  const sAsset = Math.min(100, Math.max(0, Math.round(config.sAsset * 10) / 10));

  // 3. S_threat (0 - 100): GTI Exploitation State + Exploit Availability + EPSS Multiplier
  const expState = (report.exploitPatterns.exploitationState || '').trim().toLowerCase();
  const expAvail = (report.exploitPatterns.exploitAvailability || '').trim().toLowerCase();
  const tags = (report.exploitPatterns.tags || []).map(t => t.toLowerCase());
  const riskFactors = (report.exploitPatterns.riskFactors || []).map(r => r.toLowerCase());
  const v4Maturity = (report.cvssDetails?.cvssv4?.exploitMaturity || '').trim().toLowerCase();
  const riskRating = (report.riskRating || '').trim().toUpperCase();

  let baseThreatTier: 100 | 75 | 25 | 10 = 10;
  let baseThreatReason = 'No known exploitation or exploit availability (Baseline: 10)';

  // Tier 100: Active exploitation in the wild (exploitation_state: 2=Reported, 3=Confirmed, 4=Wide, or CISA KEV)
  if (
    expState === 'wide' ||
    expState === 'confirmed' ||
    expState === 'reported' ||
    Boolean(report.exploitPatterns.cisaKev?.addedDate) ||
    tags.includes('observed_in_the_wild') ||
    tags.includes('was_zero_day') ||
    v4Maturity === 'attacked' ||
    report.exploitPatterns.exploitedInTheWild
  ) {
    baseThreatTier = 100;
    if (expState === 'wide' || expState === 'confirmed' || expState === 'reported') {
      baseThreatReason = `GTI Exploitation State: ${report.exploitPatterns.exploitationState} (Tier: 100)`;
    } else if (report.exploitPatterns.cisaKev?.addedDate) {
      baseThreatReason = 'Listed in CISA KEV Catalog (Tier: 100)';
    } else {
      baseThreatReason = 'Active exploitation observed in the wild (Tier: 100)';
    }
  }
  // Tier 75: Weaponized / PoC / Functional Exploit (exploit_availability: 2=Privately Held, 3=Publicly available, 4=Trivial)
  else if (
    expAvail === 'trivial' ||
    expAvail === 'publicly available' ||
    expAvail === 'privately held' ||
    riskFactors.some(r => r.includes('trivial to exploit')) ||
    tags.includes('has_exploits') ||
    v4Maturity === 'poc' ||
    report.exploitPatterns.pocAvailable
  ) {
    baseThreatTier = 75;
    if (report.exploitPatterns.exploitAvailability && expAvail !== 'no known') {
      baseThreatReason = `GTI Exploit Availability: ${report.exploitPatterns.exploitAvailability} (Tier: 75)`;
    } else {
      baseThreatReason = 'Public PoC or functional exploit available (Tier: 75)';
    }
  }
  // Tier 25: Theoretical / Early Signal (exploitation_state: 1=Suspected, exploit_availability: 1=Unverified/Interest Observed, or High/Critical GTI rating)
  else if (
    expState === 'suspected' ||
    expAvail.includes('unverified') ||
    expAvail.includes('interest observed') ||
    riskRating === 'CRITICAL' ||
    riskRating === 'HIGH'
  ) {
    baseThreatTier = 25;
    if (expState === 'suspected') {
      baseThreatReason = 'GTI Exploitation State: Suspected (Tier: 25)';
    } else if (expAvail.includes('unverified') || expAvail.includes('interest observed')) {
      baseThreatReason = `GTI Exploit Availability: ${report.exploitPatterns.exploitAvailability} (Tier: 25)`;
    } else {
      baseThreatReason = `GTI Risk Rating: ${riskRating} with theoretical exploitability (Tier: 25)`;
    }
  }

  // EPSS Multiplier
  const epss = report.epssScore ?? 0;
  let epssMultiplier: 1.0 | 1.1 | 1.25 | 1.5 = 1.0;
  if (epss > 0.75) {
    epssMultiplier = 1.5;
  } else if (epss > 0.50) {
    epssMultiplier = 1.25;
  } else if (epss > 0.25) {
    epssMultiplier = 1.1;
  }

  const tierTimesMultiplier = baseThreatTier * epssMultiplier;
  const epssTimes100 = epss * 100;
  const epssFloorApplied = epssTimes100 > tierTimesMultiplier;
  const sThreat = Math.min(
    100,
    Math.max(0, Math.round(Math.max(tierTimesMultiplier, epssTimes100) * 10) / 10)
  );

  const rawFinal = (rawW1 * sVuln + rawW2 * sAsset + rawW3 * sThreat) / weightSum;
  const finalScore = Math.min(100, Math.max(0, Math.round(rawFinal * 10) / 10));

  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
  if (finalScore >= 80) {
    riskLevel = 'CRITICAL';
  } else if (finalScore >= 60) {
    riskLevel = 'HIGH';
  } else if (finalScore >= 35) {
    riskLevel = 'MEDIUM';
  }

  return {
    finalScore,
    sVuln,
    sAsset,
    sThreat,
    baseThreatTier,
    baseThreatReason,
    epssMultiplier,
    epssFloorApplied,
    weights: effectiveWeights,
    weightsNormalized,
    riskLevel,
  };
}

