import React from 'react';
import { CveReport, RbvmBreakdown } from '../types';
import { Shield, ShieldAlert, AlertTriangle, Info, CheckCircle, Database, Gauge } from 'lucide-react';

interface CveMetricsProps {
  report: CveReport;
  rbvmBreakdown?: RbvmBreakdown | null;
}

const severityConfigs = {
  LOW: { color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', icon: CheckCircle },
  MEDIUM: { color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20', icon: Info },
  HIGH: { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20', icon: AlertTriangle },
  CRITICAL: { color: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/20', icon: ShieldAlert }
};

// Parse both CVSS v4.0 and CVSS v3.x vectors to human-readable strings
function parseCvssVector(vectorStr: string) {
  if (!vectorStr) return [];
  const isV4 = vectorStr.toUpperCase().startsWith('CVSS:4');
  const parts = vectorStr.split('/');
  const metrics: { key: string; label: string; value: string; desc: string }[] = [];

  const v3Mapping: Record<string, { label: string; values: Record<string, { val: string; desc: string }> }> = {
    AV: {
      label: 'Attack Vector',
      values: {
        N: { val: 'Network', desc: 'Exploitable remotely over network' },
        A: { val: 'Adjacent', desc: 'Requires shared physical or logical network' },
        L: { val: 'Local', desc: 'Requires local system access' },
        P: { val: 'Physical', desc: 'Requires physical interaction with hardware' }
      }
    },
    AC: {
      label: 'Attack Complexity',
      values: {
        L: { val: 'Low', desc: 'No specialized access conditions required' },
        H: { val: 'High', desc: 'Successful attack depends on conditions beyond attacker control' }
      }
    },
    PR: {
      label: 'Privileges Required',
      values: {
        N: { val: 'None', desc: 'No privileges required prior to attack' },
        L: { val: 'Low', desc: 'Requires basic user capabilities' },
        H: { val: 'High', desc: 'Requires administrative privileges' }
      }
    },
    UI: {
      label: 'User Interaction',
      values: {
        N: { val: 'None', desc: 'System can be exploited without user interaction' },
        R: { val: 'Required', desc: 'Requires user to take action before exploit succeeds' }
      }
    },
    S: {
      label: 'Scope',
      values: {
        U: { val: 'Unchanged', desc: 'Impact limited to the vulnerable component' },
        C: { val: 'Changed', desc: 'Impact can affect resources beyond vulnerable component' }
      }
    },
    C: {
      label: 'Confidentiality',
      values: {
        N: { val: 'None', desc: 'No loss of confidentiality' },
        L: { val: 'Low', desc: 'Some restricted information disclosure' },
        H: { val: 'High', desc: 'Total loss of confidentiality' }
      }
    },
    I: {
      label: 'Integrity',
      values: {
        N: { val: 'None', desc: 'No loss of integrity' },
        L: { val: 'Low', desc: 'Limited modification of data possible' },
        H: { val: 'High', desc: 'Total loss of integrity' }
      }
    },
    A: {
      label: 'Availability',
      values: {
        N: { val: 'None', desc: 'No impact to availability' },
        L: { val: 'Low', desc: 'Reduced performance or interruptions in resource availability' },
        H: { val: 'High', desc: 'Total loss of availability of the affected component' }
      }
    }
  };

  const v4Mapping: Record<string, { label: string; values: Record<string, { val: string; desc: string }> }> = {
    AV: v3Mapping.AV,
    AC: v3Mapping.AC,
    AT: {
      label: 'Attack Requirements',
      values: {
        N: { val: 'None', desc: 'No deployment or execution preconditions required' },
        P: { val: 'Present', desc: 'Depends on specific deployment or race conditions' }
      }
    },
    PR: v3Mapping.PR,
    UI: {
      label: 'User Interaction',
      values: {
        N: { val: 'None', desc: 'No user interaction required' },
        P: { val: 'Passive', desc: 'Requires involuntary user interaction' },
        A: { val: 'Active', desc: 'Requires specific conscious user interaction' }
      }
    },
    VC: {
      label: 'Vuln System Conf.',
      values: {
        H: { val: 'High', desc: 'Total confidentiality loss on vulnerable system' },
        L: { val: 'Low', desc: 'Limited confidentiality loss on vulnerable system' },
        N: { val: 'None', desc: 'No confidentiality loss on vulnerable system' }
      }
    },
    VI: {
      label: 'Vuln System Integ.',
      values: {
        H: { val: 'High', desc: 'Total integrity loss on vulnerable system' },
        L: { val: 'Low', desc: 'Limited integrity loss on vulnerable system' },
        N: { val: 'None', desc: 'No integrity loss on vulnerable system' }
      }
    },
    VA: {
      label: 'Vuln System Avail.',
      values: {
        H: { val: 'High', desc: 'Total availability loss on vulnerable system' },
        L: { val: 'Low', desc: 'Limited availability loss on vulnerable system' },
        N: { val: 'None', desc: 'No availability loss on vulnerable system' }
      }
    },
    SC: {
      label: 'Subseq. System Conf.',
      values: {
        H: { val: 'High', desc: 'Total confidentiality loss on subsequent systems' },
        L: { val: 'Low', desc: 'Limited confidentiality loss on subsequent systems' },
        N: { val: 'None', desc: 'No confidentiality loss on subsequent systems' }
      }
    },
    SI: {
      label: 'Subseq. System Integ.',
      values: {
        H: { val: 'High', desc: 'Total integrity loss on subsequent systems' },
        L: { val: 'Low', desc: 'Limited integrity loss on subsequent systems' },
        N: { val: 'None', desc: 'No integrity loss on subsequent systems' }
      }
    },
    SA: {
      label: 'Subseq. System Avail.',
      values: {
        H: { val: 'High', desc: 'Total availability loss on subsequent systems' },
        L: { val: 'Low', desc: 'Limited availability loss on subsequent systems' },
        N: { val: 'None', desc: 'No availability loss on subsequent systems' }
      }
    },
    E: {
      label: 'Exploit Maturity',
      values: {
        A: { val: 'Attacked', desc: 'Active exploitation or public exploit tools observed' },
        P: { val: 'PoC', desc: 'Proof-of-concept exploit code is available' },
        U: { val: 'Unreported', desc: 'No known public exploit or active attacks' },
        X: { val: 'Not Defined', desc: 'Exploit maturity metric not defined' }
      }
    }
  };

  const activeMapping = isV4 ? v4Mapping : v3Mapping;

  parts.forEach(part => {
    const [key, code] = part.split(':');
    if (key && code && activeMapping[key]) {
      const spec = activeMapping[key];
      const match = spec.values[code];
      metrics.push({
        key,
        label: spec.label,
        value: match ? match.val : code,
        desc: match ? match.desc : ''
      });
    }
  });

  return metrics;
}

export default function CveMetrics({
  report,
  rbvmBreakdown = null
}: CveMetricsProps) {
  const { severity, cvssScore, cvssVector, cvssDetails, epssScore, epssPercentile, affectedProducts, cwe } = report;
  const sev = severityConfigs[severity] || severityConfigs.MEDIUM;
  const IconComponent = sev.icon;

  const isV4Primary = Boolean(cvssVector && cvssVector.toUpperCase().startsWith('CVSS:4')) || Boolean(cvssDetails?.cvssv4?.score !== undefined && cvssDetails?.cvssv4?.score !== null);
  const parsedMetrics = parseCvssVector(cvssVector);

  // SVG parameters for CVSS circle dial
  const radius = 50;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  const numericCvss = cvssScore ?? 0;
  const cvssPercentage = Math.min(Math.max(numericCvss, 0), 10) / 10;
  const strokeDashoffset = circumference - cvssPercentage * circumference;

  const fallbackV3Score = cvssDetails?.cvssv3?.baseScore ?? cvssDetails?.cvssv3Translated?.baseScore ?? null;

  const rbvmSev = rbvmBreakdown ? severityConfigs[rbvmBreakdown.riskLevel] : null;
  const RbvmIcon = rbvmSev ? rbvmSev.icon : Shield;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

      {/* Conditional RBVM Score Breakdown Card (Only shown when user provides S_asset) */}
      {rbvmBreakdown && rbvmSev && (
        <div className="bg-slate-950/80 border border-emerald-500/30 rounded-2xl p-6 lg:col-span-3 space-y-5 relative overflow-hidden shadow-xl">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-900 pb-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Gauge className="w-4 h-4 text-emerald-400" />
                <span className="text-xs font-mono uppercase tracking-wider text-emerald-400 font-bold">
                  Contextualized RBVM Score (In-Memory Session)
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono">
                Final Score = [({rbvmBreakdown.weights.w1.toFixed(2)} × S_vuln) + ({rbvmBreakdown.weights.w2.toFixed(2)} × S_asset) + ({rbvmBreakdown.weights.w3.toFixed(2)} × S_threat)]
                {rbvmBreakdown.controlReductionPct > 0 && (
                  <span className="text-teal-400">
                    {' '}× {rbvmBreakdown.controlMultiplier} (-{rbvmBreakdown.controlReductionPct}% Controls)
                  </span>
                )}
              </p>
              {rbvmBreakdown.controlReductionPct > 0 && (
                <p className="text-[11px] text-teal-400 font-mono">
                  Compensating controls reduced raw weighted score from{' '}
                  <strong>{rbvmBreakdown.rawWeightedScore.toFixed(1)}</strong> to{' '}
                  <strong>{rbvmBreakdown.finalScore.toFixed(1)}</strong> (-{rbvmBreakdown.controlReductionPct}% compounded).
                </p>
              )}
              {rbvmBreakdown.weightsNormalized && (
                <p className="text-[11px] text-amber-400 font-mono">
                  Your weights did not sum to 1.00 — scaled proportionally to the effective weights shown above.
                </p>
              )}
            </div>

            <div className="flex items-center gap-4">
              <div className="text-right">
                <div className="text-3xl font-mono font-black text-slate-100">
                  {rbvmBreakdown.finalScore.toFixed(1)}
                  <span className="text-sm text-slate-500 font-normal">/100</span>
                </div>
                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">
                  {rbvmBreakdown.controlReductionPct > 0
                    ? `Mitigated (Raw: ${rbvmBreakdown.rawWeightedScore.toFixed(1)})`
                    : 'Weighted Risk Score'}
                </span>
              </div>
              <div className={`inline-flex items-center gap-1.5 px-3.5 py-2 ${rbvmSev.bg} ${rbvmSev.border} border rounded-xl text-xs font-mono font-bold uppercase ${rbvmSev.color}`}>
                <RbvmIcon className="w-4 h-4" />
                <span>{rbvmBreakdown.riskLevel}</span>
              </div>
            </div>
          </div>

          {/* 3-Pillar Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* S_vuln */}
            <div className="p-4 bg-slate-900/50 border border-slate-800/80 rounded-xl space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400 uppercase">1. S_vuln (W₁={rbvmBreakdown.weights.w1})</span>
                <span className="text-slate-100 font-bold">{rbvmBreakdown.sVuln.toFixed(1)} / 100</span>
              </div>
              <div className="w-full h-1.5 bg-slate-950 rounded-full overflow-hidden">
                <div
                  className="h-full bg-amber-500 rounded-full"
                  style={{ width: `${Math.min(rbvmBreakdown.sVuln, 100)}%` }}
                />
              </div>
              <p className="text-[11px] text-slate-400 font-mono">
                GTI {isV4Primary ? 'CVSS v4.0' : 'CVSS v3.x'} ({cvssScore !== null ? cvssScore.toFixed(1) : '0.0'}) × 10 → Contributes{' '}
                <strong className="text-slate-200">{(rbvmBreakdown.weights.w1 * rbvmBreakdown.sVuln).toFixed(1)} pts</strong>
              </p>
            </div>

            {/* S_asset */}
            <div className="p-4 bg-slate-900/50 border border-slate-800/80 rounded-xl space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400 uppercase">2. S_asset (W₂={rbvmBreakdown.weights.w2})</span>
                <span className="text-emerald-400 font-bold">{rbvmBreakdown.sAsset.toFixed(1)} / 100</span>
              </div>
              <div className="w-full h-1.5 bg-slate-950 rounded-full overflow-hidden">
                <div
                  className="h-full bg-emerald-500 rounded-full"
                  style={{ width: `${Math.min(rbvmBreakdown.sAsset, 100)}%` }}
                />
              </div>
              <p className="text-[11px] text-slate-400 font-mono">
                User Asset Exposure & Sensitivity → Contributes{' '}
                <strong className="text-slate-200">{(rbvmBreakdown.weights.w2 * rbvmBreakdown.sAsset).toFixed(1)} pts</strong>
              </p>
            </div>

            {/* S_threat */}
            <div className="p-4 bg-slate-900/50 border border-slate-800/80 rounded-xl space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400 uppercase">3. S_threat (W₃={rbvmBreakdown.weights.w3})</span>
                <span className="text-rose-400 font-bold">{rbvmBreakdown.sThreat.toFixed(1)} / 100</span>
              </div>
              <div className="w-full h-1.5 bg-slate-950 rounded-full overflow-hidden">
                <div
                  className="h-full bg-rose-500 rounded-full"
                  style={{ width: `${Math.min(rbvmBreakdown.sThreat, 100)}%` }}
                />
              </div>
              <p className="text-[11px] text-slate-400 font-mono">
                {rbvmBreakdown.baseThreatReason} × {rbvmBreakdown.epssMultiplier}x EPSS
                {rbvmBreakdown.epssFloorApplied ? ' (EPSS floor)' : ''} → Contributes{' '}
                <strong className="text-slate-200">{(rbvmBreakdown.weights.w3 * rbvmBreakdown.sThreat).toFixed(1)} pts</strong>
              </p>
            </div>
          </div>

          {/* Simplistic RBVM Triage Judgment */}
          <div
            className={`p-3.5 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${rbvmSev.bg} ${rbvmSev.border}`}
          >
            <div className="space-y-0.5">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono uppercase tracking-wider font-bold px-1.5 py-0.5 rounded bg-slate-950/70 text-slate-400 border border-slate-800">
                  Simplistic Judgment
                </span>
                <span className={`text-xs font-mono font-bold uppercase ${rbvmSev.color}`}>
                  {rbvmBreakdown.riskLevel === 'CRITICAL'
                    ? 'Critical (≥ 80)'
                    : rbvmBreakdown.riskLevel === 'HIGH'
                    ? 'High (60–79.9)'
                    : rbvmBreakdown.riskLevel === 'MEDIUM'
                    ? 'Medium (35–59.9)'
                    : 'Low (< 35)'}
                </span>
              </div>
              <p className="text-xs font-sans text-slate-200 pt-0.5">
                {rbvmBreakdown.riskLevel === 'CRITICAL'
                  ? 'Patch immediately, monitor logs for potential intrusion, and implement mitigation measures as soon as possible.'
                  : rbvmBreakdown.riskLevel === 'HIGH'
                  ? 'Patch as soon as possible, monitor logs for potential intrusion, and implement mitigation measures as soon as possible.'
                  : rbvmBreakdown.riskLevel === 'MEDIUM'
                  ? 'Patch as soon as practical. Where possible, implement mitigation measures.'
                  : 'Patch within standard maintenance cycles.'}
              </p>
            </div>
          </div>

          {/* Purely Contextual GTI Telemetry Callouts (Does not alter the score) */}
          <div className="pt-3 border-t border-slate-900/80 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-slate-500 uppercase">GTI Contextual Telemetry (Non-Scoring):</span>
              {report.exploitPatterns.exploitationVectors && report.exploitPatterns.exploitationVectors.length > 0 && (
                <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                  Vectors: {report.exploitPatterns.exploitationVectors.join(', ')}
                </span>
              )}
              {report.exploitPatterns.exploitationConsequence && (
                <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                  Consequence: {report.exploitPatterns.exploitationConsequence}
                </span>
              )}
              {report.exploitPatterns.exploitationState && (
                <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                  Exploitation State: {report.exploitPatterns.exploitationState}
                </span>
              )}
              {report.exploitPatterns.exploitAvailability && (
                <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                  Exploit Availability: {report.exploitPatterns.exploitAvailability}
                </span>
              )}
            </div>
          </div>
        </div>
      )}
      
      {/* CVSS Dial Card */}
      <div className="bg-slate-950/60 border border-slate-900 rounded-2xl p-6 flex flex-col items-center justify-between text-center relative overflow-hidden">
        <div className="absolute top-3 left-3 flex items-center gap-1.5 text-slate-500 font-mono text-[10px] tracking-wider uppercase">
          <Shield className="w-3.5 h-3.5 text-emerald-500" />
          <span>GTI Severity & CVSS</span>
        </div>

        <div className="mt-6 relative flex items-center justify-center">
          <svg className="w-32 h-32 transform -rotate-90">
            <circle
              cx="64"
              cy="64"
              r={radius}
              className="stroke-slate-900 fill-transparent"
              strokeWidth={strokeWidth}
            />
            <circle
              cx="64"
              cy="64"
              r={radius}
              className="fill-transparent transition-all duration-1000 ease-out"
              strokeWidth={strokeWidth}
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              stroke={
                severity === 'CRITICAL' ? '#f43f5e' : 
                severity === 'HIGH' ? '#f97316' : 
                severity === 'MEDIUM' ? '#f59e0b' : '#10b981'
              }
            />
          </svg>
          <div className="absolute flex flex-col items-center justify-center">
            <span className="text-3xl font-mono font-black text-slate-100">
              {cvssScore !== null ? cvssScore.toFixed(1) : 'N/A'}
            </span>
            <span className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">
              {isV4Primary ? 'CVSS v4.0' : 'CVSS v3.x'}
            </span>
          </div>
        </div>

        <div className="mt-4 w-full">
          <div className={`inline-flex items-center gap-1.5 px-3 py-1.5 ${sev.bg} ${sev.border} border rounded-full text-xs font-mono font-bold uppercase ${sev.color}`}>
            <IconComponent className="w-3.5 h-3.5" />
            <span>{report.riskRating || severity} RISK</span>
          </div>

          {isV4Primary && fallbackV3Score !== null && (
            <div className="mt-2 text-[10px] font-mono text-slate-400">
              CVSS v3 Base: <span className="text-slate-200 font-bold">{fallbackV3Score.toFixed(1)}</span>
              {cvssDetails?.cvssv3Translated?.baseScore !== undefined && cvssDetails?.cvssv3Translated?.baseScore !== null && (
                <span> (GTIG Translated: <span className="text-slate-200 font-bold">{cvssDetails.cvssv3Translated.baseScore.toFixed(1)}</span>)</span>
              )}
            </div>
          )}
          
          {epssScore !== undefined && (
            <div className="mt-5 pt-4 border-t border-slate-900/60 text-left space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-slate-500 font-mono uppercase tracking-wider">EPSS Score:</span>
                <span className="text-slate-200 font-mono font-bold">
                  {(epssScore * 100).toFixed(2)}%
                  {epssPercentile !== undefined && (
                    <span className="text-slate-400 font-normal ml-1">
                      ({(epssPercentile * 100).toFixed(1)}th pct)
                    </span>
                  )}
                </span>
              </div>
              <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all duration-1000 ${
                    epssScore > 0.5 ? 'bg-rose-500' : epssScore > 0.15 ? 'bg-amber-500' : 'bg-emerald-500'
                  }`}
                  style={{ width: `${Math.min(epssScore * 100, 100)}%` }}
                />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* CVSS Metric Vector Details */}
      <div className="bg-slate-950/60 border border-slate-900 rounded-2xl p-6 lg:col-span-2 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <span className="text-slate-200 font-sans font-bold text-sm">
            {isV4Primary ? 'CVSS v4.0 Vector Metrics' : 'CVSS v3 Vector Metrics'}
          </span>
          {cvssVector && (
            <span className="text-[10px] font-mono bg-slate-900 text-slate-400 px-2 py-1 rounded select-all truncate max-w-xs md:max-w-md">
              {cvssVector}
            </span>
          )}
        </div>

        {parsedMetrics.length > 0 ? (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {parsedMetrics.map((met) => (
              <div key={met.key} className="p-3 bg-slate-900/40 border border-slate-900 hover:border-slate-800 rounded-xl flex flex-col justify-between space-y-1 transition-all">
                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">{met.label}</span>
                <span className={`text-xs font-mono font-bold ${
                  met.value === 'Network' || met.value === 'Changed' || met.value === 'High' || met.value === 'Attacked' || (met.value === 'None' && (met.key === 'PR' || met.key === 'AT' || met.key === 'UI'))
                    ? 'text-amber-400'
                    : 'text-slate-300'
                }`}>{met.value}</span>
                {met.desc && (
                  <span className="text-[9px] text-slate-400 leading-tight font-sans mt-1 line-clamp-2">{met.desc}</span>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="py-8 text-center text-slate-500 font-mono text-xs border border-dashed border-slate-900 rounded-xl">
            No CVSS vector reported in Google Threat Intelligence for this CVE.
          </div>
        )}

        {cwe && (cwe.id || cwe.title) && (
          <div className="pt-2 border-t border-slate-900/60 flex items-center justify-between text-xs font-mono">
            <span className="text-slate-500 uppercase">Weakness Enumeration (CWE):</span>
            <span className="text-slate-300">
              <strong className="text-emerald-400">{cwe.id}</strong> {cwe.title ? `— ${cwe.title}` : ''}
            </span>
          </div>
        )}
      </div>

      {/* Affected Vendors / Product Matrices (from GTI CPEs) */}
      <div className="bg-slate-950/60 border border-slate-900 rounded-2xl p-6 lg:col-span-3">
        <div className="flex items-center gap-2 mb-4">
          <Database className="w-4 h-4 text-emerald-500" />
          <h3 className="text-sm font-sans font-bold text-slate-200 uppercase tracking-wider">Affected Products (GTI CPEs)</h3>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-900">
          <table className="w-full text-left border-collapse font-sans text-xs">
            <thead>
              <tr className="bg-slate-900 text-slate-400 uppercase tracking-wider font-mono text-[10px] border-b border-slate-900/60">
                <th className="p-3 pl-4">Vendor</th>
                <th className="p-3">Product</th>
                <th className="p-3 pr-4 text-right">Affected Versions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900/40 text-slate-300">
              {affectedProducts && affectedProducts.length > 0 ? (
                affectedProducts.map((p, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/20 transition-all">
                    <td className="p-3 pl-4 font-semibold text-slate-200 whitespace-nowrap">{p.vendor}</td>
                    <td className="p-3 font-mono whitespace-nowrap">{p.product}</td>
                    <td className="p-3 pr-4 text-right font-mono text-amber-500 max-w-md break-words">{p.versions}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={3} className="p-6 text-center text-slate-500 font-mono">
                    No CPE product entries reported in Google Threat Intelligence for this CVE.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
