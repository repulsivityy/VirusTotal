import React from 'react';
import { CveReport } from '../types';
import { Shield, ShieldAlert, AlertTriangle, Info, CheckCircle, Database } from 'lucide-react';

interface CveMetricsProps {
  report: CveReport;
}

const severityConfigs = {
  LOW: { color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', icon: CheckCircle },
  MEDIUM: { color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20', icon: Info },
  HIGH: { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20', icon: AlertTriangle },
  CRITICAL: { color: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/20', icon: ShieldAlert }
};

// Help parse standard CVSS v3 vectors to human-readable strings
function parseCvssVector(vectorStr: string) {
  if (!vectorStr) return [];
  const parts = vectorStr.split('/');
  const metrics: { key: string; label: string; value: string; desc: string }[] = [];

  const mapping: Record<string, { label: string; values: Record<string, { val: string; desc: string }> }> = {
    AV: {
      label: 'Attack Vector',
      values: {
        N: { val: 'Network', desc: 'Exploitable remotely over public internet' },
        A: { val: 'Adjacent', desc: 'Requires proximity to the local network' },
        L: { val: 'Local', desc: 'Requires direct shell or system session access' },
        P: { val: 'Physical', desc: 'Requires physical access to target hardware' }
      }
    },
    AC: {
      label: 'Attack Complexity',
      values: {
        L: { val: 'Low', desc: 'Specialized system configurations are not required' },
        H: { val: 'High', desc: 'Requires high-precision timing, setups, or conditions' }
      }
    },
    PR: {
      label: 'Privileges Required',
      values: {
        N: { val: 'None', desc: 'Unauthorized user can execute exploit' },
        L: { val: 'Low', desc: 'Requires standard, non-administrative user permissions' },
        H: { val: 'High', desc: 'Requires administrative / root access level' }
      }
    },
    UI: {
      label: 'User Interaction',
      values: {
        N: { val: 'None', desc: 'No user interaction is required' },
        R: { val: 'Required', desc: 'Requires target user to click, open, or run file' }
      }
    },
    S: {
      label: 'Scope',
      values: {
        U: { val: 'Unchanged', desc: 'Exploit only affects the vulnerable application component' },
        C: { val: 'Changed', desc: 'Can bypass sandbox bounds to affect parent OS/hypervisor' }
      }
    },
    C: {
      label: 'Confidentiality Impact',
      values: {
        N: { val: 'None', desc: 'No sensitive system files or data can be read' },
        L: { val: 'Low', desc: 'Partial, limited access to sensitive metrics' },
        H: { val: 'High', desc: 'Full disclosure of all sensitive configuration, memory, or DB content' }
      }
    },
    I: {
      label: 'Integrity Impact',
      values: {
        N: { val: 'None', desc: 'No unauthorized files or settings can be changed' },
        L: { val: 'Low', desc: 'Partial alteration or corruption of settings' },
        H: { val: 'High', desc: 'Full system corruption, code modification, or backdoors' }
      }
    },
    A: {
      label: 'Availability Impact',
      values: {
        N: { val: 'None', desc: 'Application services continue working without downtime' },
        L: { val: 'Low', desc: 'Performance is throttled or degraded temporarily' },
        H: { val: 'High', desc: 'Complete crash, denial of service (DoS), or locked resources' }
      }
    }
  };

  parts.forEach(part => {
    const [key, code] = part.split(':');
    if (key && code && mapping[key]) {
      const spec = mapping[key];
      const match = spec.values[code];
      metrics.push({
        key,
        label: spec.label,
        value: match ? match.val : code,
        desc: match ? match.desc : 'No description available'
      });
    }
  });

  return metrics;
}

export default function CveMetrics({ report }: CveMetricsProps) {
  const { severity, cvssScore, cvssVector, epssScore, affectedProducts } = report;
  const sev = severityConfigs[severity] || severityConfigs.MEDIUM;
  const IconComponent = sev.icon;

  const parsedMetrics = parseCvssVector(cvssVector);

  // SVG parameters for CVSS circle dial
  const radius = 50;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  const cvssPercentage = Math.min(Math.max(cvssScore, 0), 10) / 10;
  const strokeDashoffset = circumference - cvssPercentage * circumference;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      
      {/* CVSS Dial Card */}
      <div className="bg-slate-950/60 border border-slate-900 rounded-2xl p-6 flex flex-col items-center justify-between text-center relative overflow-hidden">
        <div className="absolute top-3 left-3 flex items-center gap-1.5 text-slate-500 font-mono text-[10px] tracking-wider uppercase">
          <Shield className="w-3.5 h-3.5 text-emerald-500" />
          <span>Risk Assessment</span>
        </div>

        <div className="mt-6 relative flex items-center justify-center">
          <svg className="w-32 h-32 transform -rotate-90">
            {/* Background circle */}
            <circle
              cx="64"
              cy="64"
              r={radius}
              className="stroke-slate-900 fill-transparent"
              strokeWidth={strokeWidth}
            />
            {/* Active gauge ring */}
            <circle
              cx="64"
              cy="64"
              r={radius}
              className={`fill-transparent transition-all duration-1000 ease-out`}
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
            <span className="text-3xl font-mono font-black text-slate-100">{cvssScore.toFixed(1)}</span>
            <span className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">CVSS Base</span>
          </div>
        </div>

        <div className="mt-4 w-full">
          <div className={`inline-flex items-center gap-1.5 px-3 py-1.5 ${sev.bg} ${sev.border} border rounded-full text-xs font-mono font-bold uppercase ${sev.color}`}>
            <IconComponent className="w-3.5 h-3.5" />
            <span>{severity} SEVERITY</span>
          </div>
          
          {epssScore !== undefined && (
            <div className="mt-6 pt-4 border-t border-slate-900/60 text-left space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-slate-500 font-mono uppercase tracking-wider">EPSS Exploit Prob:</span>
                <span className="text-slate-200 font-mono font-bold">{(epssScore * 100).toFixed(2)}%</span>
              </div>
              <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all duration-1000 ${
                    epssScore > 0.5 ? 'bg-rose-500' : epssScore > 0.15 ? 'bg-amber-500' : 'bg-emerald-500'
                  }`}
                  style={{ width: `${Math.min(epssScore * 100, 100)}%` }}
                />
              </div>
              <p className="text-[10px] text-slate-400 font-sans leading-relaxed">
                EPSS predicts the likelihood of this vulnerability being actively exploited in the wild over the next 30 days.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* CVSS Metric Vector Details */}
      <div className="bg-slate-950/60 border border-slate-900 rounded-2xl p-6 lg:col-span-2 space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-slate-200 font-sans font-bold text-sm">CVSS v3 Vector Metrics</span>
          <span className="text-[10px] font-mono bg-slate-900 text-slate-400 px-2 py-1 rounded select-all truncate max-w-xs md:max-w-none">
            {cvssVector}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {parsedMetrics.map((met) => (
            <div key={met.key} className="p-3 bg-slate-900/40 border border-slate-900 hover:border-slate-800 rounded-xl flex flex-col justify-between space-y-1 transition-all">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">{met.label}</span>
              <span className={`text-xs font-mono font-bold ${
                met.value === 'Network' || met.value === 'Changed' || met.value === 'High' || met.value === 'None' && met.key === 'PR' ? 'text-amber-400' : 'text-slate-300'
              }`}>{met.value}</span>
              <span className="text-[9px] text-slate-400 leading-tight font-sans mt-1 line-clamp-2">{met.desc}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Affected Vendors / Product Matrices */}
      <div className="bg-slate-950/60 border border-slate-900 rounded-2xl p-6 lg:col-span-3">
        <div className="flex items-center gap-2 mb-4">
          <Database className="w-4 h-4 text-emerald-500" />
          <h3 className="text-sm font-sans font-bold text-slate-200 uppercase tracking-wider">Affected Products Catalog</h3>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-900">
          <table className="w-full text-left border-collapse font-sans text-xs">
            <thead>
              <tr className="bg-slate-900 text-slate-400 uppercase tracking-wider font-mono text-[10px] border-b border-slate-900/60">
                <th className="p-3 pl-4">Vendor</th>
                <th className="p-3">Product / Engine</th>
                <th className="p-3 pr-4 text-right">Vulnerable Versions Limit</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900/40 text-slate-300">
              {affectedProducts && affectedProducts.length > 0 ? (
                affectedProducts.map((p, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/20 transition-all">
                    <td className="p-3 pl-4 font-semibold text-slate-200">{p.vendor}</td>
                    <td className="p-3 font-mono">{p.product}</td>
                    <td className="p-3 pr-4 text-right font-mono text-amber-500">{p.versions}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={3} className="p-6 text-center text-slate-500 font-mono">
                    No specific products catalog mapped to report bounds.
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
