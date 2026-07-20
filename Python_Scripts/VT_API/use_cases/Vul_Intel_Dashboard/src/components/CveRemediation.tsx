import React from 'react';
import { CveReport } from '../types';
import { ShieldCheck, ArrowRight, ExternalLink, Bookmark, Globe } from 'lucide-react';
import { sanitizeUrl } from '../utils';

interface CveRemediationProps {
  report: CveReport;
}

export default function CveRemediation({ report }: CveRemediationProps) {
  const { remediation, groundingSources } = report;
  const { status, fixedVersions, steps, references } = remediation;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      
      {/* Remediation steps checklist */}
      <div className="bg-slate-950/60 border border-slate-900 rounded-2xl p-6 space-y-4">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-500" />
          <h3 className="text-sm font-sans font-bold text-slate-200 uppercase tracking-wider">Remediation Directives</h3>
        </div>

        <div className="flex justify-between items-center p-3 bg-slate-900/40 border border-slate-900 rounded-xl">
          <span className="text-xs font-mono text-slate-400">Status</span>
          <span className="px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-full text-xs font-mono text-emerald-400 font-bold uppercase">
            {status}
          </span>
        </div>

        {fixedVersions && fixedVersions.length > 0 && (
          <div className="flex justify-between items-center p-3 bg-slate-900/40 border border-slate-900 rounded-xl">
            <span className="text-xs font-mono text-slate-400">Fixed/Patched in</span>
            <span className="text-xs font-mono text-emerald-400 font-semibold text-right">
              {fixedVersions.join(', ')}
            </span>
          </div>
        )}

        <div className="space-y-3">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block pl-1">Actionable Checklist</span>
          <div className="space-y-2">
            {steps && steps.length > 0 ? (
              steps.map((step, idx) => (
                <div key={idx} className="flex gap-2.5 p-3 bg-slate-900/20 border border-slate-900 rounded-xl">
                  <span className="text-xs font-mono text-emerald-500 font-black shrink-0">{String(idx + 1).padStart(2, '0')}.</span>
                  <span className="text-xs text-slate-300 font-sans leading-relaxed">{step}</span>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 font-mono italic pl-1">No custom actionable checklist mapped.</p>
            )}
          </div>
        </div>

      </div>

      {/* Reference Links & Grounding Citations */}
      <div className="space-y-6">
        
        {/* Official Vendor references */}
        <div className="bg-slate-950/60 border border-slate-900 rounded-2xl p-6 space-y-4">
          <div className="flex items-center gap-2">
            <Bookmark className="w-4 h-4 text-emerald-500" />
            <h3 className="text-sm font-sans font-bold text-slate-200 uppercase tracking-wider">Official Advisories</h3>
          </div>

          <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
            {references && references.length > 0 ? (
              references.map((ref, idx) => (
                <a
                  key={idx}
                  href={sanitizeUrl(ref.url)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex justify-between items-center p-3 bg-slate-900/40 hover:bg-slate-900/80 border border-slate-900 hover:border-slate-800 rounded-xl text-slate-300 hover:text-slate-100 transition-all font-sans text-xs group"
                >
                  <span className="font-medium truncate max-w-xs">{ref.title}</span>
                  <ExternalLink className="w-3.5 h-3.5 text-slate-500 group-hover:text-emerald-400 transition-colors shrink-0 ml-2" />
                </a>
              ))
            ) : (
              <p className="text-xs text-slate-500 font-mono italic">No reference links reported.</p>
            )}
          </div>
        </div>

        {/* Real-time Google Search Grounding Sources */}
        {groundingSources && groundingSources.length > 0 && (
          <div className="bg-slate-950/60 border border-slate-900 rounded-2xl p-6 space-y-4">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-emerald-500" />
              <h3 className="text-sm font-sans font-bold text-slate-200 uppercase tracking-wider">Grounded Intelligence Citations</h3>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed font-sans pl-1">
              The metrics and exploit intelligence shown are cross-referenced with these real-time security research indexes:
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-40 overflow-y-auto pr-1">
              {groundingSources.map((source, idx) => (
                <a
                  key={idx}
                  href={sanitizeUrl(source.url)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 p-2.5 bg-slate-900/30 hover:bg-slate-900/70 border border-slate-900/60 hover:border-slate-800 rounded-xl text-slate-300 hover:text-emerald-400 transition-all font-sans text-[11px] group"
                >
                  <div className="p-1 bg-emerald-500/10 rounded-lg group-hover:bg-emerald-500/20 shrink-0">
                    <Globe className="w-3.5 h-3.5 text-emerald-400" />
                  </div>
                  <span className="font-medium truncate" title={source.title}>
                    {source.title}
                  </span>
                </a>
              ))}
            </div>
          </div>
        )}

      </div>

    </div>
  );
}
