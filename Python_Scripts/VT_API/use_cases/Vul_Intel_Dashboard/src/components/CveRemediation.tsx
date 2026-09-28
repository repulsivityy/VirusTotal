import React from 'react';
import { CveReport } from '../types';
import { ShieldCheck, ExternalLink, Bookmark, Globe } from 'lucide-react';
import { sanitizeUrl } from '../utils';

interface CveRemediationProps {
  report: CveReport;
}

export default function CveRemediation({ report }: CveRemediationProps) {
  const { remediation } = report;
  const {
    status,
    availableMitigation,
    daysToPatch,
    fixedVersions,
    steps,
    vendorFixReferences,
    references
  } = remediation;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      
      {/* Remediation steps & workarounds */}
      <div className="bg-slate-950/60 border border-slate-900 rounded-2xl p-6 space-y-4">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-500" />
          <h3 className="text-sm font-sans font-bold text-slate-200 uppercase tracking-wider">GTI Mitigation & Workarounds</h3>
        </div>

        <div className="flex flex-wrap justify-between items-center gap-2 p-3 bg-slate-900/40 border border-slate-900 rounded-xl">
          <span className="text-xs font-mono text-slate-400">Available Mitigations</span>
          <div className="flex flex-wrap gap-1.5">
            {availableMitigation && availableMitigation.length > 0 ? (
              availableMitigation.map((m, idx) => (
                <span
                  key={idx}
                  className="px-2.5 py-0.5 bg-emerald-500/10 border border-emerald-500/20 rounded-full text-xs font-mono text-emerald-400 font-bold uppercase"
                >
                  {m}
                </span>
              ))
            ) : (
              <span className="px-2.5 py-0.5 bg-slate-900 border border-slate-800 rounded-full text-xs font-mono text-slate-400 uppercase">
                {status}
              </span>
            )}
          </div>
        </div>

        {daysToPatch !== undefined && daysToPatch !== null && (
          <div className="flex justify-between items-center p-3 bg-slate-900/40 border border-slate-900 rounded-xl">
            <span className="text-xs font-mono text-slate-400">Days to Patch (GTI)</span>
            <span className={`text-xs font-mono font-bold ${daysToPatch < 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
              {daysToPatch} days {daysToPatch < 0 ? '(Zero-Day / Exploited Prior to Patch)' : ''}
            </span>
          </div>
        )}

        {fixedVersions && fixedVersions.length > 0 && (
          <div className="flex justify-between items-center p-3 bg-slate-900/40 border border-slate-900 rounded-xl">
            <span className="text-xs font-mono text-slate-400">Fixed/Patched in</span>
            <span className="text-xs font-mono text-emerald-400 font-semibold text-right">
              {fixedVersions.join(', ')}
            </span>
          </div>
        )}

        <div className="space-y-3">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block pl-1">GTI Workarounds</span>
          <div className="space-y-2">
            {steps && steps.length > 0 ? (
              steps.map((step, idx) => (
                <div key={idx} className="flex gap-2.5 p-3 bg-slate-900/20 border border-slate-900 rounded-xl">
                  <span className="text-xs font-mono text-emerald-500 font-black shrink-0">{String(idx + 1).padStart(2, '0')}.</span>
                  <span className="text-xs text-slate-300 font-sans leading-relaxed">{step}</span>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 font-mono italic pl-1">
                No specific workaround steps reported in Google Threat Intelligence.
              </p>
            )}
          </div>
        </div>

      </div>

      {/* Vendor Fix References & GTI Sources */}
      <div className="space-y-6">
        
        {/* Official Vendor Fix References (attrs.vendor_fix_references) */}
        <div className="bg-slate-950/60 border border-slate-900 rounded-2xl p-6 space-y-4">
          <div className="flex items-center gap-2">
            <Bookmark className="w-4 h-4 text-emerald-500" />
            <h3 className="text-sm font-sans font-bold text-slate-200 uppercase tracking-wider">Vendor Fix Advisories (GTI)</h3>
          </div>

          <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
            {vendorFixReferences && vendorFixReferences.length > 0 ? (
              vendorFixReferences.map((ref, idx) => (
                <a
                  key={idx}
                  href={sanitizeUrl(ref.url)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex justify-between items-center p-3 bg-slate-900/40 hover:bg-slate-900/80 border border-slate-900 hover:border-slate-800 rounded-xl text-slate-300 hover:text-slate-100 transition-all font-sans text-xs group"
                >
                  <div className="space-y-0.5 truncate max-w-md">
                    <div className="font-medium truncate" title={ref.title}>{ref.title}</div>
                    {(ref.sourceName || ref.uniqueId || ref.publishedDate) && (
                      <div className="text-[10px] font-mono text-slate-500 flex items-center gap-2">
                        {ref.sourceName && <span>{ref.sourceName}</span>}
                        {ref.uniqueId && <span className="text-emerald-400">[{ref.uniqueId}]</span>}
                        {ref.publishedDate && <span>• {ref.publishedDate}</span>}
                      </div>
                    )}
                  </div>
                  <ExternalLink className="w-3.5 h-3.5 text-slate-500 group-hover:text-emerald-400 transition-colors shrink-0 ml-2" />
                </a>
              ))
            ) : (
              <p className="text-xs text-slate-500 font-mono italic">No vendor fix references reported in GTI.</p>
            )}
          </div>
        </div>

        {/* GTI Intelligence Sources (attrs.sources) */}
        <div className="bg-slate-950/60 border border-slate-900 rounded-2xl p-6 space-y-4">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-emerald-500" />
            <h3 className="text-sm font-sans font-bold text-slate-200 uppercase tracking-wider">GTI Intelligence Sources</h3>
          </div>

          {references && references.length > 0 ? (
            <div className="grid grid-cols-1 gap-2 max-h-56 overflow-y-auto pr-1">
              {references.map((source, idx) => (
                <a
                  key={idx}
                  href={sanitizeUrl(source.url)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between gap-2 p-2.5 bg-slate-900/30 hover:bg-slate-900/70 border border-slate-900/60 hover:border-slate-800 rounded-xl text-slate-300 hover:text-emerald-400 transition-all font-sans text-[11px] group"
                >
                  <div className="flex items-center gap-2 truncate">
                    <div className="p-1 bg-emerald-500/10 rounded-lg group-hover:bg-emerald-500/20 shrink-0">
                      <Globe className="w-3.5 h-3.5 text-emerald-400" />
                    </div>
                    <div className="truncate">
                      <span className="font-medium block truncate" title={source.title}>
                        {source.title}
                      </span>
                      {(source.sourceName || source.publishedDate) && (
                        <span className="text-[10px] font-mono text-slate-500">
                          {source.sourceName}{source.publishedDate ? ` • ${source.publishedDate}` : ''}
                        </span>
                      )}
                    </div>
                  </div>
                  <ExternalLink className="w-3 h-3 text-slate-500 group-hover:text-emerald-400 shrink-0" />
                </a>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-500 font-mono italic">No external sources indexed in GTI.</p>
          )}
        </div>

      </div>

    </div>
  );
}
