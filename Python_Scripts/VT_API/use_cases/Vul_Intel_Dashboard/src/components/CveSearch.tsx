import React, { useState } from 'react';
import { Search, ShieldAlert, Sparkles } from 'lucide-react';

interface CveSearchProps {
  onSearch: (cveId: string) => void;
  isLoading: boolean;
}

export default function CveSearch({ onSearch, isLoading }: CveSearchProps) {
  const [query, setQuery] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!query.trim()) {
      setError('Please enter a CVE ID.');
      return;
    }

    const match = query.match(/\bCVE-\d{4}-\d{4,7}\b/i);
    if (!match) {
      setError('Invalid CVE format. Must match CVE-YYYY-NNNN or CVE-YYYY-NNNNN (e.g., CVE-2023-38831).');
      return;
    }

    const cleanQuery = match[0].toUpperCase();
    setError(null);
    onSearch(cleanQuery);
  };

  return (
    <div id="cve-search-section" className="w-full space-y-6">
      {/* Title block */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 bg-amber-500/10 border border-amber-500/20 rounded-full text-amber-400 text-xs font-mono">
          <Sparkles className="w-3.5 h-3.5 animate-pulse" />
          <span>Google Threat Intelligence</span>
        </div>
        <h2 className="text-3xl md:text-4xl font-sans font-bold tracking-tight text-slate-100">
          Vulnerability Threat Intelligence
        </h2>
        <p className="text-slate-400 max-w-xl mx-auto text-sm md:text-base">
          Analyze global CVE threats instantly. Pulls live exploit patterns, severity metrics, affected vendors, and remediation directives powered by grounded threat telemetry.
        </p>
      </div>

      {/* Search Input Card */}
      <form onSubmit={handleSubmit} className="w-full max-w-2xl mx-auto">
        <div className="relative flex items-center bg-slate-900/90 border border-slate-800 focus-within:border-emerald-500/50 shadow-2xl rounded-2xl p-1.5 transition-all duration-300">
          <div className="pl-4 text-slate-500">
            <Search className="w-5 h-5" />
          </div>
          <input
            type="text"
            placeholder="Search CVE (e.g., CVE-2021-44228, CVE-2024-3094)"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              if (error) setError(null);
            }}
            disabled={isLoading}
            autoFocus
            className="w-full bg-transparent border-0 outline-none focus:ring-0 text-slate-100 px-3 py-3 font-mono text-base placeholder-slate-500"
          />
          <button
            type="submit"
            disabled={isLoading}
            className="px-6 py-3 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-800 disabled:opacity-50 text-slate-900 font-medium rounded-xl transition-all font-sans cursor-pointer flex items-center gap-2 shadow-lg shadow-emerald-950/20"
          >
            {isLoading ? (
              <>
                <div className="w-4 h-4 border-2 border-slate-900 border-t-transparent rounded-full animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <span>Query Threat Intel</span>
            )}
          </button>
        </div>

        {error && (
          <div className="mt-3 flex items-center gap-2 px-4 py-2.5 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-400 text-xs font-mono animate-fade-in">
            <ShieldAlert className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </form>
    </div>
  );
}
