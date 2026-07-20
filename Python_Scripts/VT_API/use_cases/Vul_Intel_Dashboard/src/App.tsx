import React, { useState, useEffect } from 'react';
import { CveReport, CveAssociation } from './types';
import CveSearch from './components/CveSearch';
import CveMetrics from './components/CveMetrics';
import CveExploits from './components/CveExploits';
import CveRemediation from './components/CveRemediation';
import { sanitizeUrl } from './utils';
import {
  Shield,
  TrendingUp,
  Download,
  Terminal,
  FileText,
  Sparkles,
  ExternalLink,
  Lock,
  RefreshCw,
  Info,
  Settings
} from 'lucide-react';

const LOADING_STEPS = [
  'Contacting threat intelligence indexers...',
  'Polling active Google telemetry feeds...',
  'Checking CISA Known Exploited Vulnerabilities catalog...',
  'Analyzing Google Threat Intelligence threat groups & campaign tracking...',
  'Evaluating CVSS base scoring vectors & EPSS weights...',
  'Synthesizing remediation actions & patch advisories...'
];

export default function App() {
  const [report, setReport] = useState<CveReport | null>(null);
  const [associations, setAssociations] = useState<CveAssociation[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [loadStepIdx, setLoadStepIdx] = useState(0);
  const [activeTab, setActiveTab] = useState<'overview' | 'exploits' | 'remediation'>('overview');
  const [error, setError] = useState<string | null>(null);
  const [isCopied, setIsCopied] = useState(false);

  // API Keys state
  const [gtiKey, setGtiKey] = useState<string>(() => localStorage.getItem('gti_key') || '');
  const [geminiKey, setGeminiKey] = useState<string>(() => localStorage.getItem('gemini_key') || '');
  const [tempGtiKey, setTempGtiKey] = useState<string>(() => localStorage.getItem('gti_key') || '');
  const [tempGeminiKey, setTempGeminiKey] = useState<string>(() => localStorage.getItem('gemini_key') || '');
  const [showSettings, setShowSettings] = useState(false);
  const [showGtiPassword, setShowGtiPassword] = useState(false);
  const [showGeminiPassword, setShowGeminiPassword] = useState(false);
  const [serverConfig, setServerConfig] = useState<{ hasServerGtiKey: boolean; hasServerGeminiKey: boolean } | null>(null);
  const [news, setNews] = useState<{ summary: string; sources: { title: string; url: string }[] } | null>(null);

  // Load server config on mount
  useEffect(() => {
    fetch('/api/config')
      .then((res) => res.json())
      .then((data) => setServerConfig(data))
      .catch((err) => console.error('Failed to load server config:', err));
  }, []);

  // Cycle loading steps during querying
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isLoading) {
      timer = setInterval(() => {
        setLoadStepIdx((prev) => (prev + 1) % LOADING_STEPS.length);
      }, 1500);
    } else {
      setLoadStepIdx(0);
    }
    return () => clearInterval(timer);
  }, [isLoading]);

  const handleSaveKeys = () => {
    localStorage.setItem('gti_key', tempGtiKey);
    localStorage.setItem('gemini_key', tempGeminiKey);
    setGtiKey(tempGtiKey);
    setGeminiKey(tempGeminiKey);
    setShowSettings(false);
  };

  const handleClearKeys = () => {
    localStorage.removeItem('gti_key');
    localStorage.removeItem('gemini_key');
    setTempGtiKey('');
    setTempGeminiKey('');
    setGtiKey('');
    setGeminiKey('');
    setShowSettings(false);
  };

  const hasGtiKeyConfigured = !!(gtiKey || serverConfig?.hasServerGtiKey);
  const hasGeminiKeyConfigured = !!(geminiKey || serverConfig?.hasServerGeminiKey);

  const handleSearch = async (cveId: string) => {
    setIsLoading(true);
    setError(null);
    setReport(null);
    setAssociations([]);
    setNews(null);

    // Build custom headers
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (gtiKey) {
      headers['x-gti-key'] = gtiKey;
    }
    if (geminiKey) {
      headers['x-gemini-key'] = geminiKey;
    }

    try {
      const [res, assocRes] = await Promise.all([
        fetch(`/api/cve/${cveId}`, { headers }),
        fetch(`/api/cve/${cveId}/associations`, { headers })
      ]);
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Vulnerability report compiling failed.');
      }

      let assocData: CveAssociation[] = [];
      if (assocRes.ok) {
        try {
          assocData = await assocRes.json();
        } catch (e) {
          console.error("Failed to parse associations:", e);
        }
      }

      setReport(data);
      setAssociations(assocData);

      // Fetch news if Gemini key is available (either client or server)
      if (hasGeminiKeyConfigured) {
        try {
          const newsRes = await fetch(`/api/cve/${cveId}/news`, { headers });
          if (newsRes.ok) {
            const newsData = await newsRes.json();
            setNews(newsData);
          }
        } catch (newsErr) {
          console.error("Failed to fetch latest news summary:", newsErr);
        }
      }

    } catch (err: any) {
      console.error('Search query error:', err);
      setError(err.message || 'Failed to establish connection to intelligence server.');
    } finally {
      setIsLoading(false);
    }
  };

  const copyJsonReport = () => {
    if (!report) return;
    navigator.clipboard.writeText(JSON.stringify(report, null, 2));
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  return (
    <div id="gti-app-container" className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-emerald-500/30 selection:text-emerald-200">

      {/* Top Threat Intel Banner / Status bar */}
      <header className="border-b border-slate-900 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40 px-4 md:px-8 py-3 flex flex-col sm:flex-row justify-between items-center gap-2">
        <div className="flex items-center gap-2">
          <div className="p-1 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-emerald-400">
            <Shield className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <h1 className="text-sm font-sans font-black uppercase tracking-wider text-slate-100">
              Google Threat Intelligence
            </h1>
            <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">
              Vulnerability Analysis Hub
            </p>
          </div>
        </div>

        {/* Real-time configuration status & Keys Button */}
        <div className="flex items-center gap-3 text-[10px] font-mono">
          <button
            onClick={() => setShowSettings(!showSettings)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md border transition-all cursor-pointer ${showSettings
                ? 'bg-emerald-600 text-slate-900 border-emerald-500 font-bold'
                : 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800'
              }`}
          >
            <Settings className="w-3.5 h-3.5 shrink-0" />
            <span>Manage API Keys</span>
          </button>

          <div className="flex items-center gap-1.5 px-2 py-1.5 bg-slate-900 border border-slate-800 rounded-md text-slate-400">
            <span className={`w-1.5 h-1.5 rounded-full ${hasGtiKeyConfigured ? 'bg-emerald-400 animate-ping' : 'bg-amber-400'}`} />
            <span>GTI Feed: {hasGtiKeyConfigured ? 'Active' : 'Unconfigured'}</span>
          </div>

          <div className="flex items-center gap-1.5 px-2 py-1.5 bg-slate-900 border border-slate-800 rounded-md text-slate-400">
            <span className={`w-1.5 h-1.5 rounded-full ${hasGeminiKeyConfigured ? 'bg-emerald-400 animate-ping' : 'bg-slate-600'}`} />
            <span>Gemini: {hasGeminiKeyConfigured ? 'Active' : 'Disabled'}</span>
          </div>
        </div>
      </header>

      {/* Main body centered layout */}
      <main className="flex-grow max-w-4xl w-full mx-auto p-4 md:p-8 space-y-6">

        {/* Critical GTI Key Missing Alert */}
        {!hasGtiKeyConfigured && (
          <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-2xl flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-start gap-3">
              <Shield className="w-5 h-5 text-amber-500 shrink-0 mt-0.5 animate-pulse" />
              <div>
                <h4 className="text-xs font-sans font-bold text-amber-400 uppercase tracking-wider">
                  GTI API Key Required
                </h4>
                <p className="text-[11px] text-slate-300 font-sans leading-relaxed">
                  Google Threat Intelligence requires a valid API key (your VirusTotal API key) to retrieve live CVE records and vulnerability metadata. Please enter a valid GTI API Key below.
                </p>
              </div>
            </div>
            <button
              onClick={() => setShowSettings(true)}
              className="px-4 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 font-sans text-xs font-bold rounded-lg border border-amber-500/30 transition-all cursor-pointer inline-flex items-center gap-1"
            >
              <span>Configure Keys</span>
            </button>
          </div>
        )}

        {/* API Keys Configuration Drawer */}
        {showSettings && (
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-2xl relative">
            <div className="flex justify-between items-center border-b border-slate-800/60 pb-3">
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-emerald-400" />
                <h3 className="text-sm font-sans font-black uppercase tracking-wider text-slate-200">
                  Credentials Configuration
                </h3>
              </div>
              <button
                onClick={() => setShowSettings(false)}
                className="text-[10px] font-mono text-slate-500 hover:text-slate-300 uppercase cursor-pointer"
              >
                Close [X]
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* GTI Key Input */}
              <div className="space-y-1.5">
                <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">
                  GTI API Key (VirusTotal API) <span className="text-amber-400">*Critical</span>
                </label>
                <div className="relative">
                  <input
                    type={showGtiPassword ? "text" : "password"}
                    placeholder={serverConfig?.hasServerGtiKey ? "Configured on Server (Optional override)" : "Enter GTI API Key..."}
                    value={tempGtiKey}
                    onChange={(e) => setTempGtiKey(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 focus:border-emerald-500/50 rounded-xl px-3 py-2.5 text-xs font-mono text-slate-200 placeholder-slate-600 outline-none pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowGtiPassword(!showGtiPassword)}
                    className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300 text-xs font-mono select-none"
                  >
                    {showGtiPassword ? "Hide" : "Show"}
                  </button>
                </div>
                <p className="text-[9px] text-slate-500 font-sans leading-relaxed">
                  Provides raw vulnerability records, severity levels, and associated collection feeds.
                </p>
              </div>

              {/* Gemini Key Input */}
              <div className="space-y-1.5">
                <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">
                  Gemini API Key (News Summarization)
                </label>
                <div className="relative">
                  <input
                    type={showGeminiPassword ? "text" : "password"}
                    placeholder={serverConfig?.hasServerGeminiKey ? "Configured on Server (Optional override)" : "Enter Gemini API Key..."}
                    value={tempGeminiKey}
                    onChange={(e) => setTempGeminiKey(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 focus:border-emerald-500/50 rounded-xl px-3 py-2.5 text-xs font-mono text-slate-200 placeholder-slate-600 outline-none pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowGeminiPassword(!showGeminiPassword)}
                    className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300 text-xs font-mono select-none"
                  >
                    {showGeminiPassword ? "Hide" : "Show"}
                  </button>
                </div>
                <p className="text-[9px] text-slate-500 font-sans leading-relaxed">
                  Required to search the live web and compile a concise 5-8 sentence news summary.
                </p>
              </div>
            </div>

            <div className="flex gap-2 pt-2 justify-end border-t border-slate-800/40">
              <button
                onClick={handleClearKeys}
                className="px-4 py-2 bg-slate-950 hover:bg-rose-950/20 text-rose-400 hover:text-rose-300 font-sans text-xs font-medium rounded-xl border border-slate-850 hover:border-rose-900/40 transition-all cursor-pointer"
              >
                Clear Keys
              </button>
              <button
                onClick={handleSaveKeys}
                className="px-5 py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-900 font-sans text-xs font-bold rounded-xl transition-all cursor-pointer"
              >
                Save Configuration
              </button>
            </div>
          </div>
        )}

        {/* Main search bar block */}
        <CveSearch onSearch={handleSearch} isLoading={isLoading} />

        {/* Quick info advisory / Diagnostic Feed */}
        {!report && !isLoading && !error && (
          <div className="p-4 bg-slate-900/20 border border-slate-900 rounded-2xl flex items-center gap-3">
            <Info className="w-4 h-4 text-emerald-400 shrink-0" />
            <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
              Google Threat Intelligence compiles CVE indicators from various registries. Grounded queries use automated web scraping vectors and Gemini synthesis to compile live remediation advisories.
            </p>
          </div>
        )}

        {/* Loading diagnostics console */}
        {isLoading && (
          <div className="p-12 bg-slate-950/60 border border-slate-900 rounded-3xl flex flex-col items-center justify-center text-center space-y-4 shadow-2xl animate-pulse">
            <div className="w-12 h-12 border-4 border-emerald-500 border-t-transparent rounded-full animate-spin shadow-lg shadow-emerald-950/20" />
            <div className="space-y-1.5 pt-2">
              <span className="text-sm font-mono text-emerald-400 font-bold uppercase tracking-wider">
                Analyzing Threat Surface
              </span>
              <p className="text-xs text-slate-500 font-mono italic max-w-sm mx-auto">
                {LOADING_STEPS[loadStepIdx]}
              </p>
            </div>
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="p-6 bg-rose-500/10 border border-rose-500/20 rounded-2xl flex flex-col space-y-2 items-start">
            <span className="text-sm font-mono text-rose-400 font-bold uppercase">Intelligence Fetch Error</span>
            <p className="text-xs text-slate-300 leading-relaxed font-sans">{error}</p>
          </div>
        )}

        {/* CVE Report Results Panel */}
        {report && !isLoading && (
          <div className="space-y-6 animate-fade-in">

            {/* Report Header Card */}
            <div className="bg-slate-950/60 border border-slate-900 rounded-2xl p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 relative overflow-hidden">
              <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-emerald-500/5 to-transparent rounded-bl-full pointer-events-none" />
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-2xl font-mono font-black text-emerald-400 selection:bg-emerald-500/50">
                    {report.cveId}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 bg-slate-900 text-slate-400 border border-slate-800 rounded-md">
                    Data Source: {
                      report.dataSource === 'GTI_API' ? 'Direct GTI API' :
                        report.dataSource === 'MOCK' ? 'Fallback Local Intelligence Compiler' :
                          'Grounded Gemini Intelligence'
                    }
                  </span>
                </div>
                <h3 className="text-lg font-sans font-bold text-slate-100 leading-tight">
                  {report.title}
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed font-sans max-w-2xl">
                  {report.description}
                </p>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={copyJsonReport}
                  className="p-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-xl text-slate-400 hover:text-slate-200 transition-all font-sans text-xs flex items-center gap-1.5 cursor-pointer"
                  title="Copy full JSON report to clipboard"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>{isCopied ? 'Copied!' : 'Export JSON'}</span>
                </button>
              </div>
            </div>

            {/* Gemini Live News Summary Block */}
            {news && (
              <div className="bg-slate-900/40 border border-emerald-500/20 rounded-2xl p-6 space-y-4 relative overflow-hidden">
                <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-br from-emerald-500/5 to-transparent rounded-bl-full pointer-events-none" />
                <div className="flex items-center justify-between gap-2 border-b border-slate-800/60 pb-3">
                  <div className="flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-emerald-400 shrink-0" />
                    <h4 className="text-sm font-sans font-bold text-slate-200 uppercase tracking-wider">
                      Latest News & Security Advisory Summary
                    </h4>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-md">
                    Gemini Search Grounded
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {news.summary}
                </p>

                {news.sources && news.sources.length > 0 && (
                  <div className="pt-2 border-t border-slate-800/40">
                    <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-2">
                      Verified News Sources
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {news.sources.map((src: any, idx: number) => (
                        <a
                          key={idx}
                          href={sanitizeUrl(src.url)}
                          target="_blank"
                          referrerPolicy="no-referrer"
                          className="inline-flex items-center gap-1 text-[10px] text-slate-400 hover:text-emerald-400 bg-slate-900/60 border border-slate-800 px-2 py-1 rounded-md transition-all font-mono"
                        >
                          <span>{src.title}</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Navigation Tabs */}
            <div className="flex border-b border-slate-900 bg-slate-950 p-1 rounded-xl gap-2">
              <button
                onClick={() => setActiveTab('overview')}
                className={`flex-1 py-3 text-xs font-sans font-bold rounded-lg transition-all cursor-pointer ${activeTab === 'overview'
                    ? 'bg-slate-900 text-slate-100 border-b-2 border-emerald-500'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
                  }`}
              >
                Overview & Severity Metrics
              </button>
              <button
                onClick={() => setActiveTab('exploits')}
                className={`flex-1 py-3 text-xs font-sans font-bold rounded-lg transition-all cursor-pointer ${activeTab === 'exploits'
                    ? 'bg-slate-900 text-slate-100 border-b-2 border-emerald-500'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
                  }`}
              >
                Exploits & Threat Actors
              </button>
              <button
                onClick={() => setActiveTab('remediation')}
                className={`flex-1 py-3 text-xs font-sans font-bold rounded-lg transition-all cursor-pointer ${activeTab === 'remediation'
                    ? 'bg-slate-900 text-slate-100 border-b-2 border-emerald-500'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
                  }`}
              >
                Actionable Remediation
              </button>
            </div>

            {/* Tab Content Rendering */}
            <div className="space-y-6">
              {activeTab === 'overview' && <CveMetrics report={report} />}
              {activeTab === 'exploits' && <CveExploits report={report} associations={associations} />}
              {activeTab === 'remediation' && <CveRemediation report={report} />}
            </div>

          </div>
        )}

        {/* Initial landing instruction card when no report is shown */}
        {!report && !isLoading && !error && (
          <div className="p-12 bg-slate-950/60 border border-slate-900 rounded-3xl text-center space-y-4 max-w-xl mx-auto mt-6 relative overflow-hidden">
            <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-br from-emerald-500/5 to-transparent rounded-bl-full pointer-events-none" />
            <div className="p-3 bg-slate-900 border border-slate-800 rounded-2xl text-slate-400 inline-block">
              <Terminal className="w-8 h-8 text-emerald-500" />
            </div>
            <div className="space-y-1">
              <h4 className="text-sm font-sans font-bold text-slate-200 uppercase tracking-wider">Awaiting Threat Indicator Query</h4>
              <p className="text-xs text-slate-400 leading-relaxed font-sans">
                Enter any CVE code in the intelligence search bar above to synthesize a live threat assessment.
              </p>
            </div>
          </div>
        )}

      </main>

      {/* Modern footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 text-center text-[10px] font-mono text-slate-500 uppercase tracking-widest mt-auto">
        Threat intelligence platform &bull; Powered by Google Threat Intelligence and Gemini v3
      </footer>

    </div>
  );
}
