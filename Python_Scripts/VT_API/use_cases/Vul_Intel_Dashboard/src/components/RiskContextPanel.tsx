import React, { useState } from 'react';
import {
  Sliders,
  ChevronDown,
  ChevronUp,
  Server,
  Globe,
  Shield,
  Lock,
  RotateCcw,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { RbvmConfig } from '../types';

interface RiskContextPanelProps {
  config: RbvmConfig;
  onChange: (newConfig: RbvmConfig) => void;
}

interface AssetPreset {
  id: string;
  label: string;
  score: number;
  exposure: string;
  sensitivity: string;
  description: string;
  icon: React.ReactNode;
}

const ASSET_PRESETS: AssetPreset[] = [
  {
    id: 'tier-100',
    label: 'Internet-Facing + Customer PII',
    score: 100,
    exposure: 'Internet-Facing',
    sensitivity: 'Customer / Regulated PII',
    description: 'Publicly reachable asset holding sensitive customer or regulated data.',
    icon: <Globe className="w-4 h-4 text-rose-400" />
  },
  {
    id: 'tier-75',
    label: 'External (No PII) / Internal PII',
    score: 75,
    exposure: 'External or Internal Core',
    sensitivity: 'High Business / Internal PII',
    description: 'Internet-facing asset with non-sensitive data, or internal asset holding PII.',
    icon: <Shield className="w-4 h-4 text-orange-400" />
  },
  {
    id: 'tier-50',
    label: 'Internal Business System',
    score: 50,
    exposure: 'Internal Network',
    sensitivity: 'Internal Operational',
    description: 'Standard internal corporate infrastructure or application.',
    icon: <Server className="w-4 h-4 text-amber-400" />
  },
  {
    id: 'tier-25',
    label: 'Internal-Only / Non-Sensitive',
    score: 25,
    exposure: 'Isolated / Internal',
    sensitivity: 'No Sensitive Data',
    description: 'Internal-only, segmented, or dev/test asset with no sensitive data.',
    icon: <Lock className="w-4 h-4 text-emerald-400" />
  }
];

export default function RiskContextPanel({ config, onChange }: RiskContextPanelProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const weightSum = Math.round((config.weights.w1 + config.weights.w2 + config.weights.w3) * 100) / 100;
  const isWeightSumValid = Math.abs(weightSum - 1.0) < 0.01;

  const handleSelectPreset = (preset: AssetPreset) => {
    if (config.assetPresetId === preset.id && config.sAsset === preset.score) {
      // Clicking active preset deselects back to pure GTI mode (null)
      onChange({
        ...config,
        sAsset: null,
        assetPresetId: undefined
      });
    } else {
      onChange({
        ...config,
        sAsset: preset.score,
        assetPresetId: preset.id
      });
    }
  };

  const handleClearAsset = () => {
    onChange({
      ...config,
      sAsset: null,
      assetPresetId: undefined
    });
  };

  const handleCustomAssetScore = (val: number) => {
    const clamped = Math.min(100, Math.max(0, val));
    onChange({
      ...config,
      sAsset: clamped,
      assetPresetId: 'custom'
    });
  };

  const handleWeightChange = (key: 'w1' | 'w2' | 'w3', rawVal: string) => {
    const parsed = parseFloat(rawVal);
    const safeVal = Number.isNaN(parsed) ? 0 : Math.min(1, Math.max(0, Math.round(parsed * 100) / 100));
    onChange({
      ...config,
      weights: {
        ...config.weights,
        [key]: safeVal
      }
    });
  };

  const handleResetWeights = () => {
    onChange({
      ...config,
      weights: { w1: 0.2, w2: 0.4, w3: 0.4 }
    });
  };

  const isContextActive = config.sAsset !== null;

  return (
    <div className="w-full max-w-4xl mx-auto">
      <div className="bg-slate-900/70 border border-slate-800/90 rounded-2xl overflow-hidden transition-all">
        {/* Toggle Header Bar */}
        <button
          type="button"
          onClick={() => setIsExpanded(!isExpanded)}
          className="w-full px-5 py-3.5 flex items-center justify-between text-left hover:bg-slate-900/90 transition-colors cursor-pointer"
        >
          <div className="flex items-center gap-3 flex-wrap">
            <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <Sliders className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <span className="text-sm font-semibold text-slate-200">
                  Organization Risk Context
                </span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  Optional RBVM
                </span>
                {config.sAsset !== null && (
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                    S_asset: {config.sAsset}/100
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                {isContextActive
                  ? 'Asset context active — RBVM score will be calculated alongside GTI telemetry.'
                  : 'Add asset exposure (e.g., internet-facing + PII) to calculate a contextualized RBVM score.'}
              </p>
            </div>
          </div>
          <div className="text-slate-400 flex items-center gap-1.5 text-xs font-mono shrink-0 ml-4">
            <span>{isExpanded ? 'Hide' : 'Configure'}</span>
            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </button>

        {/* Expandable Configuration Body */}
        {isExpanded && (
          <div className="px-5 pb-5 pt-3 border-t border-slate-800/80 space-y-6 bg-slate-950/40">
            {/* Section 1: Asset Context (S_asset) */}
            <div className="space-y-3">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold">
                    1. Asset Context (S_asset: Exposure & Data Sensitivity)
                  </h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Select an asset profile to enable the RBVM score. Leave unselected to view pure GTI intelligence only.
                  </p>
                </div>
                {config.sAsset !== null && (
                  <button
                    type="button"
                    onClick={handleClearAsset}
                    className="text-xs font-mono text-slate-400 hover:text-rose-400 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 hover:border-rose-500/30 transition-colors cursor-pointer"
                  >
                    Clear Asset Context (Intel Only)
                  </button>
                )}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {ASSET_PRESETS.map((preset) => {
                  const isSelected =
                    config.assetPresetId === preset.id ||
                    (config.assetPresetId === undefined && config.sAsset === preset.score);
                  return (
                    <button
                      key={preset.id}
                      type="button"
                      onClick={() => handleSelectPreset(preset)}
                      className={`text-left p-3.5 rounded-xl border transition-all cursor-pointer flex flex-col justify-between ${
                        isSelected
                          ? 'bg-emerald-500/10 border-emerald-500/50 shadow-lg shadow-emerald-950/30'
                          : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700'
                      }`}
                    >
                      <div>
                        <div className="flex items-center justify-between gap-2 mb-2">
                          <div className="p-1.5 rounded-lg bg-slate-950/80 border border-slate-800">
                            {preset.icon}
                          </div>
                          <span
                            className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                              isSelected
                                ? 'bg-emerald-500 text-slate-950'
                                : 'bg-slate-800 text-slate-300'
                            }`}
                          >
                            Score: {preset.score}
                          </span>
                        </div>
                        <div className="text-xs font-semibold text-slate-200 mb-1">
                          {preset.label}
                        </div>
                        <p className="text-[11px] text-slate-400 leading-relaxed">
                          {preset.description}
                        </p>
                      </div>
                      <div className="mt-3 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] font-mono text-slate-400">
                        <span>{preset.exposure}</span>
                        <span>•</span>
                        <span>{preset.sensitivity}</span>
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* Fine-tune slider when asset context is enabled */}
              {config.sAsset !== null && (
                <div className="flex items-center gap-4 bg-slate-900/60 border border-slate-800/80 rounded-xl px-4 py-2.5">
                  <span className="text-xs font-mono text-slate-400 whitespace-nowrap">
                    Fine-tune S_asset:
                  </span>
                  <input
                    type="range"
                    min={0}
                    max={100}
                    step={5}
                    value={config.sAsset}
                    onChange={(e) => handleCustomAssetScore(Number(e.target.value))}
                    className="w-full accent-emerald-500 cursor-pointer"
                  />
                  <span className="text-sm font-mono font-bold text-emerald-400 w-14 text-right">
                    {config.sAsset}/100
                  </span>
                </div>
              )}
            </div>

            {/* Section 2: Risk Appetite Weights */}
            <div className="pt-2 border-t border-slate-800/60">
              {/* Risk Appetite Weights (W1, W2, W3) */}
              <div className="bg-slate-900/50 border border-slate-800/80 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold">
                      2. Risk Appetite Weights (W₁ + W₂ + W₃ = 1.0)
                    </h4>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      Final Score = (W₁ × S_vuln) + (W₂ × S_asset) + (W₃ × S_threat)
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={handleResetWeights}
                    className="inline-flex items-center gap-1 text-[11px] font-mono text-slate-400 hover:text-slate-200 px-2 py-1 rounded bg-slate-800/80 hover:bg-slate-800 transition-colors cursor-pointer"
                    title="Reset weights to 0.20 / 0.40 / 0.40"
                  >
                    <RotateCcw className="w-3 h-3" />
                    <span>Reset</span>
                  </button>
                </div>

                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="block text-[11px] font-mono text-slate-400 mb-1">
                      W₁ (Vuln / CVSS)
                    </label>
                    <input
                      type="number"
                      min={0}
                      max={1}
                      step={0.05}
                      value={config.weights.w1}
                      onChange={(e) => handleWeightChange('w1', e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:border-emerald-500/50 outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-mono text-slate-400 mb-1">
                      W₂ (Asset Context)
                    </label>
                    <input
                      type="number"
                      min={0}
                      max={1}
                      step={0.05}
                      value={config.weights.w2}
                      onChange={(e) => handleWeightChange('w2', e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:border-emerald-500/50 outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-mono text-slate-400 mb-1">
                      W₃ (GTI Threat)
                    </label>
                    <input
                      type="number"
                      min={0}
                      max={1}
                      step={0.05}
                      value={config.weights.w3}
                      onChange={(e) => handleWeightChange('w3', e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:border-emerald-500/50 outline-none"
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between text-[11px] font-mono pt-1">
                  <span className="text-slate-400">Total Weight Sum:</span>
                  <span
                    className={`inline-flex items-center gap-1 font-semibold ${
                      isWeightSumValid ? 'text-emerald-400' : 'text-amber-400'
                    }`}
                  >
                    {isWeightSumValid ? (
                      <CheckCircle2 className="w-3.5 h-3.5" />
                    ) : (
                      <AlertCircle className="w-3.5 h-3.5" />
                    )}
                    <span>{weightSum.toFixed(2)}</span>
                    {!isWeightSumValid && <span>(Will be scaled to 1.00)</span>}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
