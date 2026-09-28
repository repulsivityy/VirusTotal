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
  AlertCircle,
  Database,
  KeyRound,
  Layers,
  Cpu,
  ShieldCheck,
  Activity,
  Check
} from 'lucide-react';
import {
  CompensatingControlId,
  ImpactFactorId,
  RbvmConfig,
  ReachabilityTierId
} from '../types';
import {
  computeAssetScore,
  computeControlMultiplier,
  IMPACT_SCORES,
  REACHABILITY_SCORES
} from '../utils';

interface RiskContextPanelProps {
  config: RbvmConfig;
  onChange: (newConfig: RbvmConfig) => void;
}

interface ReachabilityOption {
  id: ReachabilityTierId;
  label: string;
  score: number;
  description: string;
  icon: React.ReactNode;
}

interface ImpactOption {
  id: ImpactFactorId;
  label: string;
  score: number;
  description: string;
  exclusiveWith?: ImpactFactorId;
  icon: React.ReactNode;
}

interface ControlOption {
  id: CompensatingControlId;
  label: string;
  reductionLabel: string;
  description: string;
  icon: React.ReactNode;
}

const REACHABILITY_OPTIONS: ReachabilityOption[] = [
  {
    id: 'internet',
    label: 'Internet-Facing',
    score: REACHABILITY_SCORES.internet,
    description: 'Directly reachable from the public internet.',
    icon: <Globe className="w-4 h-4 text-rose-400" />
  },
  {
    id: 'internal',
    label: 'Internal Network',
    score: REACHABILITY_SCORES.internal,
    description: 'Accessible only within internal corporate networks.',
    icon: <Server className="w-4 h-4 text-amber-400" />
  },
  {
    id: 'isolated',
    label: 'Isolated / Air-Gapped',
    score: REACHABILITY_SCORES.isolated,
    description: 'Strictly segmented or isolated network zone.',
    icon: <Lock className="w-4 h-4 text-emerald-400" />
  }
];

const IMPACT_OPTIONS: ImpactOption[] = [
  {
    id: 'sensitive_data',
    label: 'Hosts Sensitive Data',
    score: IMPACT_SCORES.sensitive_data,
    description: 'Stores customer PII, financial, or regulated data.',
    icon: <Database className="w-4 h-4 text-rose-400" />
  },
  {
    id: 'tier0_auth',
    label: 'Tier-0 Auth',
    score: IMPACT_SCORES.tier0_auth,
    description: 'Core identity, SSO/IAM, domain controller, or PKI.',
    icon: <KeyRound className="w-4 h-4 text-orange-400" />
  },
  {
    id: 'prod_env',
    label: 'Production Environment',
    score: IMPACT_SCORES.prod_env,
    description: 'Live customer-facing or operational business workload.',
    exclusiveWith: 'dev_env',
    icon: <Layers className="w-4 h-4 text-amber-400" />
  },
  {
    id: 'dev_env',
    label: 'Staging / Dev Environment',
    score: IMPACT_SCORES.dev_env,
    description: 'Non-production test, QA, or sandbox environment.',
    exclusiveWith: 'prod_env',
    icon: <Cpu className="w-4 h-4 text-sky-400" />
  }
];

const CONTROL_OPTIONS: ControlOption[] = [
  {
    id: 'inline_enforcement',
    label: 'Inline Network Enforcement',
    reductionLabel: '-15%',
    description: 'Active WAF, IPS, or L7 firewall blocking exploit traffic.',
    icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />
  },
  {
    id: 'runtime_detection',
    label: 'Runtime / Behavioral Detection',
    reductionLabel: '-15%',
    description: 'EDR / XDR agent with active behavioral prevention.',
    icon: <Activity className="w-4 h-4 text-teal-400" />
  }
];

export default function RiskContextPanel({ config, onChange }: RiskContextPanelProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const selectedReachability = config.reachability ?? null;
  const selectedImpacts = config.impactFactors ?? [];
  const selectedControls = config.compensatingControls ?? [];

  const { multiplier: controlMultiplier, reductionPct: controlReductionPct } =
    computeControlMultiplier(selectedControls);

  const weightSum = Math.round((config.weights.w1 + config.weights.w2 + config.weights.w3) * 100) / 100;
  const isWeightSumValid = Math.abs(weightSum - 1.0) < 0.01;

  const handleSelectReachability = (tierId: ReachabilityTierId) => {
    const nextReachability = selectedReachability === tierId ? null : tierId;
    const nextSAsset = computeAssetScore(nextReachability, selectedImpacts);
    onChange({
      ...config,
      reachability: nextReachability,
      sAsset: nextSAsset,
      assetPresetId: undefined
    });
  };

  const handleToggleImpact = (option: ImpactOption) => {
    const exists = selectedImpacts.includes(option.id);
    let nextImpacts: ImpactFactorId[];
    if (exists) {
      nextImpacts = selectedImpacts.filter((id) => id !== option.id);
    } else {
      // Remove mutually exclusive counterpart (e.g., prod_env vs dev_env)
      const filtered = option.exclusiveWith
        ? selectedImpacts.filter((id) => id !== option.exclusiveWith)
        : selectedImpacts;
      nextImpacts = [...filtered, option.id];
    }

    const nextSAsset = computeAssetScore(selectedReachability, nextImpacts);
    onChange({
      ...config,
      impactFactors: nextImpacts,
      sAsset: nextSAsset,
      assetPresetId: undefined
    });
  };

  const handleToggleControl = (controlId: CompensatingControlId) => {
    const exists = selectedControls.includes(controlId);
    const nextControls = exists
      ? selectedControls.filter((id) => id !== controlId)
      : [...selectedControls, controlId];

    onChange({
      ...config,
      compensatingControls: nextControls
    });
  };

  const handleClearAsset = () => {
    onChange({
      ...config,
      sAsset: null,
      assetPresetId: undefined,
      reachability: null,
      impactFactors: [],
      compensatingControls: []
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
  const rawUncappedAsset =
    (selectedReachability ? REACHABILITY_SCORES[selectedReachability] : 0) +
    selectedImpacts.reduce((sum, id) => sum + IMPACT_SCORES[id], 0);

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
              <div className="flex items-center gap-2 flex-wrap">
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
                {controlReductionPct > 0 && (
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-teal-500/15 text-teal-300 border border-teal-500/30">
                    Controls: -{controlReductionPct}% (×{controlMultiplier})
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                {isContextActive
                  ? 'Asset context active — RBVM score dynamically calculated with reachability, criticality & controls.'
                  : 'Select reachability, criticality checkboxes, and compensating controls to compute a contextualized RBVM score.'}
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
            {/* Top summary & Clear button */}
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="text-xs text-slate-400">
                Build <span className="font-mono text-slate-200">S_asset</span> from{' '}
                <span className="text-slate-200 font-semibold">Base Reachability</span> +{' '}
                <span className="text-slate-200 font-semibold">Impact / Criticality</span> (capped at 100), then apply{' '}
                <span className="text-emerald-400 font-semibold">Compensating Controls</span>.
              </div>
              {(config.sAsset !== null || selectedControls.length > 0) && (
                <button
                  type="button"
                  onClick={handleClearAsset}
                  className="text-xs font-mono text-slate-400 hover:text-rose-400 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 hover:border-rose-500/30 transition-colors cursor-pointer"
                >
                  Clear All Context (Intel Only)
                </button>
              )}
            </div>

            {/* Section 1: Base Reachability (Mutually Exclusive) */}
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold">
                    1. Base Reachability (Mutually Exclusive)
                  </h4>
                  <p className="text-[11px] text-slate-400">
                    Select one network exposure baseline. Clicking an active tier deselects it.
                  </p>
                </div>
                <span className="text-xs font-mono text-slate-400">
                  Base:{' '}
                  <strong className="text-slate-200">
                    +{selectedReachability ? REACHABILITY_SCORES[selectedReachability] : 0} pts
                  </strong>
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {REACHABILITY_OPTIONS.map((opt) => {
                  const isSelected = selectedReachability === opt.id;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => handleSelectReachability(opt.id)}
                      className={`text-left p-3.5 rounded-xl border transition-all cursor-pointer flex flex-col justify-between ${
                        isSelected
                          ? 'bg-emerald-500/10 border-emerald-500/50 shadow-lg shadow-emerald-950/30'
                          : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700'
                      }`}
                    >
                      <div>
                        <div className="flex items-center justify-between gap-2 mb-2">
                          <div className="p-1.5 rounded-lg bg-slate-950/80 border border-slate-800">
                            {opt.icon}
                          </div>
                          <span
                            className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                              isSelected
                                ? 'bg-emerald-500 text-slate-950'
                                : 'bg-slate-800 text-slate-300'
                            }`}
                          >
                            +{opt.score}
                          </span>
                        </div>
                        <div className="text-xs font-semibold text-slate-200 mb-1">
                          {opt.label}
                        </div>
                        <p className="text-[11px] text-slate-400 leading-relaxed">
                          {opt.description}
                        </p>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Section 2: Impact / Criticality Checkboxes */}
            <div className="space-y-2.5 pt-2 border-t border-slate-800/60">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold">
                    2. Impact / Criticality (Additive Checkboxes)
                  </h4>
                  <p className="text-[11px] text-slate-400">
                    Check all that apply. Production (+20) and Staging/Dev (+5) are mutually exclusive.
                  </p>
                </div>
                <span className="text-xs font-mono text-slate-400">
                  S_asset:{' '}
                  <strong className="text-emerald-400">
                    {config.sAsset ?? 0}/100
                  </strong>
                  {rawUncappedAsset > 100 && (
                    <span className="text-amber-400 ml-1">(Raw {rawUncappedAsset} capped at 100)</span>
                  )}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {IMPACT_OPTIONS.map((opt) => {
                  const isChecked = selectedImpacts.includes(opt.id);
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => handleToggleImpact(opt)}
                      className={`text-left p-3.5 rounded-xl border transition-all cursor-pointer flex items-start gap-3 ${
                        isChecked
                          ? 'bg-emerald-500/10 border-emerald-500/50 shadow-md shadow-emerald-950/20'
                          : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700'
                      }`}
                    >
                      <div
                        className={`mt-0.5 w-4 h-4 rounded flex items-center justify-center border shrink-0 transition-colors ${
                          isChecked
                            ? 'bg-emerald-500 border-emerald-400 text-slate-950'
                            : 'bg-slate-950 border-slate-700 text-transparent'
                        }`}
                      >
                        <Check className="w-3 h-3 stroke-[3]" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                            {opt.icon}
                            <span>{opt.label}</span>
                          </span>
                          <span
                            className={`text-xs font-mono font-bold px-2 py-0.5 rounded shrink-0 ${
                              isChecked
                                ? 'bg-emerald-500 text-slate-950'
                                : 'bg-slate-800 text-slate-300'
                            }`}
                          >
                            +{opt.score}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                          {opt.description}
                        </p>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Section 3: Compensating Controls (Compounding % Reduction) */}
            <div className="space-y-2.5 pt-2 border-t border-slate-800/60">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold">
                    3. Compensating Controls (Compounding % Reduction)
                  </h4>
                  <p className="text-[11px] text-slate-400">
                    Each control reduces the remaining weighted risk score by 15% (both = ×0.85 × 0.85 = -27.75%).
                  </p>
                </div>
                <span className="text-xs font-mono text-teal-400 font-semibold">
                  {controlReductionPct > 0
                    ? `Active Reduction: -${controlReductionPct}% (×${controlMultiplier})`
                    : 'No controls active (×1.00)'}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {CONTROL_OPTIONS.map((ctrl) => {
                  const isChecked = selectedControls.includes(ctrl.id);
                  return (
                    <button
                      key={ctrl.id}
                      type="button"
                      onClick={() => handleToggleControl(ctrl.id)}
                      className={`text-left p-3.5 rounded-xl border transition-all cursor-pointer flex items-start gap-3 ${
                        isChecked
                          ? 'bg-teal-500/10 border-teal-500/50 shadow-md shadow-teal-950/20'
                          : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700'
                      }`}
                    >
                      <div
                        className={`mt-0.5 w-4 h-4 rounded flex items-center justify-center border shrink-0 transition-colors ${
                          isChecked
                            ? 'bg-teal-400 border-teal-300 text-slate-950'
                            : 'bg-slate-950 border-slate-700 text-transparent'
                        }`}
                      >
                        <Check className="w-3 h-3 stroke-[3]" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                            {ctrl.icon}
                            <span>{ctrl.label}</span>
                          </span>
                          <span
                            className={`text-xs font-mono font-bold px-2 py-0.5 rounded shrink-0 ${
                              isChecked
                                ? 'bg-teal-400 text-slate-950'
                                : 'bg-slate-800 text-teal-300'
                            }`}
                          >
                            {ctrl.reductionLabel}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                          {ctrl.description}
                        </p>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Section 4: Risk Appetite Weights */}
            <div className="pt-2 border-t border-slate-800/60">
              <div className="bg-slate-900/50 border border-slate-800/80 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold">
                      4. Pillar Weights (W₁ + W₂ + W₃ = 1.0)
                    </h4>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      Final Score = [(W₁ × S_vuln) + (W₂ × S_asset) + (W₃ × S_threat)] × Control Multiplier
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
