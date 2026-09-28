export interface CisaKevInfo {
  addedDate?: string;
  dueDate?: string;
  ransomwareUse?: string;
}

export interface ExploitPatterns {
  exploitedInTheWild: boolean;
  pocAvailable: boolean;
  exploitationState?: string;
  exploitAvailability?: string;
  exploitationConsequence?: string;
  exploitationVectors?: string[];
  firstExploitationDate?: string;
  exploitReleaseDate?: string;
  techDetailsReleaseDate?: string;
  cisaKev?: CisaKevInfo;
  riskFactors?: string[];
  tags?: string[];
  threatActors: string[];
  technicalDetails: string;
}

export interface ReferenceLink {
  title: string;
  url: string;
  sourceName?: string;
  uniqueId?: string;
  publishedDate?: string;
}

export interface Remediation {
  status: string;
  availableMitigation?: string[];
  daysToPatch?: number | null;
  fixedVersions: string[];
  steps: string[];
  vendorFixReferences?: ReferenceLink[];
  references: ReferenceLink[];
}

export interface AffectedProduct {
  vendor: string;
  product: string;
  versions: string;
}

export interface GroundingSource {
  title: string;
  url: string;
}

export interface CvssDetails {
  cvssv3?: {
    baseScore?: number | null;
    temporalScore?: number | null;
    vector?: string | null;
  };
  cvssv3Translated?: {
    baseScore?: number | null;
    temporalScore?: number | null;
    vector?: string | null;
  };
  cvssv4?: {
    score?: number | null;
    vector?: string | null;
    exploitMaturity?: string | null;
  };
}

export interface CveReport {
  cveId: string;
  mveId?: string;
  title: string;
  description: string;
  executiveSummary?: string;
  analysis?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  riskRating?: string;
  predictedRiskRating?: string;
  priority?: string;
  cvssScore: number | null;
  cvssVector: string;
  cvssDetails?: CvssDetails;
  epssScore?: number;
  epssPercentile?: number;
  cwe?: {
    id: string;
    title: string;
  };
  publishedDate: string;
  creationDate?: string;
  lastModifiedDate?: string;
  exploitPatterns: ExploitPatterns;
  remediation: Remediation;
  affectedProducts: AffectedProduct[];
  counters?: AssociationCounters;
  targetedIndustries?: string[];
  targetedRegions?: string[];
  operatingSystems?: string[];
  gtiInsights: string;
  groundingSources?: GroundingSource[];
  dataSource: 'GTI_API' | 'GEMINI_GROUNDED' | 'MOCK';
}

export interface AssociationCounters {
  files?: number;
  domains?: number;
  ipAddresses?: number;
  urls?: number;
  iocs?: number;
  subscribers?: number;
  attackTechniques?: number;
}

export interface CveAssociation {
  id: string;
  type: string;
  collectionType: 'campaign' | 'threat-actor' | 'malware' | string;
  name: string;
  description: string;
  origin?: string;
  creationDate?: string;
  lastModificationDate?: string;
  counters?: AssociationCounters;
  targetedRegions?: string[];
  sourceRegion?: string;
  altNames?: string[];
  motivations?: string[];
}

export type ReachabilityTierId = 'internet' | 'internal' | 'isolated';

export type ImpactFactorId = 'sensitive_data' | 'tier0_auth' | 'prod_env' | 'dev_env';

export type CompensatingControlId = 'inline_enforcement' | 'runtime_detection';

export interface RbvmWeights {
  w1: number; // Vulnerability weight (default 0.20)
  w2: number; // Asset context weight (default 0.40)
  w3: number; // Threat likelihood weight (default 0.40)
}

export interface RbvmConfig {
  sAsset: number | null; // null = no asset input provided (do not show RBVM score)
  assetPresetId?: string;
  reachability?: ReachabilityTierId | null;
  impactFactors?: ImpactFactorId[];
  compensatingControls?: CompensatingControlId[];
  weights: RbvmWeights;
}

export interface RbvmBreakdown {
  finalScore: number;
  rawWeightedScore: number; // Weighted score before compensating control dampening
  sVuln: number;
  sAsset: number;
  sThreat: number;
  baseThreatTier: 100 | 75 | 25 | 10;
  baseThreatReason: string;
  epssMultiplier: 1.0 | 1.1 | 1.25 | 1.5;
  epssFloorApplied: boolean;
  controlMultiplier: number; // Compounded multiplier, e.g. 0.85 * 0.85 = 0.7225
  controlReductionPct: number; // Effective % reduction, e.g. 27.75
  weights: RbvmWeights; // Effective (normalized) weights used in the calculation
  weightsNormalized: boolean; // True if user weights did not sum to 1.0 and were scaled
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}


