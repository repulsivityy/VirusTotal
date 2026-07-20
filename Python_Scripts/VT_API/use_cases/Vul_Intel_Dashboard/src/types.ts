export interface ExploitPatterns {
  exploitedInTheWild: boolean;
  pocAvailable: boolean;
  threatActors: string[];
  technicalDetails: string;
}

export interface ReferenceLink {
  title: string;
  url: string;
}

export interface Remediation {
  status: string;
  fixedVersions: string[];
  steps: string[];
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

export interface CveReport {
  cveId: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cvssScore: number;
  cvssVector: string;
  epssScore?: number;
  publishedDate: string;
  lastModifiedDate?: string;
  exploitPatterns: ExploitPatterns;
  remediation: Remediation;
  affectedProducts: AffectedProduct[];
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
