export type Rating = 'A' | 'B' | 'C' | 'D' | 'E';

export type QualityGateStatus = 'PASSED' | 'FAILED' | 'WARN';

export type IssueSeverity = 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO';

export type IssueType = 'BUG' | 'VULNERABILITY' | 'CODE_SMELL' | 'SECURITY_HOTSPOT';

export type IssueStatus = 'OPEN' | 'CONFIRMED' | 'RESOLVED' | 'CLOSED';

export type IssueResolution = 'FIXED' | 'WONT_FIX' | 'FALSE_POSITIVE';

export interface ProjectMetrics {
  bugs: number;
  bugsRating: Rating;
  vulnerabilities: number;
  vulnerabilitiesRating: Rating;
  securityHotspots: number;
  securityHotspotsReviewed: number; // percentage
  codeSmells: number;
  codeSmellsRating: Rating;
  debtMinutes: number;
  coverage: number; // percentage
  uncoveredLines: number;
  duplications: number; // percentage
  duplicatedBlocks: number;
  ncloc: number; // lines of code
  newBugs?: number;
  newVulnerabilities?: number;
  newCodeSmells?: number;
  newCoverage?: number;
  newDuplications?: number;
}

export interface SparklinePoint {
  date: string;
  bugs: number;
  codeSmells: number;
  coverage: number;
}

export interface Branch {
  name: string;
  isMain: boolean;
  status: QualityGateStatus;
  lastAnalysis: string;
}

export interface Project {
  key: string;
  name: string;
  description: string;
  qualityGateStatus: QualityGateStatus;
  failedGateConditions?: string[];
  metrics: ProjectMetrics;
  lastAnalysisDate: string;
  tags: string[];
  language: string;
  branches: Branch[];
  sparkline: SparklinePoint[];
  visibility: 'public' | 'private';
}

export interface DataFlowStep {
  step: number;
  file: string;
  line: number;
  code: string;
  description: string;
}

export interface CodeLine {
  line: number;
  code: string;
  isCovered?: boolean;
  isUncovered?: boolean;
  isDuplicated?: boolean;
  issueId?: string;
  issueSeverity?: IssueSeverity;
  issueMessage?: string;
}

export interface Issue {
  id: string;
  key: string;
  ruleKey: string;
  ruleName: string;
  severity: IssueSeverity;
  type: IssueType;
  status: IssueStatus;
  resolution?: IssueResolution;
  message: string;
  projectKey: string;
  projectName: string;
  component: string; // file path
  line: number;
  effortMinutes: number;
  assignee?: string;
  author: string;
  creationDate: string;
  updateDate: string;
  tags: string[];
  cleanCodeAttribute?: string;
  codeSnippet?: CodeLine[];
  dataFlowTrace?: DataFlowStep[];
  ruleDescription?: {
    why: string;
    howToFix: string;
    nonCompliant: string;
    compliant: string;
  };
}

/// Mirrors the server's flat GateConditionDto — no per-project assignment,
/// no inheritance, no NEW_CODE/OVERALL period (Fase 4 is deliberately minimal).
export interface QualityGateCondition {
  metric: string;
  operator: 'gt' | 'lt';
  threshold: number;
}

export interface QualityGate {
  name: string;
  conditions: QualityGateCondition[];
}

/// Mirrors the server's ProfileActivationDto/ProfileDto.
export interface QualityProfileActivation {
  rule: string;
  severity: 'info' | 'minor' | 'major' | 'critical' | 'blocker';
}

export interface QualityProfile {
  name: string;
  activations: QualityProfileActivation[];
}

export interface MetricDefinition {
  key: string;
  name: string;
  category: 'RELIABILITY' | 'SECURITY' | 'SECURITY_REVIEW' | 'MAINTAINABILITY' | 'COVERAGE' | 'DUPLICATIONS' | 'SIZE' | 'COMPLEXITY';
  type: 'INT' | 'PERCENT' | 'WORK_DUR' | 'RATING';
  description: string;
}

/// Mirrors the server's RuleDto (GET /rules) — the real analyzer catalog.
export interface RuleDefinition {
  id: string;
  description: string;
  tags: string[];
  cwe?: number;
  defaultSeverity: string;
  remediationEffortMinutes: number;
  producesHotspots: boolean;
}

export interface FileNode {
  path: string;
  name: string;
  type: 'file' | 'dir';
  ncloc?: number;
  bugs?: number;
  codeSmells?: number;
  vulnerabilities?: number;
  coverage?: number;
  duplications?: number;
  children?: FileNode[];
  content?: CodeLine[];
}

/// Mirrors the server's SystemInfoDto (GET /api/system/info).
export interface SystemInfo {
  version: string;
  gitSha: string;
  uptimeSeconds: number;
  database: {
    connected: boolean;
    postgresVersion?: string;
  };
  issuesTotal: number;
  hotspotsTotal: number;
  pendingScanJobs: number;
}
