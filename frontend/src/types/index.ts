export type Rating = 'A' | 'B' | 'C' | 'D' | 'E';

export type QualityGateStatus = 'PASSED' | 'FAILED' | 'WARN';

export type IssueSeverity = 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO';

export type IssueType = 'BUG' | 'VULNERABILITY' | 'CODE_SMELL' | 'SECURITY_HOTSPOT';

export type IssueStatus = 'OPEN' | 'CONFIRMED' | 'REOPENED' | 'RESOLVED' | 'FALSE_POSITIVE' | 'WONT_FIX';

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

export interface QualityGateCondition {
  id: string;
  metric: string;
  metricName: string;
  op: 'LT' | 'GT' | 'EQ'; // Less than, Greater than, Equal
  errorThreshold: string;
  period?: 'NEW_CODE' | 'OVERALL';
}

export interface QualityGate {
  id: string;
  name: string;
  isDefault: boolean;
  conditions: QualityGateCondition[];
}

export interface QualityProfile {
  key: string;
  name: string;
  language: string;
  languageName: string;
  isDefault: boolean;
  activeRuleCount: number;
  deprecatedRuleCount: number;
  updatedAt: string;
}

export interface MetricDefinition {
  key: string;
  name: string;
  category: 'RELIABILITY' | 'SECURITY' | 'SECURITY_REVIEW' | 'MAINTAINABILITY' | 'COVERAGE' | 'DUPLICATIONS' | 'SIZE' | 'COMPLEXITY';
  type: 'INT' | 'PERCENT' | 'WORK_DUR' | 'RATING';
  description: string;
}

export interface RuleDefinition {
  key: string;
  name: string;
  lang: string;
  type: IssueType;
  severity: IssueSeverity;
  status: 'READY' | 'DEPRECATED' | 'BETA';
  sysTags: string[];
  htmlDesc: string;
  remediationEffort: string;
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

export interface SystemInfo {
  version: string;
  serverUptime: string;
  dbStatus: 'CONNECTED' | 'DISCONNECTED';
  searchEngineStatus: 'GREEN' | 'YELLOW' | 'RED';
  diskSpaceFreeGb: number;
  activeBackgroundTasks: number;
  totalProjectsCount: number;
  totalIssuesCount: number;
}
