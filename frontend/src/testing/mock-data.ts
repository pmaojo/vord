import {
  Project,
  Issue,
  QualityGate,
  QualityProfile,
  RuleDefinition,
  FileNode,
  SystemInfo,
  MetricDefinition
} from '../types';

export const MOCK_PROJECTS: Project[] = [];
export const MOCK_ISSUES: Issue[] = [];
export const MOCK_METRICS_LIST: MetricDefinition[] = [];
export const MOCK_FILE_TREE: FileNode[] = [];

export const MOCK_QUALITY_GATES: QualityGate[] = [
  {
    id: 'qg-sonar-way',
    name: 'yunq Standard Gate',
    isDefault: true,
    conditions: [
      { id: 'c1', metric: 'new_reliability_rating', operator: 'GREATER_THAN', errorThreshold: '1', status: 'OK' },
      { id: 'c2', metric: 'new_security_rating', operator: 'GREATER_THAN', errorThreshold: '1', status: 'OK' },
      { id: 'c3', metric: 'new_coverage', operator: 'LESS_THAN', errorThreshold: '80.0', status: 'OK' },
    ],
  },
];

export const MOCK_QUALITY_PROFILES: QualityProfile[] = [
  {
    key: 'qp-rules-standard',
    name: 'yunq Recommended Ruleset',
    language: 'Rust / Polyglot',
    isDefault: true,
    isBuiltIn: true,
    activeRulesCount: 42,
  },
];

export const MOCK_RULES: RuleDefinition[] = [];

export const MOCK_SYSTEM_INFO: SystemInfo = {
  version: '0.1.1',
  edition: 'Enterprise',
  serverTime: new Date().toISOString(),
  uptime: '42d 12h',
  status: 'GREEN',
  database: 'PostgreSQL 16.2 / In-Memory Engine',
  activeWorkers: 5,
  queueSize: 0,
};
