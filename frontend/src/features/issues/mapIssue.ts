import { ApiIssue, ApiRule } from '../../lib/api';
import { Issue, IssueSeverity, IssueStatus, IssueResolution, IssueType } from '../../types';

const RESOLUTION_MAP: Record<string, IssueResolution> = {
  fixed: 'FIXED',
  'wont-fix': 'WONT_FIX',
  'false-positive': 'FALSE_POSITIVE',
};

/// Rule ids are namespaced `<category>:<name>` — there is no issue "type"
/// field on the real backend, so this is the best honest guess at
/// BUG/VULNERABILITY/CODE_SMELL, overridden by the rule's real
/// produces_hotspots flag when known.
function inferType(ruleId: string, producesHotspots: boolean | undefined): IssueType {
  if (producesHotspots) return 'SECURITY_HOTSPOT';
  const category = ruleId.split(':')[0];
  if (category === 'owasp' || category === 'secrets' || category === 'iac') return 'VULNERABILITY';
  return 'CODE_SMELL';
}

export function mapApiIssueToIssue(
  item: ApiIssue,
  projectKey: string,
  ruleIndex: Map<string, ApiRule>
): Issue {
  const rule = ruleIndex.get(item.rule);
  return {
    id: item.id.toString(),
    key: `ISSUE-${item.id}`,
    ruleKey: item.rule,
    ruleName: item.rule,
    severity: (item.severity.toUpperCase() as IssueSeverity) || 'MAJOR',
    type: inferType(item.rule, rule?.produces_hotspots),
    status: (item.status.toUpperCase() as IssueStatus) || 'OPEN',
    resolution: item.resolution ? RESOLUTION_MAP[item.resolution] : undefined,
    message: item.message,
    component: item.file,
    projectKey,
    projectName: projectKey,
    line: item.line,
    creationDate: new Date().toISOString(),
    updateDate: new Date().toISOString(),
    effortMinutes: rule?.remediation_effort_minutes ?? 0,
    assignee: item.assignee,
    author: 'yunq-analyzer',
    tags: rule?.tags ?? [],
  };
}
