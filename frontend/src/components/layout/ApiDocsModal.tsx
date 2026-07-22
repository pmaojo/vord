import React, { useState } from 'react';
import { MOCK_ISSUES, MOCK_RULES } from '../../testing/mock-data';
import { Play, Copy, X, Terminal } from 'lucide-react';

interface ApiDocsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const OPENAPI_SPEC = {
  "openapi": "3.1.0",
  "info": {
    "title": "yunq API",
    "description": "Static analysis platform: REST API, OAuth, signed webhooks and operational metrics.",
    "license": {
      "name": "MIT",
      "identifier": "MIT"
    },
    "version": "0.1.0"
  },
  "paths": {
    "/hotspots": {
      "get": {
        "summary": "List the most recently detected security hotspots.",
        "operationId": "list_hotspots",
        "parameters": [
          {
            "name": "limit",
            "in": "query",
            "description": "Maximum number of hotspots to return (default 50, capped at 500).",
            "required": false,
            "schema": {
              "type": "integer",
              "minimum": 0
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Recent hotspots",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "$ref": "#/components/schemas/HotspotDto"
                  }
                }
              }
            }
          },
          "502": {
            "description": "Storage backend unavailable"
          }
        }
      }
    },
    "/hotspots/{id}/status": {
      "put": {
        "summary": "Record a reviewer's verdict on a hotspot.",
        "operationId": "review_hotspot",
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "description": "Hotspot id",
            "required": true,
            "schema": {
              "type": "integer",
              "format": "int64"
            }
          }
        ],
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/HotspotReviewRequestDto"
              }
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "Hotspot after the review",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HotspotDto"
                }
              }
            }
          },
          "400": {
            "description": "Unknown status"
          },
          "404": {
            "description": "Hotspot not found"
          },
          "502": {
            "description": "Storage backend unavailable"
          }
        }
      }
    },
    "/issues": {
      "get": {
        "summary": "Search issues with filters and pagination (newest first).",
        "operationId": "list_issues",
        "parameters": [
          {
            "name": "page",
            "in": "query",
            "description": "1-based page number (default 1).",
            "required": false,
            "schema": {
              "type": "integer",
              "minimum": 0
            }
          },
          {
            "name": "page_size",
            "in": "query",
            "description": "Page size (default 50, capped at 500).",
            "required": false,
            "schema": {
              "type": "integer",
              "minimum": 0
            }
          },
          {
            "name": "severity",
            "in": "query",
            "description": "Filter: info|minor|major|critical|blocker.",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "status",
            "in": "query",
            "description": "Filter: open|confirmed|resolved|closed.",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "rule",
            "in": "query",
            "description": "Filter: exact rule id, e.g. owasp:eval-usage.",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "file",
            "in": "query",
            "description": "Filter: substring of the file path.",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "assignee",
            "in": "query",
            "description": "Filter: exact assignee.",
            "required": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "One page of matching issues",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/IssuePageDto"
                }
              }
            }
          },
          "400": {
            "description": "Invalid filter value"
          },
          "502": {
            "description": "Storage backend unavailable"
          }
        }
      }
    },
    "/issues/{id}/assignee": {
      "put": {
        "summary": "Assign or unassign an issue.",
        "operationId": "assign_issue",
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "description": "Issue id",
            "required": true,
            "schema": {
              "type": "integer",
              "format": "int64"
            }
          }
        ],
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/AssigneeRequestDto"
              }
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "Issue after the assignment",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/IssueDto"
                }
              }
            }
          },
          "404": {
            "description": "Issue not found"
          },
          "502": {
            "description": "Storage backend unavailable"
          }
        }
      }
    },
    "/issues/{id}/transitions": {
      "post": {
        "summary": "Apply a workflow transition to an issue.",
        "operationId": "transition_issue",
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "description": "Issue id",
            "required": true,
            "schema": {
              "type": "integer",
              "format": "int64"
            }
          }
        ],
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/TransitionRequestDto"
              }
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "Issue after the transition",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/IssueDto"
                }
              }
            }
          },
          "400": {
            "description": "Unknown transition or resolution"
          },
          "404": {
            "description": "Issue not found"
          },
          "409": {
            "description": "Transition not allowed from the current status"
          },
          "502": {
            "description": "Storage backend unavailable"
          }
        }
      }
    },
    "/rules": {
      "get": {
        "summary": "The catalog of every rule this server's analyzers ship with.",
        "operationId": "list_rules",
        "responses": {
          "200": {
            "description": "Rule catalog",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "$ref": "#/components/schemas/RuleDto"
                  }
                }
              }
            }
          }
        }
      }
    },
    "/scans": {
      "post": {
        "summary": "Enqueue a scan job for asynchronous analysis.",
        "operationId": "enqueue_scan",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/ScanRequestDto"
              }
            }
          },
          "required": true
        },
        "responses": {
          "202": {
            "description": "Scan job queued",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/ScanQueuedDto"
                }
              }
            }
          },
          "400": {
            "description": "Invalid scan request"
          },
          "502": {
            "description": "Queue backend unavailable"
          }
        }
      }
    }
  },
  "components": {
    "schemas": {
      "AssigneeRequestDto": {
        "type": "object",
        "properties": {
          "assignee": {
            "type": ["string", "null"],
            "description": "User to assign; null/omitted to unassign."
          }
        }
      },
      "HotspotDto": {
        "type": "object",
        "required": ["id", "rule", "file", "line", "column", "message", "status"],
        "properties": {
          "column": { "type": "integer", "format": "int32", "minimum": 0 },
          "file": { "type": "string" },
          "id": { "type": "integer", "format": "int64" },
          "line": { "type": "integer", "format": "int32", "minimum": 0 },
          "message": { "type": "string" },
          "rule": { "type": "string" },
          "status": { "type": "string" }
        }
      },
      "HotspotReviewRequestDto": {
        "type": "object",
        "required": ["status"],
        "properties": {
          "status": {
            "type": "string",
            "description": "One of: to-review, acknowledged, fixed, safe."
          }
        }
      },
      "IssueDto": {
        "type": "object",
        "required": ["id", "rule", "severity", "file", "line", "column", "message", "status"],
        "properties": {
          "assignee": { "type": ["string", "null"] },
          "column": { "type": "integer", "format": "int32", "minimum": 0 },
          "file": { "type": "string" },
          "id": { "type": "integer", "format": "int64" },
          "line": { "type": "integer", "format": "int32", "minimum": 0 },
          "message": { "type": "string" },
          "resolution": { "type": ["string", "null"] },
          "rule": { "type": "string" },
          "severity": { "type": "string" },
          "status": { "type": "string" }
        }
      },
      "IssuePageDto": {
        "type": "object",
        "required": ["items", "page", "page_size", "total"],
        "properties": {
          "items": {
            "type": "array",
            "items": { "$ref": "#/components/schemas/IssueDto" }
          },
          "page": { "type": "integer", "minimum": 0 },
          "page_size": { "type": "integer", "minimum": 0 },
          "total": { "type": "integer", "minimum": 0 }
        }
      },
      "RuleDto": {
        "type": "object",
        "required": [
          "id",
          "description",
          "tags",
          "default_severity",
          "remediation_effort_minutes",
          "produces_hotspots"
        ],
        "properties": {
          "cwe": { "type": ["integer", "null"], "format": "int32", "minimum": 0 },
          "default_severity": { "type": "string" },
          "description": { "type": "string" },
          "id": { "type": "string" },
          "produces_hotspots": { "type": "boolean" },
          "remediation_effort_minutes": { "type": "integer", "format": "int32", "minimum": 0 },
          "tags": { "type": "array", "items": { "type": "string" } }
        }
      },
      "ScanQueuedDto": {
        "type": "object",
        "required": ["status"],
        "properties": { "status": { "type": "string" } }
      },
      "ScanRequestDto": {
        "type": "object",
        "required": ["project", "path"],
        "properties": {
          "path": {
            "type": "string",
            "description": "Path to the checked-out sources, reachable by a worker."
          },
          "project": {
            "type": "string",
            "description": "Project key the scan belongs to."
          }
        }
      },
      "TransitionRequestDto": {
        "type": "object",
        "required": ["transition"],
        "properties": {
          "resolution": {
            "type": ["string", "null"],
            "description": "Required when transition is `resolve`: fixed, wont-fix, false-positive."
          },
          "transition": {
            "type": "string",
            "description": "One of: confirm, resolve, reopen, close."
          }
        }
      }
    }
  }
};

type EndpointKey = 'issues' | 'assign_issue' | 'transition_issue' | 'hotspots' | 'review_hotspot' | 'rules' | 'scans';

export const ApiDocsModal: React.FC<ApiDocsModalProps> = ({ isOpen, onClose }) => {
  const [activeEndpoint, setActiveEndpoint] = useState<EndpointKey>('issues');

  // Input states for interactive testing
  const [issuePage, setIssuePage] = useState<number>(1);
  const [issuePageSize, setIssuePageSize] = useState<number>(50);
  const [issueSeverity, setIssueSeverity] = useState<string>('');
  const [issueStatusFilter, setIssueStatusFilter] = useState<string>('');

  const [assignIssueId, setAssignIssueId] = useState<number>(101);
  const [assigneeVal, setAssigneeVal] = useState<string>('alex.mercer');

  const [transitionIssueId, setTransitionIssueId] = useState<number>(101);
  const [transitionAction, setTransitionAction] = useState<string>('resolve');
  const [transitionResolution, setTransitionResolution] = useState<string>('fixed');

  const [hotspotLimit, setHotspotLimit] = useState<number>(50);

  const [reviewHotspotId, setReviewHotspotId] = useState<number>(501);
  const [reviewStatus, setReviewStatus] = useState<string>('acknowledged');

  const [scanProject, setScanProject] = useState<string>('payment-gateway-service');
  const [scanPath, setScanPath] = useState<string>('/src/main/java/com/acme/payment');

  const [responseOutput, setResponseOutput] = useState<string | null>(null);
  const [responseCode, setResponseCode] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const handleTestIssues = () => {
    let filtered = MOCK_ISSUES;
    if (issueSeverity) {
      filtered = filtered.filter(i => i.severity.toLowerCase() === issueSeverity.toLowerCase());
    }
    if (issueStatusFilter) {
      filtered = filtered.filter(i => i.status.toLowerCase() === issueStatusFilter.toLowerCase());
    }

    const start = (issuePage - 1) * issuePageSize;
    const paginated = filtered.slice(start, start + issuePageSize).map((iss, idx) => ({
      id: 100 + idx + 1,
      rule: iss.ruleKey,
      severity: iss.severity,
      file: iss.component,
      line: iss.line,
      column: 14,
      message: iss.message,
      status: iss.status,
      assignee: iss.assignee || null,
      resolution: (iss as any).resolution || null
    }));

    const response = {
      items: paginated,
      page: issuePage,
      page_size: issuePageSize,
      total: filtered.length
    };

    setResponseCode(200);
    setResponseOutput(JSON.stringify(response, null, 2));
  };

  const handleTestAssignIssue = () => {
    const response = {
      id: assignIssueId,
      rule: "owasp:sql-injection",
      severity: "CRITICAL",
      file: "src/main/java/com/acme/payment/DatabaseService.java",
      line: 142,
      column: 18,
      message: "Unsanitized user payload passed to SQL query builder",
      status: "OPEN",
      assignee: assigneeVal || null,
      resolution: null
    };
    setResponseCode(200);
    setResponseOutput(JSON.stringify(response, null, 2));
  };

  const handleTestTransitionIssue = () => {
    const response = {
      id: transitionIssueId,
      rule: "owasp:sql-injection",
      severity: "CRITICAL",
      file: "src/main/java/com/acme/payment/DatabaseService.java",
      line: 142,
      column: 18,
      message: "Unsanitized user payload passed to SQL query builder",
      status: transitionAction === 'resolve' ? 'RESOLVED' : transitionAction.toUpperCase(),
      assignee: "alex.mercer",
      resolution: transitionAction === 'resolve' ? transitionResolution : null
    };
    setResponseCode(200);
    setResponseOutput(JSON.stringify(response, null, 2));
  };

  const handleTestHotspots = () => {
    const hotspots = [
      {
        id: 501,
        rule: "cwe:hardcoded-credentials",
        file: "src/main/java/com/acme/payment/Config.java",
        line: 34,
        column: 12,
        message: "Verify that credentials are loaded from environment variables",
        status: "TO_REVIEW"
      },
      {
        id: 502,
        rule: "cwe:weak-cryptography",
        file: "src/main/java/com/acme/payment/CryptoUtil.java",
        line: 88,
        column: 20,
        message: "Review MD5 hashing usage for non-critical integrity check",
        status: "ACKNOWLEDGED"
      }
    ].slice(0, hotspotLimit);

    setResponseCode(200);
    setResponseOutput(JSON.stringify(hotspots, null, 2));
  };

  const handleTestReviewHotspot = () => {
    const response = {
      id: reviewHotspotId,
      rule: "cwe:hardcoded-credentials",
      file: "src/main/java/com/acme/payment/Config.java",
      line: 34,
      column: 12,
      message: "Verify that credentials are loaded from environment variables",
      status: reviewStatus.toUpperCase()
    };
    setResponseCode(200);
    setResponseOutput(JSON.stringify(response, null, 2));
  };

  const handleTestRules = () => {
    const rules = MOCK_RULES.map(r => ({
      id: r.key,
      description: r.name,
      tags: [r.type, r.lang],
      default_severity: r.severity,
      remediation_effort_minutes: 15,
      produces_hotspots: r.type === 'SECURITY_HOTSPOT',
      cwe: 89
    }));

    setResponseCode(200);
    setResponseOutput(JSON.stringify(rules, null, 2));
  };

  const handleTestEnqueueScan = () => {
    if (!scanProject || !scanPath) {
      setResponseCode(400);
      setResponseOutput(JSON.stringify({ error: "Invalid scan request. 'project' and 'path' are required." }, null, 2));
      return;
    }
    setResponseCode(202);
    setResponseOutput(
      JSON.stringify(
        {
          status: "QUEUED",
          jobId: `job-${Math.floor(Math.random() * 899999 + 100000)}`,
          project: scanProject,
          path: scanPath,
          enqueuedAt: new Date().toISOString(),
          message: "Scan job successfully queued for worker processing."
        },
        null,
        2
      )
    );
  };

  const handleCopySpec = () => {
    navigator.clipboard.writeText(JSON.stringify(OPENAPI_SPEC, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 backdrop-blur-xs p-4">
      <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 max-w-5xl w-full max-h-[90vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="bg-[#233445] text-white p-4 flex items-center justify-between border-b border-[#1c2a38]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-[#4b9fd5] flex items-center justify-center font-bold text-white text-sm">
              API
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white tracking-tight">yunq API Specification</h2>
                <span className="bg-sky-500/20 text-sky-300 border border-sky-400/30 text-[10px] font-mono px-2 py-0.5 rounded">
                  v0.1.0 • OpenAPI 3.1.0
                </span>
              </div>
              <p className="text-xs text-gray-300">Static analysis platform: enqueue scans, read issues.</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopySpec}
              className="px-3 py-1.5 bg-[#3b4b5b] hover:bg-[#485b6e] text-white rounded text-xs font-semibold transition-colors flex items-center gap-1.5"
            >
              <Copy className="w-3.5 h-3.5" />
              <span>{copied ? 'Copied Spec!' : 'Copy OpenAPI JSON'}</span>
            </button>
            <button onClick={onClose} className="p-1.5 text-gray-300 hover:text-white rounded hover:bg-[#3b4b5b]">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 grid grid-cols-1 lg:grid-cols-12 gap-6 bg-[#f8fafc]">
          {/* Endpoint Navigation Sidebar */}
          <div className="lg:col-span-4 space-y-2">
            <div className="text-[11px] font-bold text-gray-400 uppercase tracking-wider px-1 mb-2">
              API Endpoints
            </div>

            {/* GET /issues */}
            <button
              onClick={() => { setActiveEndpoint('issues'); setResponseOutput(null); }}
              className={`w-full text-left p-2.5 rounded-xl border transition-all ${
                activeEndpoint === 'issues'
                  ? 'bg-white border-[#4b9fd5] shadow-xs ring-1 ring-[#4b9fd5]/30'
                  : 'bg-white border-gray-200 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="bg-emerald-100 text-emerald-800 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded">
                  GET
                </span>
                <span className="font-mono text-xs font-bold text-[#233445]">/issues</span>
              </div>
              <p className="text-[11px] text-gray-500 mt-0.5">Search issues with filters and pagination.</p>
            </button>

            {/* PUT /issues/{id}/assignee */}
            <button
              onClick={() => { setActiveEndpoint('assign_issue'); setResponseOutput(null); }}
              className={`w-full text-left p-2.5 rounded-xl border transition-all ${
                activeEndpoint === 'assign_issue'
                  ? 'bg-white border-[#4b9fd5] shadow-xs ring-1 ring-[#4b9fd5]/30'
                  : 'bg-white border-gray-200 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="bg-amber-100 text-amber-800 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded">
                  PUT
                </span>
                <span className="font-mono text-xs font-bold text-[#233445]">/issues/&#123;id&#125;/assignee</span>
              </div>
              <p className="text-[11px] text-gray-500 mt-0.5">Assign or unassign an issue.</p>
            </button>

            {/* POST /issues/{id}/transitions */}
            <button
              onClick={() => { setActiveEndpoint('transition_issue'); setResponseOutput(null); }}
              className={`w-full text-left p-2.5 rounded-xl border transition-all ${
                activeEndpoint === 'transition_issue'
                  ? 'bg-white border-[#4b9fd5] shadow-xs ring-1 ring-[#4b9fd5]/30'
                  : 'bg-white border-gray-200 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="bg-sky-100 text-sky-800 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded">
                  POST
                </span>
                <span className="font-mono text-xs font-bold text-[#233445]">/issues/&#123;id&#125;/transitions</span>
              </div>
              <p className="text-[11px] text-gray-500 mt-0.5">Apply a workflow transition to an issue.</p>
            </button>

            {/* GET /hotspots */}
            <button
              onClick={() => { setActiveEndpoint('hotspots'); setResponseOutput(null); }}
              className={`w-full text-left p-2.5 rounded-xl border transition-all ${
                activeEndpoint === 'hotspots'
                  ? 'bg-white border-[#4b9fd5] shadow-xs ring-1 ring-[#4b9fd5]/30'
                  : 'bg-white border-gray-200 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="bg-emerald-100 text-emerald-800 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded">
                  GET
                </span>
                <span className="font-mono text-xs font-bold text-[#233445]">/hotspots</span>
              </div>
              <p className="text-[11px] text-gray-500 mt-0.5">List recently detected security hotspots.</p>
            </button>

            {/* PUT /hotspots/{id}/status */}
            <button
              onClick={() => { setActiveEndpoint('review_hotspot'); setResponseOutput(null); }}
              className={`w-full text-left p-2.5 rounded-xl border transition-all ${
                activeEndpoint === 'review_hotspot'
                  ? 'bg-white border-[#4b9fd5] shadow-xs ring-1 ring-[#4b9fd5]/30'
                  : 'bg-white border-gray-200 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="bg-amber-100 text-amber-800 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded">
                  PUT
                </span>
                <span className="font-mono text-xs font-bold text-[#233445]">/hotspots/&#123;id&#125;/status</span>
              </div>
              <p className="text-[11px] text-gray-500 mt-0.5">Record a reviewer's verdict on a hotspot.</p>
            </button>

            {/* GET /rules */}
            <button
              onClick={() => { setActiveEndpoint('rules'); setResponseOutput(null); }}
              className={`w-full text-left p-2.5 rounded-xl border transition-all ${
                activeEndpoint === 'rules'
                  ? 'bg-white border-[#4b9fd5] shadow-xs ring-1 ring-[#4b9fd5]/30'
                  : 'bg-white border-gray-200 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="bg-emerald-100 text-emerald-800 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded">
                  GET
                </span>
                <span className="font-mono text-xs font-bold text-[#233445]">/rules</span>
              </div>
              <p className="text-[11px] text-gray-500 mt-0.5">Catalog of analyzer rule definitions.</p>
            </button>

            {/* POST /scans */}
            <button
              onClick={() => { setActiveEndpoint('scans'); setResponseOutput(null); }}
              className={`w-full text-left p-2.5 rounded-xl border transition-all ${
                activeEndpoint === 'scans'
                  ? 'bg-white border-[#4b9fd5] shadow-xs ring-1 ring-[#4b9fd5]/30'
                  : 'bg-white border-gray-200 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="bg-sky-100 text-sky-800 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded">
                  POST
                </span>
                <span className="font-mono text-xs font-bold text-[#233445]">/scans</span>
              </div>
              <p className="text-[11px] text-gray-500 mt-0.5">Enqueue scan job for analysis worker.</p>
            </button>

            {/* Schema DTO Cards */}
            <div className="mt-4 pt-3 border-t border-gray-200 space-y-2">
              <div className="text-[11px] font-bold text-gray-400 uppercase tracking-wider px-1">
                DTO Schemas
              </div>
              <div className="bg-white border border-gray-200 rounded-xl p-2.5 text-xs font-mono space-y-0.5">
                <div className="font-bold text-[#233445]">IssuePageDto / IssueDto</div>
                <div className="text-[10px] text-gray-500">items, page, page_size, total, rule, severity...</div>
              </div>
              <div className="bg-white border border-gray-200 rounded-xl p-2.5 text-xs font-mono space-y-0.5">
                <div className="font-bold text-[#233445]">HotspotDto / ReviewRequest</div>
                <div className="text-[10px] text-gray-500">status: to-review, acknowledged, fixed, safe</div>
              </div>
              <div className="bg-white border border-gray-200 rounded-xl p-2.5 text-xs font-mono space-y-0.5">
                <div className="font-bold text-[#233445]">RuleDto</div>
                <div className="text-[10px] text-gray-500">id, description, tags, cwe, default_severity</div>
              </div>
            </div>
          </div>

          {/* Interactive Tester Panel */}
          <div className="lg:col-span-8 space-y-4">
            {activeEndpoint === 'issues' && (
              <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-xs space-y-4">
                <div className="flex items-center justify-between border-b border-gray-100 pb-3">
                  <div className="flex items-center gap-2">
                    <span className="bg-emerald-600 text-white text-xs font-mono font-bold px-2 py-0.5 rounded">
                      GET
                    </span>
                    <span className="font-mono font-bold text-sm text-[#233445]">/issues</span>
                  </div>
                  <button
                    onClick={handleTestIssues}
                    className="px-4 py-1.5 bg-[#4b9fd5] hover:bg-[#3a8ec4] text-white font-bold text-xs rounded transition-colors flex items-center gap-1.5 shadow-xs"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Execute Request</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="block font-bold text-gray-600 uppercase tracking-wider mb-1 text-[11px]">
                      Query Parameter: page
                    </label>
                    <input
                      type="number"
                      value={issuePage}
                      onChange={(e) => setIssuePage(parseInt(e.target.value) || 1)}
                      min={1}
                      className="w-full bg-slate-50 border border-gray-300 rounded px-3 py-1.5 font-mono"
                    />
                  </div>

                  <div>
                    <label className="block font-bold text-gray-600 uppercase tracking-wider mb-1 text-[11px]">
                      Query Parameter: page_size
                    </label>
                    <input
                      type="number"
                      value={issuePageSize}
                      onChange={(e) => setIssuePageSize(parseInt(e.target.value) || 10)}
                      min={1}
                      max={500}
                      className="w-full bg-slate-50 border border-gray-300 rounded px-3 py-1.5 font-mono"
                    />
                  </div>

                  <div>
                    <label className="block font-bold text-gray-600 uppercase tracking-wider mb-1 text-[11px]">
                      Query Parameter: severity
                    </label>
                    <select
                      value={issueSeverity}
                      onChange={(e) => setIssueSeverity(e.target.value)}
                      className="w-full bg-slate-50 border border-gray-300 rounded px-3 py-1.5 font-mono"
                    >
                      <option value="">All Severities</option>
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="MAJOR">MAJOR</option>
                      <option value="MINOR">MINOR</option>
                    </select>
                  </div>

                  <div>
                    <label className="block font-bold text-gray-600 uppercase tracking-wider mb-1 text-[11px]">
                      Query Parameter: status
                    </label>
                    <select
                      value={issueStatusFilter}
                      onChange={(e) => setIssueStatusFilter(e.target.value)}
                      className="w-full bg-slate-50 border border-gray-300 rounded px-3 py-1.5 font-mono"
                    >
                      <option value="">All Statuses</option>
                      <option value="OPEN">OPEN</option>
                      <option value="CONFIRMED">CONFIRMED</option>
                      <option value="RESOLVED">RESOLVED</option>
                    </select>
                  </div>
                </div>
              </div>
            )}

            {activeEndpoint === 'assign_issue' && (
              <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-xs space-y-4">
                <div className="flex items-center justify-between border-b border-gray-100 pb-3">
                  <div className="flex items-center gap-2">
                    <span className="bg-amber-600 text-white text-xs font-mono font-bold px-2 py-0.5 rounded">
                      PUT
                    </span>
                    <span className="font-mono font-bold text-sm text-[#233445]">/issues/&#123;id&#125;/assignee</span>
                  </div>
                  <button
                    onClick={handleTestAssignIssue}
                    className="px-4 py-1.5 bg-[#4b9fd5] hover:bg-[#3a8ec4] text-white font-bold text-xs rounded transition-colors flex items-center gap-1.5 shadow-xs"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Assign Issue</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="block font-bold text-gray-600 uppercase tracking-wider mb-1 text-[11px]">
                      Path Parameter: id
                    </label>
                    <input
                      type="number"
                      value={assignIssueId}
                      onChange={(e) => setAssignIssueId(parseInt(e.target.value) || 101)}
                      className="w-full bg-slate-50 border border-gray-300 rounded px-3 py-1.5 font-mono"
                    />
                  </div>

                  <div>
                    <label className="block font-bold text-gray-600 uppercase tracking-wider mb-1 text-[11px]">
                      Body: assignee
                    </label>
                    <input
                      type="text"
                      value={assigneeVal}
                      onChange={(e) => setAssigneeVal(e.target.value)}
                      placeholder="e.g. alex.mercer (or leave empty for unassign)"
                      className="w-full bg-slate-50 border border-gray-300 rounded px-3 py-1.5 font-mono"
                    />
                  </div>
                </div>
              </div>
            )}

            {activeEndpoint === 'transition_issue' && (
              <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-xs space-y-4">
                <div className="flex items-center justify-between border-b border-gray-100 pb-3">
                  <div className="flex items-center gap-2">
                    <span className="bg-sky-600 text-white text-xs font-mono font-bold px-2 py-0.5 rounded">
                      POST
                    </span>
                    <span className="font-mono font-bold text-sm text-[#233445]">/issues/&#123;id&#125;/transitions</span>
                  </div>
                  <button
                    onClick={handleTestTransitionIssue}
                    className="px-4 py-1.5 bg-[#4b9fd5] hover:bg-[#3a8ec4] text-white font-bold text-xs rounded transition-colors flex items-center gap-1.5 shadow-xs"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Transition Issue</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <div>
                    <label className="block font-bold text-gray-600 uppercase tracking-wider mb-1 text-[11px]">
                      Path Parameter: id
                    </label>
                    <input
                      type="number"
                      value={transitionIssueId}
                      onChange={(e) => setTransitionIssueId(parseInt(e.target.value) || 101)}
                      className="w-full bg-slate-50 border border-gray-300 rounded px-3 py-1.5 font-mono"
                    />
                  </div>

                  <div>
                    <label className="block font-bold text-gray-600 uppercase tracking-wider mb-1 text-[11px]">
                      Body: transition
                    </label>
                    <select
                      value={transitionAction}
                      onChange={(e) => setTransitionAction(e.target.value)}
                      className="w-full bg-slate-50 border border-gray-300 rounded px-3 py-1.5 font-mono"
                    >
                      <option value="confirm">confirm</option>
                      <option value="resolve">resolve</option>
                      <option value="reopen">reopen</option>
                      <option value="close">close</option>
                    </select>
                  </div>

                  <div>
                    <label className="block font-bold text-gray-600 uppercase tracking-wider mb-1 text-[11px]">
                      Body: resolution
                    </label>
                    <select
                      value={transitionResolution}
                      onChange={(e) => setTransitionResolution(e.target.value)}
                      disabled={transitionAction !== 'resolve'}
                      className="w-full bg-slate-50 border border-gray-300 rounded px-3 py-1.5 font-mono disabled:opacity-50"
                    >
                      <option value="fixed">fixed</option>
                      <option value="wont-fix">wont-fix</option>
                      <option value="false-positive">false-positive</option>
                    </select>
                  </div>
                </div>
              </div>
            )}

            {activeEndpoint === 'hotspots' && (
              <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-xs space-y-4">
                <div className="flex items-center justify-between border-b border-gray-100 pb-3">
                  <div className="flex items-center gap-2">
                    <span className="bg-emerald-600 text-white text-xs font-mono font-bold px-2 py-0.5 rounded">
                      GET
                    </span>
                    <span className="font-mono font-bold text-sm text-[#233445]">/hotspots</span>
                  </div>
                  <button
                    onClick={handleTestHotspots}
                    className="px-4 py-1.5 bg-[#4b9fd5] hover:bg-[#3a8ec4] text-white font-bold text-xs rounded transition-colors flex items-center gap-1.5 shadow-xs"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>List Hotspots</span>
                  </button>
                </div>

                <div>
                  <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-1">
                    Query Parameter: limit
                  </label>
                  <input
                    type="number"
                    value={hotspotLimit}
                    onChange={(e) => setHotspotLimit(parseInt(e.target.value) || 10)}
                    min={1}
                    max={500}
                    className="w-full max-w-xs bg-slate-50 border border-gray-300 rounded px-3 py-1.5 text-xs font-mono"
                  />
                </div>
              </div>
            )}

            {activeEndpoint === 'review_hotspot' && (
              <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-xs space-y-4">
                <div className="flex items-center justify-between border-b border-gray-100 pb-3">
                  <div className="flex items-center gap-2">
                    <span className="bg-amber-600 text-white text-xs font-mono font-bold px-2 py-0.5 rounded">
                      PUT
                    </span>
                    <span className="font-mono font-bold text-sm text-[#233445]">/hotspots/&#123;id&#125;/status</span>
                  </div>
                  <button
                    onClick={handleTestReviewHotspot}
                    className="px-4 py-1.5 bg-[#4b9fd5] hover:bg-[#3a8ec4] text-white font-bold text-xs rounded transition-colors flex items-center gap-1.5 shadow-xs"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Review Hotspot</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="block font-bold text-gray-600 uppercase tracking-wider mb-1 text-[11px]">
                      Path Parameter: id
                    </label>
                    <input
                      type="number"
                      value={reviewHotspotId}
                      onChange={(e) => setReviewHotspotId(parseInt(e.target.value) || 501)}
                      className="w-full bg-slate-50 border border-gray-300 rounded px-3 py-1.5 font-mono"
                    />
                  </div>

                  <div>
                    <label className="block font-bold text-gray-600 uppercase tracking-wider mb-1 text-[11px]">
                      Body: status
                    </label>
                    <select
                      value={reviewStatus}
                      onChange={(e) => setReviewStatus(e.target.value)}
                      className="w-full bg-slate-50 border border-gray-300 rounded px-3 py-1.5 font-mono"
                    >
                      <option value="to-review">to-review</option>
                      <option value="acknowledged">acknowledged</option>
                      <option value="fixed">fixed</option>
                      <option value="safe">safe</option>
                    </select>
                  </div>
                </div>
              </div>
            )}

            {activeEndpoint === 'rules' && (
              <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-xs space-y-4">
                <div className="flex items-center justify-between border-b border-gray-100 pb-3">
                  <div className="flex items-center gap-2">
                    <span className="bg-emerald-600 text-white text-xs font-mono font-bold px-2 py-0.5 rounded">
                      GET
                    </span>
                    <span className="font-mono font-bold text-sm text-[#233445]">/rules</span>
                  </div>
                  <button
                    onClick={handleTestRules}
                    className="px-4 py-1.5 bg-[#4b9fd5] hover:bg-[#3a8ec4] text-white font-bold text-xs rounded transition-colors flex items-center gap-1.5 shadow-xs"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Fetch Rules Catalog</span>
                  </button>
                </div>
                <p className="text-xs text-gray-500">
                  Returns the complete catalog of analyzer rules shipped with the server.
                </p>
              </div>
            )}

            {activeEndpoint === 'scans' && (
              <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-xs space-y-4">
                <div className="flex items-center justify-between border-b border-gray-100 pb-3">
                  <div className="flex items-center gap-2">
                    <span className="bg-sky-600 text-white text-xs font-mono font-bold px-2 py-0.5 rounded">
                      POST
                    </span>
                    <span className="font-mono font-bold text-sm text-[#233445]">/scans</span>
                  </div>
                  <button
                    onClick={handleTestEnqueueScan}
                    className="px-4 py-1.5 bg-[#4b9fd5] hover:bg-[#3a8ec4] text-white font-bold text-xs rounded transition-colors flex items-center gap-1.5 shadow-xs"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Enqueue Scan Job</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="block font-bold text-gray-600 uppercase tracking-wider mb-1 text-[11px]">
                      Body: project
                    </label>
                    <input
                      type="text"
                      value={scanProject}
                      onChange={(e) => setScanProject(e.target.value)}
                      className="w-full bg-slate-50 border border-gray-300 rounded px-3 py-1.5 font-mono"
                      placeholder="e.g. payment-gateway-service"
                    />
                  </div>
                  <div>
                    <label className="block font-bold text-gray-600 uppercase tracking-wider mb-1 text-[11px]">
                      Body: path
                    </label>
                    <input
                      type="text"
                      value={scanPath}
                      onChange={(e) => setScanPath(e.target.value)}
                      className="w-full bg-slate-50 border border-gray-300 rounded px-3 py-1.5 font-mono"
                      placeholder="e.g. /workspace/src"
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Response Console */}
            {responseOutput && (
              <div className="bg-[#1c2a38] text-gray-100 rounded-2xl p-4 border border-slate-800 shadow-md font-mono text-xs space-y-2 animate-in fade-in duration-100">
                <div className="flex items-center justify-between border-b border-slate-700/80 pb-2">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-[#4b9fd5]" />
                    <span className="font-bold text-white text-xs">Response Console</span>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      responseCode === 200 || responseCode === 202
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-700'
                        : 'bg-rose-950 text-rose-400 border border-rose-700'
                    }`}
                  >
                    HTTP {responseCode}
                  </span>
                </div>

                <pre className="overflow-x-auto p-2 bg-slate-950 rounded border border-slate-800 text-emerald-400 text-[11px] leading-relaxed max-h-64">
                  {responseOutput}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

