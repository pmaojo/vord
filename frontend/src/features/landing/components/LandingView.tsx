import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldCheck,
  Cpu,
  Zap,
  Terminal,
  Bot,
  Layers,
  CheckCircle2,
  Lock,
  GitPullRequest,
  BarChart3,
  FileCode2,
  ArrowRight,
  Server,
  Code2,
  Sparkles,
  BookOpen,
  Activity,
  Globe
} from 'lucide-react';

export const LandingView: React.FC = () => {
  const [selectedCategory, setSelectedCategory] = useState<string>('core');

  const featureCategories = [
    {
      id: 'core',
      title: 'Core Static Engine',
      subtitle: 'Hexagonal Workspace & Taint Tracker',
      icon: Cpu,
      color: 'text-sky-600 bg-sky-50 border-sky-200',
      features: [
        'Hexagonal workspace architecture for decoupled I/O and engine logic',
        'AST + Profile configuration parsers with Tree-sitter (TypeScript & Rust)',
        'Single-file and inter-procedural taint analysis flow graph',
        'OWASP Top 10 & Code Smells core rulesets',
        'In-memory arena allocation infra & CLI binaries',
        'SQS queue + PostgreSQL persistence backend'
      ]
    },
    {
      id: 'detection',
      title: 'Detection & Analysis',
      subtitle: 'Multi-Language AST & Coverage Parser',
      icon: Code2,
      color: 'text-emerald-600 bg-emerald-50 border-emerald-200',
      features: [
        '9+ Language AST parsers (Java, Python, Go, C/C++, C#, PHP, Ruby, Kotlin, Swift)',
        'IaC & Dockerfile security syntax scanning',
        'Cyclomatic & Cognitive complexity computation',
        'Token-based duplicate detection (CPD engine)',
        'Multi-provider secret scanner with private entropy thresholds',
        'LCOV, JaCoCo, Cobertura, llvm-cov & JUnit report ingestion',
        'Rayon parallelism & content-hash based incremental caching'
      ]
    },
    {
      id: 'quality',
      title: 'Quality Gates & Debt',
      subtitle: 'Gates, Ratings & Debt Engine',
      icon: BarChart3,
      color: 'text-indigo-600 bg-indigo-50 border-indigo-200',
      features: [
        'Quality Gates release policy evaluation engine',
        'New Code definition (4 configurable period modes)',
        'A–E Reliability, Security & Maintainability Ratings',
        'Technical Debt calculation & remediation cost estimation',
        'Security Hotspot marking & developer review workflow',
        'SVG badges, trend tracking & automated housekeeping'
      ]
    },
    {
      id: 'api',
      title: 'API & Web Platform',
      subtitle: 'REST Services & OpenAPI Contract',
      icon: Globe,
      color: 'text-teal-600 bg-teal-50 border-teal-200',
      features: [
        'Complete REST API, generated OpenAPI 3.1 contract',
        'Faceted search, component trees & line-level source blame annotations',
        'Token-based authentication & OAuth integration (GitHub/GitLab)',
        'Webhooks engine with exponential backoff retry logic',
        'Audit logs, Prometheus metrics exporter & PDF/CSV/JSON report builder'
      ]
    },
    {
      id: 'scm',
      title: 'SCM, CI & Editor Extensions',
      subtitle: 'Pull Request Decoration & LSP Plugins',
      icon: GitPullRequest,
      color: 'text-amber-600 bg-amber-50 border-amber-200',
      features: [
        'GitHub App integration with automated Check Runs',
        'Inline pull request decoration for GitHub, GitLab, Bitbucket & Azure DevOps',
        'Monorepo subproject sharding & CI context auto-detection',
        'VSCode, JetBrains, Vim/Neovim & Emacs LSP server plugins',
        'Real-time editor linting with connected-mode server synchronization'
      ]
    },
    {
      id: 'ai',
      title: 'AI Code Remediation',
      subtitle: 'Claude API Auto-Fix & Sandbox Execution',
      icon: Bot,
      color: 'text-purple-600 bg-purple-50 border-purple-200',
      features: [
        'Automated fix generation using Claude API',
        'Isolated Git worktree sandbox execution & automated re-scanning',
        'Verdict engine for fix verification before PR creation',
        'Trust boundary enforcement & stricter quality gates for AI code',
        'In-editor click-to-apply patch suggestions'
      ]
    },
    {
      id: 'enterprise',
      title: 'Enterprise & Compliance',
      subtitle: 'Hierarchical Portfolios & SSO',
      icon: Lock,
      color: 'text-[#233445] bg-slate-100 border-slate-300',
      features: [
        'Hierarchical portfolio aggregation & executive risk scoring',
        'OWASP Top 10, CWE Top 25 & PCI DSS compliance evidence exports',
        'Enterprise SSO: SAML 2.0, OpenID Connect (OIDC) & LDAP/AD sync',
        'SCIM user provisioning & permission templates by group',
        'Multi-node load balancing & high-throughput parallel worker execution'
      ]
    }
  ];

  return (
    <div className="space-y-12">
      {/* Hero Section */}
      <section className="bg-[#233445] text-white py-16 px-4 border-b border-[#1c2a38] relative overflow-hidden">
        <div className="max-w-7xl mx-auto relative z-10">
          <div className="flex flex-col lg:flex-row items-center justify-between gap-12">
            <div className="max-w-2xl space-y-6">
              <div className="inline-flex items-center gap-2 bg-[#3b4b5b] border border-sky-400/30 text-sky-300 text-xs font-mono font-bold px-3 py-1 rounded-full">
                <Sparkles className="w-3.5 h-3.5 text-[#4b9fd5]" />
                <span>yunq Engine v0.1.0 • Hexagonal Architecture</span>
              </div>

              <h1 className="text-4xl sm:text-5xl font-black text-white tracking-tight leading-tight">
                Next-Gen Static Analysis & <span className="text-[#4b9fd5]">AI Code Remediation</span>
              </h1>

              <p className="text-gray-300 text-sm sm:text-base leading-relaxed">
                High-performance hexagonal static analysis platform featuring AST parsers, inter-procedural taint tracking, Quality Gates, LSP extensions, and Claude-powered automated bug fixes.
              </p>

              <div className="flex flex-wrap items-center gap-4 pt-2">
                <Link
                  to="/projects"
                  className="px-6 py-3 bg-[#4b9fd5] hover:bg-[#3a8ec4] text-white font-bold text-xs uppercase tracking-wider rounded-lg shadow-sm transition-all flex items-center gap-2"
                >
                  <span>Explore Projects Portfolio</span>
                  <ArrowRight className="w-4 h-4" />
                </Link>

                <Link
                  to="/admin"
                  className="px-6 py-3 bg-[#3b4b5b] hover:bg-[#485b6e] text-white font-bold text-xs uppercase tracking-wider rounded-lg border border-gray-600 transition-all flex items-center gap-2"
                >
                  <Server className="w-4 h-4 text-[#4b9fd5]" />
                  <span>Admin Control Plane</span>
                </Link>
              </div>
            </div>

            {/* Architecture Card */}
            <div className="w-full lg:w-96 bg-[#1c2a38] border border-slate-700/80 rounded-2xl p-6 shadow-2xl space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-slate-700 pb-3">
                <div className="flex items-center gap-2 text-sky-400 font-bold">
                  <Terminal className="w-4 h-4" />
                  <span>yunq-worker-01.local</span>
                </div>
                <span className="text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-700 px-2 py-0.5 rounded font-bold">
                  ONLINE
                </span>
              </div>

              <div className="space-y-2 text-gray-300 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-gray-500">AST Parser Speed:</span>
                  <span className="text-emerald-400 font-bold">1.4M LOC/sec</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Rayon Worker Threads:</span>
                  <span className="text-white font-bold">32 Parallel</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Incremental Cache Hit:</span>
                  <span className="text-sky-400 font-bold">98.2%</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">AI Fix Engine:</span>
                  <span className="text-purple-400 font-bold">Claude 3.5 Sonnet</span>
                </div>
              </div>

              <div className="bg-slate-950 p-3 rounded border border-slate-800 text-[10px] text-emerald-400 space-y-1">
                <div>$ yunq scan --project payment-service</div>
                <div className="text-gray-400">[INFO] AST parsed in 42ms</div>
                <div className="text-gray-400">[INFO] Taint tracking completed: 0 vulns</div>
                <div className="text-emerald-400 font-bold">[PASSED] Quality Gate passed (98.4% coverage)</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Feature Showcase Section */}
      <section className="max-w-7xl mx-auto px-4 py-6 space-y-8">
        <div className="text-center max-w-3xl mx-auto">
          <h2 className="text-2xl font-black text-[#233445] tracking-tight">
            Platform Capabilities & Feature Overview
          </h2>
          <p className="text-xs text-gray-500 mt-2">
            Explore the core static analysis engine, multi-language parsers, AI remediation sandbox, and enterprise security modules.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          {/* Left: Feature Category Selector */}
          <div className="lg:col-span-4 space-y-2">
            {featureCategories.map((cat) => {
              const Icon = cat.icon;
              const isSelected = selectedCategory === cat.id;
              return (
                <button
                  key={cat.id}
                  onClick={() => setSelectedCategory(cat.id)}
                  className={`w-full text-left p-3.5 rounded-xl border transition-all flex items-center justify-between ${
                    isSelected
                      ? 'bg-white border-[#4b9fd5] shadow-xs ring-2 ring-[#4b9fd5]/20'
                      : 'bg-white border-gray-200 hover:border-gray-300'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg border ${cat.color}`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="text-xs font-bold text-[#233445]">{cat.title}</div>
                      <div className="text-[11px] text-gray-500">{cat.subtitle}</div>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Right: Selected Category Details */}
          <div className="lg:col-span-8 bg-white rounded-2xl border border-gray-200 p-6 shadow-2xs space-y-6">
            {(() => {
              const active = featureCategories.find((c) => c.id === selectedCategory) || featureCategories[0];
              const Icon = active.icon;
              return (
                <div>
                  <div className="flex items-center gap-3 border-b border-gray-100 pb-4 mb-6">
                    <div className={`p-3 rounded-xl border ${active.color}`}>
                      <Icon className="w-6 h-6" />
                    </div>
                    <div>
                      <h3 className="text-xl font-bold text-[#233445]">{active.title}</h3>
                      <p className="text-xs text-gray-500 mt-0.5">{active.subtitle}</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {active.features.map((feat, idx) => (
                      <div
                        key={idx}
                        className="bg-[#f8fafc] border border-gray-200/80 rounded-xl p-3.5 flex items-start gap-3"
                      >
                        <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                        <span className="text-xs font-medium text-slate-800 leading-relaxed">{feat}</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}
          </div>
        </div>

        {/* Overview Grid Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-6">
          <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-2xs space-y-3">
            <div className="p-2.5 bg-sky-50 text-sky-600 border border-sky-200 rounded-xl w-fit">
              <Cpu className="w-5 h-5" />
            </div>
            <h4 className="text-sm font-bold text-[#233445]">Hexagonal Static Analysis</h4>
            <p className="text-xs text-gray-500 leading-relaxed">
              Tree-sitter AST parsing, cognitive complexity calculations, and inter-procedural taint analysis flow graphs running on Rayon parallel threads.
            </p>
          </div>

          <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-2xs space-y-3">
            <div className="p-2.5 bg-purple-50 text-purple-600 border border-purple-200 rounded-xl w-fit">
              <Bot className="w-5 h-5" />
            </div>
            <h4 className="text-sm font-bold text-[#233445]">Claude AI Code Remediation</h4>
            <p className="text-xs text-gray-500 leading-relaxed">
              Generates verified code patches inside isolated Git worktrees, re-evaluates AST quality gates, and automatically decorates pull requests.
            </p>
          </div>

          <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-2xs space-y-3">
            <div className="p-2.5 bg-emerald-50 text-emerald-600 border border-emerald-200 rounded-xl w-fit">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <h4 className="text-sm font-bold text-[#233445]">Enterprise Governance & SSO</h4>
            <p className="text-xs text-gray-500 leading-relaxed">
              SAML 2.0 / OIDC single sign-on, SCIM user provisioning, SAML group permission mapping, and OWASP/CWE/PCI DSS compliance exports.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
};

