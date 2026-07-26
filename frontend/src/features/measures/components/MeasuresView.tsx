import React, { useState } from 'react';
import { useParams } from 'react-router-dom';
import { MOCK_PROJECTS, MOCK_METRICS_LIST } from '../../../testing/mock-data';
import type { Project } from '../../../types';
import { ProjectHeader } from '../../../components/layout/ProjectHeader';
import { RatingBadge } from '../../../components/common/RatingBadge';
import {
  BarChart3,
  PieChart,
  Grid,
  TrendingUp,
  Bug,
  ShieldCheck,
  Wrench,
  Copy,
  Layers,
  ChevronRight
} from 'lucide-react';
import { ResponsiveContainer, Treemap, Tooltip, ScatterChart, Scatter, XAxis, YAxis, ZAxis, CartesianGrid } from 'recharts';

export const MeasuresView: React.FC = () => {
  const { projectKey } = useParams<{ projectKey: string }>();
  const decodedKey = projectKey ? decodeURIComponent(projectKey) : '';
  const project: Project | undefined = MOCK_PROJECTS.find((p) => p.key === decodedKey) ?? MOCK_PROJECTS[0];

  const [currentBranch, setCurrentBranch] = useState(
    project?.branches.find((b) => b.isMain)?.name || 'main'
  );

  const [selectedCategory, setSelectedCategory] = useState<string>('RELIABILITY');

  // MOCK_PROJECTS is currently empty (this page has no real project-metrics
  // data source wired in yet) — render a clear placeholder instead of
  // crashing on `undefined.branches`/`undefined.metrics` below.
  if (!project) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-16 text-center text-sm text-slate-500">
        No project data available for <span className="font-mono font-bold">{decodedKey || 'this key'}</span>.
        Measures still read from local mock data, which is currently empty.
      </div>
    );
  }

  const categories = [
    { key: 'RELIABILITY', name: 'Reliability', icon: Bug },
    { key: 'SECURITY', name: 'Security', icon: ShieldCheck },
    { key: 'MAINTAINABILITY', name: 'Maintainability', icon: Wrench },
    { key: 'COVERAGE', name: 'Coverage', icon: PieChart },
    { key: 'DUPLICATIONS', name: 'Duplications', icon: Copy },
    { key: 'SIZE', name: 'Size', icon: Layers },
  ];

  // Treemap data representation for Treemap Visualization
  const treemapData = [
    { name: 'PaymentDAO.java', size: 1420, bugs: 2, color: '#f87171' },
    { name: 'PaymentService.java', size: 2800, bugs: 1, color: '#fbbf24' },
    { name: 'TransactionController.java', size: 3400, bugs: 0, color: '#34d399' },
    { name: 'AuthInterceptor.java', size: 920, bugs: 0, color: '#34d399' },
    { name: 'CardTokenizer.java', size: 1850, bugs: 3, color: '#ef4444' },
    { name: 'WebhookHandler.java', size: 2100, bugs: 1, color: '#fbbf24' },
  ];

  // Bubble risk scatter data
  const scatterData = [
    { name: 'PaymentDAO.java', loc: 142, complexity: 18, debt: 120 },
    { name: 'PaymentService.java', loc: 280, complexity: 32, debt: 340 },
    { name: 'TransactionController.java', loc: 340, complexity: 45, debt: 210 },
    { name: 'CardTokenizer.java', loc: 185, complexity: 22, debt: 450 },
  ];

  const categoryMetrics = MOCK_METRICS_LIST.filter((m) => m.category === selectedCategory);

  return (
    <div>
      <ProjectHeader
        project={project}
        currentBranch={currentBranch}
        onBranchChange={setCurrentBranch}
      />

      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Category Tree Navigation */}
          <div className="lg:col-span-1 bg-white rounded-xl border border-slate-200 p-4 shadow-xs space-y-2">
            <div className="text-xs font-bold text-slate-500 uppercase tracking-wider px-2 mb-2">
              Metric Categories
            </div>
            {categories.map((cat) => {
              const Icon = cat.icon;
              const isSelected = selectedCategory === cat.key;
              return (
                <button
                  key={cat.key}
                  onClick={() => setSelectedCategory(cat.key)}
                  className={`w-full flex items-center justify-between p-3 rounded-xl font-bold text-xs transition-all ${
                    isSelected
                      ? 'bg-sky-600 text-white shadow-xs'
                      : 'text-slate-700 hover:bg-slate-100'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className="w-4 h-4" />
                    <span>{cat.name}</span>
                  </div>
                  <ChevronRight className="w-4 h-4 opacity-60" />
                </button>
              );
            })}
          </div>

          {/* Main Measures Dashboard */}
          <div className="lg:col-span-3 space-y-8">
            {/* Category Metrics Summary Cards */}
            <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
              <h2 className="text-xl font-black text-slate-900 tracking-tight mb-4 flex items-center gap-2">
                <BarChart3 className="w-5 h-5 text-sky-600" />
                <span>{categories.find((c) => c.key === selectedCategory)?.name} Metrics</span>
              </h2>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {categoryMetrics.map((metric) => (
                  <div
                    key={metric.key}
                    className="bg-slate-50 border border-slate-200/80 rounded-xl p-4 flex items-center justify-between shadow-2xs"
                  >
                    <div>
                      <div className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                        {metric.name}
                      </div>
                      <div className="text-2xl font-black text-slate-900 mt-1">
                        {metric.key === 'bugs'
                          ? project.metrics.bugs
                          : metric.key === 'vulnerabilities'
                          ? project.metrics.vulnerabilities
                          : metric.key === 'code_smells'
                          ? project.metrics.codeSmells
                          : metric.key === 'coverage'
                          ? `${project.metrics.coverage}%`
                          : metric.key === 'duplicated_lines_density'
                          ? `${project.metrics.duplications}%`
                          : metric.key === 'ncloc'
                          ? project.metrics.ncloc
                          : 'A'}
                      </div>
                      <p className="text-[11px] text-slate-500 mt-0.5">{metric.description}</p>
                    </div>

                    {metric.type === 'RATING' && (
                      <RatingBadge
                        rating={
                          selectedCategory === 'RELIABILITY'
                            ? project.metrics.bugsRating
                            : selectedCategory === 'SECURITY'
                            ? project.metrics.vulnerabilitiesRating
                            : project.metrics.codeSmellsRating
                        }
                        size="md"
                      />
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Treemap Risk Visualization */}
            <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                    <Grid className="w-5 h-5 text-sky-600" />
                    <span>Treemap Component Risk Map</span>
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Box area represents Lines of Code (LOC); color represents Issue Severity / Risk Density.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {treemapData.map((item) => (
                  <div
                    key={item.name}
                    style={{ borderTopColor: item.color }}
                    className="bg-slate-900 text-white rounded-xl p-4 border-t-4 shadow-md flex flex-col justify-between"
                  >
                    <div>
                      <div className="text-xs font-mono font-bold text-slate-300 truncate">{item.name}</div>
                      <div className="text-2xl font-black text-white mt-2">{item.size} <span className="text-xs font-normal text-slate-400">LOC</span></div>
                    </div>
                    <div className="mt-4 flex items-center justify-between text-xs font-semibold pt-2 border-t border-slate-800">
                      <span className="text-slate-400">Issues:</span>
                      <span className="px-2 py-0.5 rounded text-white font-mono" style={{ backgroundColor: item.color }}>
                        {item.bugs}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Bubble Scatter Chart (Complexity vs Debt) */}
            <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
              <h3 className="text-lg font-bold text-slate-900 mb-2 flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-sky-600" />
                <span>Risk Scatter Analysis (Cyclomatic Complexity vs. Debt)</span>
              </h3>
              <p className="text-xs text-slate-500 mb-4">
                Identify high-risk files requiring immediate refactoring.
              </p>

              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <ScatterChart margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                    <XAxis type="number" dataKey="complexity" name="Complexity" unit="" stroke="#94a3b8" />
                    <YAxis type="number" dataKey="debt" name="Technical Debt" unit="m" stroke="#94a3b8" />
                    <ZAxis type="number" dataKey="loc" range={[100, 500]} name="LOC" />
                    <Tooltip cursor={{ strokeDasharray: '3 3' }} />
                    <Scatter name="Files" data={scatterData} fill="#0284c7" />
                  </ScatterChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
