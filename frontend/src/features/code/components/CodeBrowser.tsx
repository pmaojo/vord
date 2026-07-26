import React, { useState } from 'react';
import { useParams } from 'react-router-dom';
import { MOCK_PROJECTS, MOCK_FILE_TREE } from '../../../testing/mock-data';
import { ProjectHeader } from '../../../components/layout/ProjectHeader';
import { FileNode, Project } from '../../../types';
import { SeverityIcon } from '../../../components/common/SeverityIcon';
import {
  Folder,
  FolderOpen,
  FileCode,
  ChevronRight,
  ChevronDown,
  Bug,
  Wrench,
  ShieldCheck,
  PieChart,
  Copy,
  FileText
} from 'lucide-react';
import { cn } from '../../../lib/utils';

export const CodeBrowser: React.FC = () => {
  const { projectKey } = useParams<{ projectKey: string }>();
  const decodedKey = projectKey ? decodeURIComponent(projectKey) : '';
  const project: Project | undefined = MOCK_PROJECTS.find((p) => p.key === decodedKey) ?? MOCK_PROJECTS[0];

  const [currentBranch, setCurrentBranch] = useState(
    project?.branches.find((b) => b.isMain)?.name || 'main'
  );

  const [selectedFile, setSelectedFile] = useState<FileNode | null>(
    MOCK_FILE_TREE[0]?.children?.[0]?.children?.[0] || null
  );

  const [expandedFolders, setExpandedFolders] = useState<Record<string, boolean>>({
    src: true,
    'src/main': true,
    'src/main/java': true,
    'src/features': true,
  });

  const toggleFolder = (path: string) => {
    setExpandedFolders((prev) => ({ ...prev, [path]: !prev[path] }));
  };

  // MOCK_PROJECTS is currently empty (this page has no real project-metrics
  // data source wired in yet) — render a clear placeholder instead of
  // crashing on `undefined.branches` above.
  if (!project) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-16 text-center text-sm text-slate-500">
        No project data available for <span className="font-mono font-bold">{decodedKey || 'this key'}</span>.
        Code browsing still reads from local mock data, which is currently empty.
      </div>
    );
  }

  const renderFileTree = (node: FileNode) => {
    if (node.type === 'dir') {
      const isExpanded = expandedFolders[node.path];
      return (
        <div key={node.path} className="select-none">
          <button
            onClick={() => toggleFolder(node.path)}
            className="w-full flex items-center gap-1.5 py-1 px-2 hover:bg-slate-100 rounded text-xs font-semibold text-slate-700 transition-colors"
          >
            {isExpanded ? (
              <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
            )}
            {isExpanded ? (
              <FolderOpen className="w-4 h-4 text-sky-600 shrink-0" />
            ) : (
              <Folder className="w-4 h-4 text-sky-600 shrink-0" />
            )}
            <span className="truncate">{node.name}</span>
          </button>
          {isExpanded && node.children && (
            <div className="pl-4 border-l border-slate-200 ml-3 space-y-0.5">
              {node.children.map((child) => renderFileTree(child))}
            </div>
          )}
        </div>
      );
    }

    const isSelected = selectedFile?.path === node.path;
    return (
      <button
        key={node.path}
        onClick={() => setSelectedFile(node)}
        className={cn(
          'w-full flex items-center gap-2 py-1 px-2 rounded text-xs font-mono transition-colors text-left',
          isSelected ? 'bg-sky-100 text-sky-900 font-bold' : 'text-slate-700 hover:bg-slate-100'
        )}
      >
        <FileCode className="w-3.5 h-3.5 text-slate-400 shrink-0" />
        <span className="truncate">{node.name}</span>
      </button>
    );
  };

  return (
    <div>
      <ProjectHeader
        project={project}
        currentBranch={currentBranch}
        onBranchChange={setCurrentBranch}
      />

      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* File Tree Explorer Sidebar */}
          <div className="lg:col-span-1 bg-white rounded-xl border border-slate-200 p-4 shadow-xs space-y-3">
            <div className="text-xs font-bold text-slate-500 uppercase tracking-wider px-2 border-b border-slate-100 pb-2 flex items-center gap-1.5">
              <FileText className="w-4 h-4 text-sky-600" />
              <span>Source Files</span>
            </div>
            <div className="space-y-1">{MOCK_FILE_TREE.map(renderFileTree)}</div>
          </div>

          {/* Main Source Viewer Area */}
          <div className="lg:col-span-3 space-y-6">
            {selectedFile ? (
              <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
                {/* File Header Bar */}
                <div className="bg-slate-900 text-white p-4 flex flex-wrap items-center justify-between gap-4 border-b border-slate-800">
                  <div className="flex items-center gap-2 font-mono text-xs">
                    <FileCode className="w-4 h-4 text-sky-400" />
                    <span className="font-bold text-slate-100">{selectedFile.path}</span>
                  </div>

                  <div className="flex items-center gap-4 text-xs font-mono">
                    <span className="text-slate-300">LOC: <b>{selectedFile.ncloc || 142}</b></span>
                    <span className="text-emerald-400">Coverage: <b>{selectedFile.coverage || 85}%</b></span>
                    <span className="text-rose-400">Bugs: <b>{selectedFile.bugs || 0}</b></span>
                  </div>
                </div>

                {/* Source Code Line by Line */}
                <div className="bg-slate-950 text-slate-100 font-mono text-xs overflow-x-auto divide-y divide-slate-900/60 p-2">
                  {selectedFile.content ? (
                    selectedFile.content.map((line) => (
                      <div key={line.line} className="flex items-center font-mono group hover:bg-slate-900/80">
                        {/* Coverage Gutter Bar */}
                        <div
                          className={cn(
                            'w-2 h-6 shrink-0',
                            line.isCovered && 'bg-emerald-500',
                            line.isUncovered && 'bg-rose-500',
                            !line.isCovered && !line.isUncovered && 'bg-slate-800'
                          )}
                          title={line.isCovered ? 'Line covered by tests' : line.isUncovered ? 'Uncovered line' : ''}
                        />

                        {/* Line Number */}
                        <span className="w-10 text-slate-600 text-right pr-3 select-none text-[11px]">
                          {line.line}
                        </span>

                        {/* Code Text */}
                        <code className="whitespace-pre flex-1 text-slate-200 px-2 py-0.5">
                          {line.code}
                        </code>

                        {/* Inline Issue Badge if present */}
                        {line.issueMessage && (
                          <div className="mr-2 bg-rose-950 border border-rose-700/80 text-rose-200 text-[10px] px-2 py-0.5 rounded font-sans font-bold flex items-center gap-1">
                            <SeverityIcon severity={line.issueSeverity || 'CRITICAL'} />
                            <span>{line.issueMessage}</span>
                          </div>
                        )}
                      </div>
                    ))
                  ) : (
                    <div className="p-8 text-center text-slate-500">
                      Select a file to inspect source code, line coverage gutters, and inline static analysis diagnostics.
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="bg-white rounded-xl border border-slate-200 p-12 text-center text-slate-500 shadow-xs">
                Select a file from the repository file tree on the left.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
