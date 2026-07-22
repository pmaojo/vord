import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { LandingView } from '../features/landing/components/LandingView';
import { ProjectsList } from '../features/projects/components/ProjectsList';
import { ProjectOverview } from '../features/projects/components/ProjectOverview';
import { IssuesWorkspace } from '../features/issues/components/IssuesWorkspace';
import { MeasuresView } from '../features/measures/components/MeasuresView';
import { CodeBrowser } from '../features/code/components/CodeBrowser';
import { RulesCatalogView } from '../features/rules/components/RulesCatalogView';
import { QualityProfilesView } from '../features/quality/components/QualityProfilesView';
import { QualityGatesView } from '../features/quality/components/QualityGatesView';
import { AdminView } from '../features/admin/components/AdminView';

export const AppRoutes: React.FC = () => {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/landing" replace />} />
      <Route path="/landing" element={<LandingView />} />
      <Route path="/projects" element={<ProjectsList />} />
      <Route path="/projects/:projectKey/overview" element={<ProjectOverview />} />
      <Route path="/projects/:projectKey/issues" element={<IssuesWorkspace />} />
      <Route path="/projects/:projectKey/measures" element={<MeasuresView />} />
      <Route path="/projects/:projectKey/code" element={<CodeBrowser />} />
      <Route path="/issues" element={<IssuesWorkspace />} />
      <Route path="/rules" element={<RulesCatalogView />} />
      <Route path="/quality_profiles" element={<QualityProfilesView />} />
      <Route path="/quality_gates" element={<QualityGatesView />} />
      <Route path="/admin" element={<AdminView />} />
      <Route path="*" element={<Navigate to="/landing" replace />} />
    </Routes>
  );
};
