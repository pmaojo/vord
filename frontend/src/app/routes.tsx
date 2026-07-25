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
import { LoginPage } from '../auth/LoginPage';
import { OAuthCallbackPage } from '../auth/OAuthCallbackPage';
import { ProtectedRoute } from '../auth/ProtectedRoute';

/** Wrap a route element in the ProtectedRoute guard. */
function protect(element: React.ReactElement) {
  return <ProtectedRoute>{element}</ProtectedRoute>;
}

export const AppRoutes: React.FC = () => {
  return (
    <Routes>
      {/* Public routes */}
      <Route path="/" element={<Navigate to="/landing" replace />} />
      <Route path="/landing" element={<LandingView />} />
      <Route path="/login" element={<LoginPage />} />
      {/* OAuth provider redirects here with #token=...&returnTo=... */}
      <Route path="/auth/callback" element={<OAuthCallbackPage />} />

      {/* Protected routes */}
      <Route path="/projects" element={protect(<ProjectsList />)} />
      <Route path="/projects/:projectKey/overview" element={protect(<ProjectOverview />)} />
      <Route path="/projects/:projectKey/issues" element={protect(<IssuesWorkspace />)} />
      <Route path="/projects/:projectKey/measures" element={protect(<MeasuresView />)} />
      <Route path="/projects/:projectKey/code" element={protect(<CodeBrowser />)} />
      <Route path="/issues" element={protect(<IssuesWorkspace />)} />
      <Route path="/rules" element={protect(<RulesCatalogView />)} />
      <Route path="/quality_profiles" element={protect(<QualityProfilesView />)} />
      <Route path="/quality_gates" element={protect(<QualityGatesView />)} />
      <Route path="/admin" element={protect(<AdminView />)} />

      {/* Catch-all */}
      <Route path="*" element={<Navigate to="/landing" replace />} />
    </Routes>
  );
};
