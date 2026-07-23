import React, { useState } from 'react';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { TopNavbar } from '../components/layout/TopNavbar';
import { GlobalSearchModal } from '../components/layout/GlobalSearchModal';
import { ApiDocsModal } from '../components/layout/ApiDocsModal';
import { AppRoutes } from './routes';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      staleTime: 1000 * 60 * 5, // 5 minutes
    },
  },
});

export const AppRoot: React.FC = () => {
  const [apiDocsOpen, setApiDocsOpen] = useState(false);

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="min-h-screen bg-[#f3f6f9] text-[#233445] font-sans flex flex-col antialiased">
          {/* Top persistent navbar */}
          <TopNavbar />

          {/* Main content body */}
          <main className="flex-1 pb-12">
            <AppRoutes />
          </main>

          {/* Technical Footer */}
          <footer className="bg-white border-t border-gray-200 px-6 py-2.5 h-10 flex items-center justify-between text-[11px] text-gray-500 select-none">
            <div className="flex items-center gap-4">
              <span className="font-semibold text-[#233445]">yunq™ v0.1.1</span>
              <span className="text-gray-300">•</span>
              <span>Enterprise Edition</span>
            </div>
            <div className="flex items-center gap-4">
              <a href="https://github.com/pmaojo/yunq#readme" target="_blank" rel="noreferrer" className="hover:text-[#4b9fd5] transition-colors">Documentation</a>
              <button onClick={() => setApiDocsOpen(true)} className="hover:text-[#4b9fd5] transition-colors cursor-pointer font-medium">Web API (OpenAPI)</button>
              <a href="#" onClick={(e) => { e.preventDefault(); alert('yunq Enterprise Support: Active 24/7 SLA'); }} className="hover:text-[#4b9fd5] transition-colors">Get Support</a>
            </div>
          </footer>

          {/* Global Search Modal (Cmd+K) */}
          <GlobalSearchModal />

          {/* OpenAPI Web API Docs Inspector */}
          <ApiDocsModal isOpen={apiDocsOpen} onClose={() => setApiDocsOpen(false)} />
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
};
