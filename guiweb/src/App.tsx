import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import {
  Layout,
  PlaybookList,
  PlaybookDetail,
  ErrorBoundary,
  Dashboard,
  MitreMatrix,
  Settings,
  PostMortem,
  SigmaConverter,
  SigmaMappings,
  SigmaExamples,
} from './components';
import PlaybookForm from './components/PlaybookForm';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
});

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <Layout>
            <Routes>
              <Route path="/" element={<PlaybookList />} />
              <Route path="/playbook/new" element={<PlaybookForm />} />
              <Route path="/playbook/:id" element={<PlaybookDetail />} />
              <Route path="/playbook/:id/edit" element={<PlaybookForm />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/mitre" element={<MitreMatrix />} />
              <Route path="/sigma" element={<SigmaConverter />} />
              <Route path="/sigma/examples" element={<SigmaExamples />} />
              <Route path="/sigma/mappings" element={<SigmaMappings />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/post-mortem" element={<PostMortem />} />
            </Routes>
          </Layout>
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;
