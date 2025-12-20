# Component Usage Guide

This guide shows how to use the Threat Hunting Playbook components in your application.

## Quick Start

### 1. App Setup with Error Boundary and React Query

```tsx
// App.tsx
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Layout, PlaybookList, PlaybookDetail, ErrorBoundary } from './components';

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
              <Route path="/playbook/:id" element={<PlaybookDetail />} />
            </Routes>
          </Layout>
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;
```

### 2. Environment Configuration

Create a `.env` file in the project root:

```env
VITE_API_URL=http://localhost:8000/api
```

### 3. Run the Application

```bash
npm install
npm run dev
```

## Component Examples

### Layout Component

The Layout component provides the application shell with header and sidebar.

```tsx
import { Layout } from './components';

// Basic usage
<Layout>
  <YourContent />
</Layout>

// The layout automatically handles:
// - Responsive sidebar (mobile hamburger menu)
// - Header with branding
// - Navigation highlighting
// - Glassmorphism effects
```

**Navigation Configuration:**

To add new navigation items, edit `Layout.tsx`:

```tsx
const navItems: NavItem[] = [
  { name: 'Playbooks', path: '/', icon: BookOpen },
  { name: 'Dashboard', path: '/dashboard', icon: Activity },
  { name: 'MITRE ATT&CK', path: '/mitre', icon: Shield },
  // Add your custom navigation here
];
```

### PlaybookList Component

Displays all playbooks in a searchable, filterable table.

```tsx
import { PlaybookList } from './components';

// Basic usage - all features included
<Route path="/" element={<PlaybookList />} />

// The component automatically handles:
// - Data fetching via React Query
// - Search across multiple fields
// - Filtering by tactic, severity, and tags
// - Sortable columns
// - Loading and error states
```

**Features Included:**
- Real-time search
- Multi-column sorting
- Filter by tactic, severity, and tags
- Responsive table layout
- Loading skeleton
- Error handling with retry

### PlaybookDetail Component

Shows detailed information about a single playbook with tabs.

```tsx
import { PlaybookDetail } from './components';

// Basic usage with URL parameter
<Route path="/playbook/:id" element={<PlaybookDetail />} />

// Navigate to detail page
import { Link } from 'react-router-dom';

<Link to={`/playbook/${playbookId}`}>
  View Playbook
</Link>
```

**Tabs Available:**
1. **Overview** - MITRE info, hypothesis, investigation steps
2. **Queries** - Platform-specific detection queries
3. **IOCs** - Indicators of Compromise

### ErrorBoundary Component

Catches React errors and displays a friendly error UI.

```tsx
import { ErrorBoundary } from './components';

// Wrap your entire app
<ErrorBoundary>
  <App />
</ErrorBoundary>

// Or wrap specific sections
<ErrorBoundary fallback={<CustomErrorUI />}>
  <CriticalSection />
</ErrorBoundary>
```

**Custom Fallback:**

```tsx
const CustomErrorFallback = () => (
  <div className="p-8 text-center">
    <h2 className="text-xl text-red-400">Oops!</h2>
    <p className="text-gray-400">Something went wrong</p>
  </div>
);

<ErrorBoundary fallback={<CustomErrorFallback />}>
  <YourComponent />
</ErrorBoundary>
```

## Advanced Usage

### Custom Hooks Integration

All components use React Query hooks from `hooks/usePlaybooks.ts`:

```tsx
// hooks/usePlaybooks.ts
import { useQuery } from '@tanstack/react-query';
import { getPlaybooks, getPlaybook } from '../services/api';

// Get all playbooks
export function usePlaybooks(limit?: number, offset?: number) {
  return useQuery({
    queryKey: ['playbooks', limit, offset],
    queryFn: () => getPlaybooks(limit, offset),
    staleTime: 5 * 60 * 1000,
  });
}

// Get single playbook
export function usePlaybook(id: string) {
  return useQuery({
    queryKey: ['playbook', id],
    queryFn: () => getPlaybook(id),
    enabled: !!id,
    staleTime: 10 * 60 * 1000,
  });
}
```

### Custom Styling

All components use TailwindCSS. To customize:

```tsx
// Override with Tailwind classes
import { cn } from '../lib/utils';

<div className={cn(
  'default-classes',
  customCondition && 'conditional-classes'
)}>
  Content
</div>
```

### Utility Functions

Common utilities from `lib/utils.ts`:

```tsx
import {
  getSeverityBadgeColor,
  formatDate,
  copyToClipboard,
  downloadText
} from '../lib/utils';

// Get severity color classes
const classes = getSeverityBadgeColor('critical');
// Returns: 'bg-red-500 text-white'

// Format date
const formatted = formatDate('2024-01-15T10:30:00Z');
// Returns: 'Jan 15, 2024'

// Copy to clipboard
await copyToClipboard('text to copy');

// Download as file
downloadText('content', 'filename.txt');
```

## API Integration

### API Service

All API calls go through `services/api.ts`:

```tsx
// services/api.ts
import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 30000,
});

// Get all playbooks
export const getPlaybooks = async (limit?: number, offset?: number) => {
  const response = await api.get('/playbooks', {
    params: { limit, offset },
  });
  return response.data;
};

// Get single playbook
export const getPlaybook = async (id: string) => {
  const response = await api.get(`/playbooks/${id}`);
  return response.data;
};

// Search playbooks
export const searchPlaybooks = async (filters: SearchFilters) => {
  const response = await api.get('/search', {
    params: filters,
  });
  return response.data;
};
```

### Type Definitions

All types are defined in `types/playbook.ts`:

```tsx
export interface Playbook {
  id: string;
  name: string;
  description: string;
  mitre: {
    technique: string;
    tactic: string;
    subtechniques?: string[];
  };
  severity: 'critical' | 'high' | 'medium' | 'low';
  author: string;
  created: string;
  updated: string;
  data_sources: string[];
  hunt_hypothesis: string;
  queries: {
    splunk?: string;
    elastic?: string;
    sigma?: string;
  };
  investigation_steps: string[];
  false_positives: string[];
  iocs?: IOC[];
  references: string[];
  tags: string[];
}

export interface IOC {
  type: string;
  value: string;
  context: string;
}
```

## State Management

### React Query Cache

Configure caching behavior:

```tsx
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Don't refetch on window focus
      refetchOnWindowFocus: false,

      // Retry failed requests once
      retry: 1,

      // Cache data for 5 minutes
      staleTime: 5 * 60 * 1000,

      // Keep unused data in cache for 10 minutes
      cacheTime: 10 * 60 * 1000,
    },
  },
});
```

### Manual Cache Invalidation

```tsx
import { useQueryClient } from '@tanstack/react-query';

function MyComponent() {
  const queryClient = useQueryClient();

  const handleRefresh = () => {
    // Invalidate all playbooks
    queryClient.invalidateQueries({ queryKey: ['playbooks'] });

    // Invalidate specific playbook
    queryClient.invalidateQueries({ queryKey: ['playbook', id] });
  };

  return <button onClick={handleRefresh}>Refresh</button>;
}
```

## Performance Tips

### 1. Memoization

Components already use `useMemo` for expensive computations:

```tsx
const filteredPlaybooks = useMemo(() => {
  // Filtering logic
}, [playbooks, filters]);
```

### 2. Code Splitting

Add lazy loading for better performance:

```tsx
import { lazy, Suspense } from 'react';

const PlaybookDetail = lazy(() => import('./components/PlaybookDetail'));

<Suspense fallback={<LoadingSpinner />}>
  <PlaybookDetail />
</Suspense>
```

### 3. Virtual Scrolling

For very large lists, consider adding virtual scrolling:

```bash
npm install @tanstack/react-virtual
```

## Testing

### Unit Test Example

```tsx
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import PlaybookList from './PlaybookList';

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });

  return ({ children }) => (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        {children}
      </BrowserRouter>
    </QueryClientProvider>
  );
};

test('renders playbook list', async () => {
  render(<PlaybookList />, { wrapper: createWrapper() });

  await waitFor(() => {
    expect(screen.getByText(/Threat Hunting Playbooks/i)).toBeInTheDocument();
  });
});

test('filters playbooks by search', async () => {
  const user = userEvent.setup();
  render(<PlaybookList />, { wrapper: createWrapper() });

  const searchInput = screen.getByPlaceholderText(/search playbooks/i);
  await user.type(searchInput, 'credential dumping');

  // Assert filtered results
});
```

## Troubleshooting

### Issue: Components not rendering

**Solution:**
1. Check API endpoint in `.env`
2. Verify React Query setup
3. Check browser console for errors

### Issue: Styles not applied

**Solution:**
1. Ensure Tailwind is configured: `npx tailwindcss init`
2. Check `tailwind.config.js` includes component paths
3. Verify PostCSS configuration

### Issue: Type errors

**Solution:**
```bash
# Run type check
npm run type-check

# Check for missing types
npm install --save-dev @types/react @types/react-dom
```

### Issue: API calls failing

**Solution:**
1. Check CORS configuration on backend
2. Verify API URL in environment variables
3. Check network tab in DevTools

## Best Practices

### 1. Error Handling

Always wrap components in ErrorBoundary:

```tsx
<ErrorBoundary>
  <YourComponent />
</ErrorBoundary>
```

### 2. Loading States

Components handle loading automatically, but you can add custom loaders:

```tsx
if (isLoading) {
  return <CustomLoader />;
}
```

### 3. Accessibility

All components include:
- ARIA labels
- Keyboard navigation
- Semantic HTML
- Focus management

### 4. Type Safety

Always use TypeScript types:

```tsx
import type { Playbook } from '../types/playbook';

const playbook: Playbook = {
  // TypeScript will validate structure
};
```

## Additional Resources

- [React Query Documentation](https://tanstack.com/query/latest)
- [React Router Documentation](https://reactrouter.com/)
- [TailwindCSS Documentation](https://tailwindcss.com/)
- [Lucide React Icons](https://lucide.dev/)

## Support

For issues or questions:
1. Check the component README files
2. Review TypeScript types
3. Check browser console
4. Review React Query DevTools

## Next Steps

After setting up these components, consider:
1. Adding user authentication
2. Implementing playbook creation/editing
3. Adding analytics and metrics
4. Creating export functionality
5. Building collaborative features
