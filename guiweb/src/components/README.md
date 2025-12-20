# Threat Hunting Playbook Components

This directory contains the core React components for the Threat Hunting Playbook GUI.

## Components Overview

### Layout.tsx
Main application layout with responsive header and sidebar navigation.

**Features:**
- Responsive sidebar with mobile hamburger menu
- Header with branding and action buttons
- Navigation items with active state highlighting
- Dark theme with glassmorphism effects
- Accessibility features (ARIA labels, keyboard navigation)

**Usage:**
```tsx
import { Layout } from './components';

<Layout>
  <YourContent />
</Layout>
```

### PlaybookList.tsx
Comprehensive table view of all threat hunting playbooks with advanced filtering.

**Features:**
- Real-time search across name, description, technique, and tags
- Multi-filter support (tactic, severity, tags)
- Sortable columns (name, severity, created, updated)
- Loading and error states with retry functionality
- Responsive table design
- Visual severity badges
- MITRE ATT&CK technique display

**State Management:**
- Uses `usePlaybooks` hook from React Query
- Client-side filtering and sorting
- Automatic cache invalidation

**Usage:**
```tsx
import { PlaybookList } from './components';

<Route path="/" element={<PlaybookList />} />
```

### PlaybookDetail.tsx
Detailed view of a single playbook with tabbed interface.

**Features:**
- Three tab views: Overview, Queries, IOCs
- **Overview Tab:**
  - MITRE ATT&CK framework information
  - Hunt hypothesis
  - Data sources
  - Investigation steps
  - False positives
  - Tags and references
- **Queries Tab:**
  - Platform-specific queries (Splunk, Elastic, Sigma)
  - Copy to clipboard functionality
  - Download query files
  - Syntax-highlighted code blocks
- **IOCs Tab:**
  - Searchable IOC table
  - Type-based color coding
  - Copy individual IOCs

**URL Parameters:**
- `:id` - Playbook ID from URL path

**Usage:**
```tsx
import { PlaybookDetail } from './components';

<Route path="/playbook/:id" element={<PlaybookDetail />} />
```

### ErrorBoundary.tsx
Production-ready error boundary component with detailed error reporting.

**Features:**
- Catches React component errors
- Beautiful error UI with technical details
- Reset and navigation actions
- Component stack trace display
- User-friendly error messages
- Helpful troubleshooting tips

**Usage:**
```tsx
import { ErrorBoundary } from './components';

<ErrorBoundary>
  <App />
</ErrorBoundary>
```

Or with custom fallback:
```tsx
<ErrorBoundary fallback={<CustomErrorUI />}>
  <App />
</ErrorBoundary>
```

## Design System

### Colors
- **Primary:** Cyan (cyan-500, cyan-400)
- **Background:** Gray-950, Gray-900
- **Surface:** Gray-800
- **Text:** Gray-100 (primary), Gray-400 (secondary)
- **Severity:**
  - Critical: Red-500
  - High: Amber-500
  - Medium: Yellow-500
  - Low: Emerald-500

### Typography
- **Headings:** Bold, Gray-100
- **Body:** Regular, Gray-300
- **Labels:** Medium, Gray-400
- **Code:** Monospace, Gray-300 on Gray-800

### Spacing
- Component padding: p-4 to p-8
- Card padding: p-4 to p-6
- Gap between elements: gap-2 to gap-6

## Dependencies

### Required
- `react` ^18.2.0
- `react-dom` ^18.2.0
- `react-router-dom` ^6.21.0
- `@tanstack/react-query` ^5.17.0
- `lucide-react` ^0.307.0
- `clsx` ^2.1.0
- `tailwind-merge` ^2.2.0

### Dev Dependencies
- `typescript` ^5.3.3
- `tailwindcss` ^3.4.1

## Type Safety

All components are written in TypeScript with strict type checking:
- Interface definitions in `types/playbook.ts`
- Proper prop typing with TypeScript interfaces
- Type-safe API integration
- No `any` types used

## Accessibility

### ARIA Labels
- All interactive elements have proper `aria-label` attributes
- Navigation items use `aria-current` for active states
- Modal overlays have `aria-hidden` attributes

### Keyboard Navigation
- Fully keyboard accessible
- Tab order follows visual hierarchy
- Focus states visible with ring utilities

### Screen Readers
- Semantic HTML elements used throughout
- Proper heading hierarchy (h1 → h6)
- Loading states announced
- Error messages accessible

## Performance Optimizations

### React Query Caching
- Playbooks cached for 5 minutes
- Individual playbook cached for 10 minutes
- Search results cached for 2 minutes

### Memoization
- Filter options computed with `useMemo`
- Filtered/sorted data only recalculated on dependency changes

### Code Splitting
- Component-level code splitting ready
- Lazy loading can be added with React.lazy()

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Testing Recommendations

### Unit Tests
```tsx
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import PlaybookList from './PlaybookList';

const queryClient = new QueryClient();

test('renders playbook list', () => {
  render(
    <QueryClientProvider client={queryClient}>
      <PlaybookList />
    </QueryClientProvider>
  );
  expect(screen.getByText(/Threat Hunting Playbooks/i)).toBeInTheDocument();
});
```

### Integration Tests
- Test routing between components
- Test filter combinations
- Test error states and recovery
- Test copy/download functionality

## Troubleshooting

### Components not rendering
- Ensure React Query is set up in App.tsx
- Check API endpoint configuration in `.env`
- Verify TypeScript compilation

### Styling issues
- Ensure Tailwind CSS is configured properly
- Check `tailwind.config.js` includes component paths
- Verify PostCSS is processing styles

### Type errors
- Run `npm run type-check` to identify issues
- Ensure all type definitions are imported
- Check hook return types match expectations

## Future Enhancements

### Planned Features
- [ ] Playbook comparison view
- [ ] Advanced analytics dashboard
- [ ] AI-powered query suggestions
- [ ] Export to multiple formats (PDF, JSON, CSV)
- [ ] Collaborative features (comments, sharing)
- [ ] Dark/light theme toggle
- [ ] Customizable layouts
- [ ] Saved filter presets

### Performance Improvements
- [ ] Virtual scrolling for large lists
- [ ] Intersection Observer for lazy loading
- [ ] Service Worker for offline support
- [ ] IndexedDB caching layer

## Contributing

When adding new components:
1. Follow existing component structure
2. Use TypeScript with strict types
3. Implement proper error handling
4. Add loading states
5. Include accessibility features
6. Document props and usage
7. Export from `index.ts`

## License

See main project LICENSE file.
