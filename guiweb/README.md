# Threat Hunting Playbook - Web GUI

Modern, dark-themed web interface for the Threat Hunting Playbook API.

## Features

- Browse and search threat hunting playbooks
- View detailed playbook information with syntax-highlighted queries
- Export queries for Splunk, Elastic, and Sigma
- AI-powered explanations and analysis
- Responsive design (desktop, tablet, mobile)
- Dark mode optimized for security operations

## Tech Stack

- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool and dev server
- **TailwindCSS** - Styling
- **TanStack Query** - Data fetching and caching
- **React Router** - Navigation
- **Axios** - HTTP client
- **Lucide React** - Icons

## Quick Start

### Prerequisites

- Node.js 18+ and npm
- Threat Hunting Playbook API running on `http://localhost:8000`

### Installation

```bash
cd guiweb
npm install
```

### Development

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Build

```bash
npm run build
```

Production build will be in `dist/` directory.

### Type Check

```bash
npm run type-check
```

### Lint

```bash
npm run lint
```

## Configuration

Create `.env` file based on `.env.example`:

```bash
cp .env.example .env
```

Edit `.env`:

```
VITE_API_URL=http://localhost:8000/api
```

## Project Structure

```
guiweb/
├── src/
│   ├── components/        # React components
│   │   ├── Layout.tsx
│   │   ├── PlaybookList.tsx
│   │   └── PlaybookDetail.tsx
│   ├── hooks/             # Custom React hooks
│   │   └── usePlaybooks.ts
│   ├── services/          # API services
│   │   └── api.ts
│   ├── types/             # TypeScript types
│   │   └── playbook.ts
│   ├── lib/               # Utilities
│   │   └── utils.ts
│   ├── App.tsx            # Main app component
│   ├── main.tsx           # Entry point
│   └── index.css          # Global styles
├── package.json
├── tsconfig.json
├── vite.config.ts
└── tailwind.config.js
```

## Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Lint TypeScript files
- `npm run type-check` - TypeScript type checking

## Design System

### Colors

- **Primary**: Sky Blue (#0ea5e9) - Actions, links
- **Danger**: Red (#ef4444) - Critical severity
- **Warning**: Amber (#f59e0b) - High severity
- **Success**: Emerald (#10b981) - Medium/Low severity
- **Accent**: Violet (#8b5cf6) - AI features

### Typography

- **Headings**: Inter
- **Code**: JetBrains Mono
- **Body**: Inter

## Development Guidelines

### Component Guidelines

- Use functional components with hooks
- Implement proper TypeScript types (no `any`)
- Handle loading and error states
- Add accessibility attributes (ARIA)
- Use semantic HTML

### Code Style

- Follow TypeScript strict mode
- Use ESLint for code quality
- Format with Prettier (via ESLint)
- Keep components small and focused
- Extract reusable logic into custom hooks

### State Management

- Use React Query for server state
- Use React hooks for local state
- Avoid prop drilling (use context if needed)

## Deployment

### Static Hosting

Build and deploy to any static hosting service:

```bash
npm run build
# Upload dist/ folder to your hosting service
```

### Docker

Include in parent Dockerfile:

```dockerfile
# Build frontend
FROM node:18-alpine AS frontend-build
WORKDIR /app/guiweb
COPY guiweb/package*.json ./
RUN npm ci
COPY guiweb/ ./
RUN npm run build

# Serve with nginx
FROM nginx:alpine
COPY --from=frontend-build /app/guiweb/dist /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/nginx.conf
```

### Nginx Configuration

Serve SPA with API proxy:

```nginx
server {
    listen 80;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;

    # SPA routing
    location / {
        try_files $uri $uri/ /index.html;
    }

    # API proxy
    location /api {
        proxy_pass http://api:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Troubleshooting

### Port Already in Use

Change port in `vite.config.ts`:

```ts
server: {
  port: 3001,  // Change to different port
}
```

### API Connection Failed

1. Check API is running: `curl http://localhost:8000/health`
2. Verify `VITE_API_URL` in `.env`
3. Check browser console for CORS errors

### Build Errors

1. Clear node_modules: `rm -rf node_modules && npm install`
2. Clear cache: `npm run build -- --force`
3. Check Node.js version: `node -v` (should be 18+)

## Contributing

1. Create feature branch
2. Make changes
3. Run type check and lint
4. Test locally
5. Submit pull request

## License

MIT - See parent project LICENSE file
