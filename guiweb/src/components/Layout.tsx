import { ReactNode, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  Shield,
  BookOpen,
  Activity,
  Menu,
  X,
  Search,
  Bell,
  Settings as SettingsIcon,
  Github,
  Sparkles,
  ArrowRightLeft,
} from 'lucide-react';
import { cn } from '../lib/utils';
import SearchModal from './SearchModal';
import AIAssistant from './AIAssistant';
import NotificationsPanel from './NotificationsPanel';

interface LayoutProps {
  children: ReactNode;
}

interface NavItem {
  name: string;
  path: string;
  icon: typeof Shield;
}

const navItems: NavItem[] = [
  { name: 'Playbooks', path: '/', icon: BookOpen },
  { name: 'Dashboard', path: '/dashboard', icon: Activity },
  { name: 'MITRE ATT&CK', path: '/mitre', icon: Shield },
  { name: 'Sigma Translator', path: '/sigma', icon: ArrowRightLeft },
  { name: 'Sigma Mappings', path: '/sigma/mappings', icon: SettingsIcon },
  { name: 'Post-Mortem', path: '/post-mortem', icon: BookOpen },
  { name: 'Settings', path: '/settings', icon: SettingsIcon },
];

export default function Layout({ children }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [aiAssistantOpen, setAiAssistantOpen] = useState(false);
  const location = useLocation();

  const isActive = (path: string) => {
    if (path === '/') {
      return location.pathname === '/';
    }
    return location.pathname.startsWith(path);
  };

  return (
    <div className="min-h-screen bg-gray-950">
      {/* Header */}
      <header className="fixed top-0 left-0 right-0 z-50 border-b border-gray-800 bg-gray-900/95 backdrop-blur supports-[backdrop-filter]:bg-gray-900/75">
        <div className="flex h-16 items-center justify-between px-4 sm:px-6">
          {/* Logo & Mobile Menu */}
          <div className="flex items-center gap-4">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="lg:hidden rounded-md p-2 text-gray-400 hover:bg-gray-800 hover:text-gray-100 transition-colors"
              aria-label="Toggle sidebar"
            >
              {sidebarOpen ? <X size={24} /> : <Menu size={24} />}
            </button>

            <Link to="/" className="flex items-center gap-2 group">
              <Shield className="h-8 w-8 text-cyan-500 group-hover:text-cyan-400 transition-colors" />
              <div className="hidden sm:block">
                <h1 className="text-lg font-bold text-gray-100 group-hover:text-cyan-400 transition-colors">
                  Threat Hunting
                </h1>
                <p className="text-xs text-gray-500 -mt-1">Playbook Library</p>
              </div>
            </Link>
          </div>

          {/* Header Actions */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSearchOpen(true)}
              className="rounded-md p-2 text-gray-400 hover:bg-gray-800 hover:text-gray-100 transition-colors"
              aria-label="Search"
            >
              <Search size={20} />
            </button>
            <button
              onClick={() => setNotificationsOpen(true)}
              className="rounded-md p-2 text-gray-400 hover:bg-gray-800 hover:text-gray-100 transition-colors relative"
              aria-label="Notifications"
            >
              <Bell size={20} />
              <span className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-red-500" />
            </button>
            <button
              onClick={() => setAiAssistantOpen(true)}
              className="rounded-md p-2 text-gray-400 hover:bg-gray-800 hover:text-cyan-400 transition-colors"
              aria-label="AI Assistant"
            >
              <Sparkles size={20} />
            </button>
            <a
              href="https://github.com/anthropics/threat-hunting-playbook"
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-md p-2 text-gray-400 hover:bg-gray-800 hover:text-gray-100 transition-colors"
              aria-label="GitHub repository"
            >
              <Github size={20} />
            </a>
          </div>
        </div>
      </header>

      {/* Sidebar */}
      <aside
        className={cn(
          'fixed left-0 top-16 bottom-0 z-40 w-64 border-r border-gray-800 bg-gray-900 transition-transform duration-300 ease-in-out',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        )}
      >
        <nav className="flex h-full flex-col p-4">
          <div className="flex-1 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = isActive(item.path);

              return (
                <Link
                  key={item.path}
                  to={item.path}
                  onClick={() => setSidebarOpen(false)}
                  className={cn(
                    'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all',
                    active
                      ? 'bg-cyan-500/10 text-cyan-400 shadow-sm shadow-cyan-500/20'
                      : 'text-gray-400 hover:bg-gray-800 hover:text-gray-100'
                  )}
                  aria-current={active ? 'page' : undefined}
                >
                  <Icon size={20} />
                  <span>{item.name}</span>
                </Link>
              );
            })}
          </div>

          {/* Sidebar Footer */}
          <div className="border-t border-gray-800 pt-4 mt-4">
            <div className="rounded-lg bg-gray-800/50 p-3">
              <p className="text-xs font-medium text-gray-400">
                Version 1.0.0
              </p>
              <p className="text-xs text-gray-500 mt-1">
                Powered by MITRE ATT&CK
              </p>
            </div>
          </div>
        </nav>
      </aside>

      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-gray-950/80 backdrop-blur-sm lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Main Content */}
      <main className="pt-16 lg:pl-64 min-h-screen">
        <div className="p-4 sm:p-6 lg:p-8">
          {children}
        </div>
      </main>

      {/* Modals & Panels */}
      <SearchModal isOpen={searchOpen} onClose={() => setSearchOpen(false)} />
      <NotificationsPanel isOpen={notificationsOpen} onClose={() => setNotificationsOpen(false)} />
      <AIAssistant isOpen={aiAssistantOpen} onClose={() => setAiAssistantOpen(false)} />
    </div>
  );
}
