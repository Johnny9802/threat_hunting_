import { useState } from 'react';
import {
  Settings as SettingsIcon,
  Save,
  RotateCcw,
  CheckCircle,
  Server,
  Palette,
  Bell,
  Shield,
  Database,
  Bot,
  Eye,
  EyeOff,
  Zap,
} from 'lucide-react';
import { cn } from '../lib/utils';

interface SettingsSection {
  id: string;
  title: string;
  icon: typeof SettingsIcon;
  description: string;
}

const SETTINGS_SECTIONS: SettingsSection[] = [
  {
    id: 'general',
    title: 'General',
    icon: SettingsIcon,
    description: 'Basic application settings',
  },
  {
    id: 'api',
    title: 'API Configuration',
    icon: Server,
    description: 'Backend and API settings',
  },
  {
    id: 'ai',
    title: 'AI Assistant',
    icon: Bot,
    description: 'Configure AI provider and API keys',
  },
  {
    id: 'appearance',
    title: 'Appearance',
    icon: Palette,
    description: 'Theme and display preferences',
  },
  {
    id: 'notifications',
    title: 'Notifications',
    icon: Bell,
    description: 'Notification preferences',
  },
  {
    id: 'security',
    title: 'Security',
    icon: Shield,
    description: 'Security and privacy settings',
  },
];

export default function Settings() {
  const [activeSection, setActiveSection] = useState('general');
  const [apiUrl, setApiUrl] = useState(import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000');
  const [theme, setTheme] = useState('dark');
  const [enableNotifications, setEnableNotifications] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState('5');
  const [saveSuccess, setSaveSuccess] = useState(false);

  // AI Settings
  const [aiProvider, setAiProvider] = useState<'groq' | 'openai'>(() => {
    const saved = localStorage.getItem('ai_provider');
    return (saved as 'groq' | 'openai') || 'groq';
  });
  const [groqApiKey, setGroqApiKey] = useState(() => localStorage.getItem('groq_api_key') || '');
  const [openaiApiKey, setOpenaiApiKey] = useState(() => localStorage.getItem('openai_api_key') || '');
  const [showGroqKey, setShowGroqKey] = useState(false);
  const [showOpenaiKey, setShowOpenaiKey] = useState(false);
  const [aiTestStatus, setAiTestStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');
  const [aiTestMessage, setAiTestMessage] = useState('');

  const handleSave = async () => {
    // Save general settings
    localStorage.setItem('settings', JSON.stringify({
      apiUrl,
      theme,
      enableNotifications,
      autoRefresh,
      refreshInterval,
    }));

    // Save AI settings
    localStorage.setItem('ai_provider', aiProvider);
    localStorage.setItem('groq_api_key', groqApiKey);
    localStorage.setItem('openai_api_key', openaiApiKey);

    // Send AI config to backend
    try {
      await fetch(`${apiUrl}/api/config/ai`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: aiProvider,
          groq_api_key: groqApiKey,
          openai_api_key: openaiApiKey,
        }),
      });
    } catch (err) {
      console.error('Failed to save AI config to backend:', err);
    }

    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 3000);
  };

  const testAiConnection = async () => {
    setAiTestStatus('testing');
    setAiTestMessage('Testing connection...');

    const currentKey = aiProvider === 'groq' ? groqApiKey : openaiApiKey;
    if (!currentKey) {
      setAiTestStatus('error');
      setAiTestMessage('Please enter an API key first');
      return;
    }

    try {
      const response = await fetch(`${apiUrl}/api/ai/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: aiProvider,
          api_key: currentKey,
        }),
      });

      if (response.ok) {
        setAiTestStatus('success');
        setAiTestMessage('Connection successful! AI is ready to use.');
      } else {
        const data = await response.json();
        setAiTestStatus('error');
        setAiTestMessage(data.detail || 'Connection failed');
      }
    } catch {
      setAiTestStatus('error');
      setAiTestMessage('Failed to connect to backend');
    }
  };

  const handleReset = () => {
    setApiUrl('http://localhost:8000');
    setTheme('dark');
    setEnableNotifications(true);
    setAutoRefresh(true);
    setRefreshInterval('5');
    setAiProvider('groq');
    setGroqApiKey('');
    setOpenaiApiKey('');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-100">Settings</h1>
        <p className="text-gray-400 mt-1">Manage your application preferences and configuration</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Sidebar */}
        <div className="lg:col-span-1">
          <nav className="space-y-1 rounded-lg border border-gray-800 bg-gray-900 p-2">
            {SETTINGS_SECTIONS.map((section) => {
              const Icon = section.icon;
              const isActive = activeSection === section.id;

              return (
                <button
                  key={section.id}
                  onClick={() => setActiveSection(section.id)}
                  className={cn(
                    'flex w-full items-start gap-3 rounded-lg px-3 py-2.5 text-left transition-all',
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400 shadow-sm shadow-cyan-500/20'
                      : 'text-gray-400 hover:bg-gray-800 hover:text-gray-100'
                  )}
                >
                  <Icon size={18} className="flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-medium text-sm">{section.title}</p>
                    <p className="text-xs text-gray-500 mt-0.5">{section.description}</p>
                  </div>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Content */}
        <div className="lg:col-span-3 space-y-6">
          {/* General Settings */}
          {activeSection === 'general' && (
            <div className="rounded-lg border border-gray-800 bg-gray-900 p-6 space-y-6">
              <div>
                <h2 className="text-xl font-semibold text-gray-100 mb-1">General Settings</h2>
                <p className="text-sm text-gray-400">Configure basic application behavior</p>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="flex items-center gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={autoRefresh}
                      onChange={(e) => setAutoRefresh(e.target.checked)}
                      className="rounded border-gray-700 bg-gray-800 text-cyan-500 focus:ring-2 focus:ring-cyan-500 focus:ring-offset-0"
                    />
                    <div>
                      <p className="text-sm font-medium text-gray-100">Auto-refresh playbooks</p>
                      <p className="text-xs text-gray-500">Automatically refresh playbook list</p>
                    </div>
                  </label>
                </div>

                {autoRefresh && (
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Refresh interval (minutes)
                    </label>
                    <input
                      type="number"
                      min="1"
                      max="60"
                      value={refreshInterval}
                      onChange={(e) => setRefreshInterval(e.target.value)}
                      className="w-full max-w-xs rounded-lg border border-gray-800 bg-gray-950 px-4 py-2 text-gray-100 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                    />
                  </div>
                )}
              </div>
            </div>
          )}

          {/* API Configuration */}
          {activeSection === 'api' && (
            <div className="rounded-lg border border-gray-800 bg-gray-900 p-6 space-y-6">
              <div>
                <h2 className="text-xl font-semibold text-gray-100 mb-1">API Configuration</h2>
                <p className="text-sm text-gray-400">Configure backend API connection</p>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    API Base URL
                  </label>
                  <input
                    type="url"
                    value={apiUrl}
                    onChange={(e) => setApiUrl(e.target.value)}
                    placeholder="http://localhost:8000"
                    className="w-full rounded-lg border border-gray-800 bg-gray-950 px-4 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    URL of the Threat Hunting Playbook API backend
                  </p>
                </div>

                <div className="rounded-lg border border-blue-500/20 bg-blue-500/10 p-4">
                  <div className="flex items-start gap-3">
                    <Database className="h-5 w-5 text-blue-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm text-blue-300 font-medium">API Status</p>
                      <p className="text-xs text-blue-200/80 mt-1">
                        Connected to {apiUrl}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* AI Configuration */}
          {activeSection === 'ai' && (
            <div className="rounded-lg border border-gray-800 bg-gray-900 p-6 space-y-6">
              <div>
                <h2 className="text-xl font-semibold text-gray-100 mb-1">AI Assistant Configuration</h2>
                <p className="text-sm text-gray-400">Configure AI provider for playbook explanations and suggestions</p>
              </div>

              <div className="space-y-6">
                {/* Provider Selection */}
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-3">
                    AI Provider
                  </label>
                  <div className="grid grid-cols-2 gap-3 max-w-md">
                    <button
                      onClick={() => setAiProvider('groq')}
                      className={cn(
                        'rounded-lg border p-4 text-left transition-all',
                        aiProvider === 'groq'
                          ? 'border-cyan-500 bg-cyan-500/10'
                          : 'border-gray-800 bg-gray-950 hover:bg-gray-800'
                      )}
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <Zap className="h-4 w-4 text-yellow-400" />
                        <p className="text-sm font-medium text-gray-100">Groq</p>
                      </div>
                      <p className="text-xs text-gray-500">Fast & Free tier available</p>
                    </button>
                    <button
                      onClick={() => setAiProvider('openai')}
                      className={cn(
                        'rounded-lg border p-4 text-left transition-all',
                        aiProvider === 'openai'
                          ? 'border-cyan-500 bg-cyan-500/10'
                          : 'border-gray-800 bg-gray-950 hover:bg-gray-800'
                      )}
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <Bot className="h-4 w-4 text-green-400" />
                        <p className="text-sm font-medium text-gray-100">OpenAI</p>
                      </div>
                      <p className="text-xs text-gray-500">GPT-4 Turbo</p>
                    </button>
                  </div>
                </div>

                {/* Groq API Key */}
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Groq API Key
                  </label>
                  <div className="relative">
                    <input
                      type={showGroqKey ? 'text' : 'password'}
                      value={groqApiKey}
                      onChange={(e) => setGroqApiKey(e.target.value)}
                      placeholder="gsk_..."
                      className="w-full rounded-lg border border-gray-800 bg-gray-950 px-4 py-2 pr-10 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono text-sm"
                    />
                    <button
                      type="button"
                      onClick={() => setShowGroqKey(!showGroqKey)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                    >
                      {showGroqKey ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>
                  <p className="text-xs text-gray-500 mt-1">
                    Get your free API key at{' '}
                    <a
                      href="https://console.groq.com/keys"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyan-400 hover:underline"
                    >
                      console.groq.com/keys
                    </a>
                  </p>
                </div>

                {/* OpenAI API Key */}
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    OpenAI API Key
                  </label>
                  <div className="relative">
                    <input
                      type={showOpenaiKey ? 'text' : 'password'}
                      value={openaiApiKey}
                      onChange={(e) => setOpenaiApiKey(e.target.value)}
                      placeholder="sk-..."
                      className="w-full rounded-lg border border-gray-800 bg-gray-950 px-4 py-2 pr-10 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono text-sm"
                    />
                    <button
                      type="button"
                      onClick={() => setShowOpenaiKey(!showOpenaiKey)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                    >
                      {showOpenaiKey ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>
                  <p className="text-xs text-gray-500 mt-1">
                    Get your API key at{' '}
                    <a
                      href="https://platform.openai.com/api-keys"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyan-400 hover:underline"
                    >
                      platform.openai.com/api-keys
                    </a>
                  </p>
                </div>

                {/* Test Connection */}
                <div className="pt-2">
                  <button
                    onClick={testAiConnection}
                    disabled={aiTestStatus === 'testing'}
                    className="flex items-center gap-2 rounded-md bg-gray-800 px-4 py-2 text-sm font-medium text-gray-200 hover:bg-gray-700 transition-colors disabled:opacity-50"
                  >
                    <Zap size={16} />
                    {aiTestStatus === 'testing' ? 'Testing...' : 'Test Connection'}
                  </button>
                </div>

                {/* Test Status */}
                {aiTestStatus !== 'idle' && (
                  <div
                    className={cn(
                      'rounded-lg border p-4',
                      aiTestStatus === 'success'
                        ? 'border-green-500/20 bg-green-500/10'
                        : aiTestStatus === 'error'
                        ? 'border-red-500/20 bg-red-500/10'
                        : 'border-blue-500/20 bg-blue-500/10'
                    )}
                  >
                    <div className="flex items-start gap-3">
                      <Bot
                        className={cn(
                          'h-5 w-5 flex-shrink-0 mt-0.5',
                          aiTestStatus === 'success'
                            ? 'text-green-400'
                            : aiTestStatus === 'error'
                            ? 'text-red-400'
                            : 'text-blue-400'
                        )}
                      />
                      <div>
                        <p
                          className={cn(
                            'text-sm font-medium',
                            aiTestStatus === 'success'
                              ? 'text-green-300'
                              : aiTestStatus === 'error'
                              ? 'text-red-300'
                              : 'text-blue-300'
                          )}
                        >
                          {aiTestStatus === 'success'
                            ? 'Connection Successful'
                            : aiTestStatus === 'error'
                            ? 'Connection Failed'
                            : 'Testing...'}
                        </p>
                        <p
                          className={cn(
                            'text-xs mt-1',
                            aiTestStatus === 'success'
                              ? 'text-green-200/80'
                              : aiTestStatus === 'error'
                              ? 'text-red-200/80'
                              : 'text-blue-200/80'
                          )}
                        >
                          {aiTestMessage}
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Info Box */}
                <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/10 p-4">
                  <div className="flex items-start gap-3">
                    <Bot className="h-5 w-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm text-yellow-300 font-medium">AI Features</p>
                      <p className="text-xs text-yellow-200/80 mt-1">
                        With AI enabled, you can: explain playbooks, ask security questions,
                        get investigation suggestions, and generate playbook variants.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Appearance */}
          {activeSection === 'appearance' && (
            <div className="rounded-lg border border-gray-800 bg-gray-900 p-6 space-y-6">
              <div>
                <h2 className="text-xl font-semibold text-gray-100 mb-1">Appearance</h2>
                <p className="text-sm text-gray-400">Customize the look and feel</p>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Theme</label>
                  <div className="grid grid-cols-2 gap-3 max-w-md">
                    <button
                      onClick={() => setTheme('dark')}
                      className={cn(
                        'rounded-lg border p-4 text-left transition-all',
                        theme === 'dark'
                          ? 'border-cyan-500 bg-cyan-500/10'
                          : 'border-gray-800 bg-gray-950 hover:bg-gray-800'
                      )}
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <div className="h-3 w-3 rounded-full bg-gray-950" />
                        <p className="text-sm font-medium text-gray-100">Dark</p>
                      </div>
                      <p className="text-xs text-gray-500">Default dark theme</p>
                    </button>
                    <button
                      onClick={() => setTheme('light')}
                      disabled
                      className="rounded-lg border border-gray-800 bg-gray-950 p-4 text-left opacity-50 cursor-not-allowed"
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <div className="h-3 w-3 rounded-full bg-gray-200" />
                        <p className="text-sm font-medium text-gray-100">Light</p>
                      </div>
                      <p className="text-xs text-gray-500">Coming soon</p>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Notifications */}
          {activeSection === 'notifications' && (
            <div className="rounded-lg border border-gray-800 bg-gray-900 p-6 space-y-6">
              <div>
                <h2 className="text-xl font-semibold text-gray-100 mb-1">Notifications</h2>
                <p className="text-sm text-gray-400">Manage notification preferences</p>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="flex items-center gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={enableNotifications}
                      onChange={(e) => setEnableNotifications(e.target.checked)}
                      className="rounded border-gray-700 bg-gray-800 text-cyan-500 focus:ring-2 focus:ring-cyan-500 focus:ring-offset-0"
                    />
                    <div>
                      <p className="text-sm font-medium text-gray-100">Enable notifications</p>
                      <p className="text-xs text-gray-500">
                        Receive updates about new playbooks and changes
                      </p>
                    </div>
                  </label>
                </div>
              </div>
            </div>
          )}

          {/* Security */}
          {activeSection === 'security' && (
            <div className="rounded-lg border border-gray-800 bg-gray-900 p-6 space-y-6">
              <div>
                <h2 className="text-xl font-semibold text-gray-100 mb-1">Security & Privacy</h2>
                <p className="text-sm text-gray-400">Manage security settings</p>
              </div>

              <div className="rounded-lg border border-green-500/20 bg-green-500/10 p-4">
                <div className="flex items-start gap-3">
                  <Shield className="h-5 w-5 text-green-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm text-green-300 font-medium">Security Status</p>
                    <p className="text-xs text-green-200/80 mt-1">
                      All settings are stored locally in your browser
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center justify-between rounded-lg border border-gray-800 bg-gray-900 p-4">
            <button
              onClick={handleReset}
              className="flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium text-gray-400 hover:bg-gray-800 hover:text-gray-100 transition-colors"
            >
              <RotateCcw size={16} />
              Reset to defaults
            </button>
            <button
              onClick={handleSave}
              className="flex items-center gap-2 rounded-md bg-gradient-to-r from-cyan-500 to-blue-600 px-6 py-2 text-sm font-medium text-white hover:from-cyan-600 hover:to-blue-700 transition-all"
            >
              <Save size={16} />
              Save changes
            </button>
          </div>

          {/* Success Message */}
          {saveSuccess && (
            <div className="rounded-lg border border-green-500/20 bg-green-500/10 p-4">
              <div className="flex items-center gap-3">
                <CheckCircle className="h-5 w-5 text-green-500" />
                <p className="text-sm text-green-300 font-medium">
                  Settings saved successfully!
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
