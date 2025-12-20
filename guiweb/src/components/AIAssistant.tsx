import { useState } from 'react';
import { X, Send, Loader2, Sparkles, AlertCircle, CheckCircle, MessageSquare } from 'lucide-react';
import api from '../services/api';

interface AIAssistantProps {
  isOpen: boolean;
  onClose: () => void;
}

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

export default function AIAssistant({ isOpen, onClose }: AIAssistantProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: 'Hello! I\'m your AI Threat Hunting Assistant. I can help you with:\n\n• Explaining playbooks and detection techniques\n• Suggesting investigation steps for findings\n• Answering questions about threat hunting\n• Generating queries for different SIEM platforms\n\nHow can I assist you today?',
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      role: 'user',
      content: input.trim(),
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);
    setError(null);

    try {
      const response = await api.post('/api/ai/ask', {
        question: userMessage.content,
      });

      const assistantMessage: Message = {
        role: 'assistant',
        content: response.data.answer,
        timestamp: new Date(),
      };

      setMessages((prev) => [...prev, assistantMessage]);
    } catch (err) {
      let errorMessage = 'Failed to get response from AI assistant.';

      if (err instanceof Error) {
        errorMessage = err.message;
      }

      // Check if AI service is not available
      if (errorMessage.includes('503') || errorMessage.includes('not available')) {
        errorMessage = 'AI service is not available. Please configure GROQ_API_KEY or OPENAI_API_KEY in your environment.';
      }

      setError(errorMessage);

      const errorMsg: Message = {
        role: 'assistant',
        content: `I apologize, but I encountered an error: ${errorMessage}\n\nPlease try again or rephrase your question.`,
        timestamp: new Date(),
      };

      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const clearChat = () => {
    setMessages([
      {
        role: 'assistant',
        content: 'Chat cleared. How can I help you?',
        timestamp: new Date(),
      },
    ]);
    setError(null);
  };

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-gray-950/80 backdrop-blur-sm z-50"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Panel */}
      <div className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-2xl bg-gray-900 border-l border-gray-800 shadow-2xl flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-gray-800 bg-gray-900/95 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 p-2">
              <Sparkles className="h-5 w-5 text-white" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-gray-100">AI Assistant</h2>
              <p className="text-xs text-gray-500">Threat Hunting Expert</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={clearChat}
              className="rounded-md px-3 py-1.5 text-sm text-gray-400 hover:bg-gray-800 hover:text-gray-100 transition-colors"
            >
              Clear
            </button>
            <button
              onClick={onClose}
              className="rounded-md p-2 text-gray-400 hover:bg-gray-800 hover:text-gray-100 transition-colors"
              aria-label="Close AI Assistant"
            >
              <X size={20} />
            </button>
          </div>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {messages.map((message, index) => (
            <div
              key={index}
              className={`flex gap-3 ${
                message.role === 'user' ? 'justify-end' : 'justify-start'
              }`}
            >
              {message.role === 'assistant' && (
                <div className="flex-shrink-0 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 p-2">
                  <Sparkles className="h-4 w-4 text-white" />
                </div>
              )}
              <div
                className={`max-w-[80%] rounded-lg px-4 py-3 ${
                  message.role === 'user'
                    ? 'bg-cyan-500/10 border border-cyan-500/20 text-gray-100'
                    : 'bg-gray-800 text-gray-300'
                }`}
              >
                <p className="text-sm whitespace-pre-wrap leading-relaxed">
                  {message.content}
                </p>
                <p className="text-xs text-gray-500 mt-2">
                  {message.timestamp.toLocaleTimeString()}
                </p>
              </div>
              {message.role === 'user' && (
                <div className="flex-shrink-0 rounded-full bg-gray-700 p-2">
                  <MessageSquare className="h-4 w-4 text-gray-300" />
                </div>
              )}
            </div>
          ))}

          {isLoading && (
            <div className="flex gap-3 justify-start">
              <div className="flex-shrink-0 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 p-2">
                <Sparkles className="h-4 w-4 text-white" />
              </div>
              <div className="bg-gray-800 rounded-lg px-4 py-3">
                <div className="flex items-center gap-2">
                  <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
                  <p className="text-sm text-gray-400">Thinking...</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Error Banner */}
        {error && (
          <div className="mx-6 mb-4 rounded-lg border border-red-500/20 bg-red-500/10 p-3">
            <div className="flex items-start gap-2">
              <AlertCircle className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <p className="text-sm text-red-400 font-medium">Error</p>
                <p className="text-xs text-red-300/80 mt-1">{error}</p>
              </div>
              <button
                onClick={() => setError(null)}
                className="text-red-400 hover:text-red-300"
              >
                <X size={16} />
              </button>
            </div>
          </div>
        )}

        {/* Input */}
        <div className="border-t border-gray-800 bg-gray-900/95 px-6 py-4">
          <div className="flex items-end gap-3">
            <div className="flex-1">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask me anything about threat hunting, playbooks, or detection techniques..."
                rows={3}
                className="w-full resize-none rounded-lg border border-gray-800 bg-gray-950 px-4 py-3 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors"
              />
              <p className="text-xs text-gray-500 mt-2">
                Press <kbd className="rounded bg-gray-800 px-1.5 py-0.5">Enter</kbd> to send,{' '}
                <kbd className="rounded bg-gray-800 px-1.5 py-0.5">Shift+Enter</kbd> for new line
              </p>
            </div>
            <button
              onClick={handleSend}
              disabled={!input.trim() || isLoading}
              className="rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 p-3 text-white hover:from-cyan-600 hover:to-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              aria-label="Send message"
            >
              {isLoading ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <Send className="h-5 w-5" />
              )}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
