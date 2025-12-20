import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, X, Loader2, Shield, FileCode, AlertCircle } from 'lucide-react';
import { usePlaybooks } from '../hooks/usePlaybooks';
import { cn, getSeverityBadgeColor } from '../lib/utils';
import type { Playbook } from '../types/playbook';

interface SearchModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function SearchModal({ isOpen, onClose }: SearchModalProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [filteredResults, setFilteredResults] = useState<Playbook[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const navigate = useNavigate();

  const { data: playbooks, isLoading } = usePlaybooks();

  // Filter playbooks based on search query
  useEffect(() => {
    if (!searchQuery.trim() || !playbooks) {
      setFilteredResults([]);
      setSelectedIndex(0);
      return;
    }

    const query = searchQuery.toLowerCase();
    const filtered = playbooks.filter((pb) => {
      return (
        pb.name.toLowerCase().includes(query) ||
        pb.description.toLowerCase().includes(query) ||
        pb.mitre?.technique?.toLowerCase().includes(query) ||
        pb.mitre?.tactic?.toLowerCase().includes(query) ||
        pb.tags?.some((tag) => tag.toLowerCase().includes(query)) ||
        pb.id.toLowerCase().includes(query)
      );
    }).slice(0, 10); // Limit to 10 results

    setFilteredResults(filtered);
    setSelectedIndex(0);
  }, [searchQuery, playbooks]);

  // Handle keyboard navigation
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (!isOpen) return;

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelectedIndex((prev) =>
          prev < filteredResults.length - 1 ? prev + 1 : prev
        );
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedIndex((prev) => (prev > 0 ? prev - 1 : 0));
        break;
      case 'Enter':
        e.preventDefault();
        if (filteredResults[selectedIndex]) {
          navigate(`/playbook/${filteredResults[selectedIndex].id}`);
          onClose();
        }
        break;
      case 'Escape':
        e.preventDefault();
        onClose();
        break;
    }
  }, [isOpen, filteredResults, selectedIndex, navigate, onClose]);

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  // Reset on open/close
  useEffect(() => {
    if (!isOpen) {
      setSearchQuery('');
      setFilteredResults([]);
      setSelectedIndex(0);
    }
  }, [isOpen]);

  const handleResultClick = (playbookId: string) => {
    navigate(`/playbook/${playbookId}`);
    onClose();
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

      {/* Modal */}
      <div className="fixed inset-x-0 top-20 z-50 mx-auto max-w-2xl px-4">
        <div className="rounded-lg border border-gray-800 bg-gray-900 shadow-2xl">
          {/* Search Input */}
          <div className="flex items-center border-b border-gray-800 px-4">
            <Search className="h-5 w-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search playbooks by name, technique, tactic, or tag..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="flex-1 bg-transparent px-4 py-4 text-gray-100 placeholder-gray-500 focus:outline-none"
              autoFocus
            />
            {isLoading && <Loader2 className="h-5 w-5 animate-spin text-cyan-500" />}
            <button
              onClick={onClose}
              className="rounded-md p-2 text-gray-400 hover:bg-gray-800 hover:text-gray-100 transition-colors"
              aria-label="Close search"
            >
              <X size={20} />
            </button>
          </div>

          {/* Results */}
          <div className="max-h-96 overflow-y-auto">
            {searchQuery && filteredResults.length === 0 && !isLoading && (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <AlertCircle className="h-10 w-10 text-gray-600 mb-3" />
                <p className="text-gray-400">No playbooks found for "{searchQuery}"</p>
                <p className="text-sm text-gray-500 mt-1">Try a different search term</p>
              </div>
            )}

            {!searchQuery && (
              <div className="py-12 text-center">
                <Search className="h-10 w-10 text-gray-600 mx-auto mb-3" />
                <p className="text-gray-400">Start typing to search playbooks</p>
                <p className="text-sm text-gray-500 mt-1">Search by name, technique, tactic, or tag</p>
              </div>
            )}

            {filteredResults.length > 0 && (
              <div className="py-2">
                {filteredResults.map((playbook, index) => (
                  <button
                    key={playbook.id}
                    onClick={() => handleResultClick(playbook.id)}
                    className={cn(
                      'flex w-full items-start gap-3 px-4 py-3 text-left transition-colors',
                      index === selectedIndex
                        ? 'bg-cyan-500/10 border-l-2 border-cyan-500'
                        : 'hover:bg-gray-800/50 border-l-2 border-transparent'
                    )}
                  >
                    <Shield
                      className={cn(
                        'h-5 w-5 flex-shrink-0 mt-0.5',
                        index === selectedIndex ? 'text-cyan-400' : 'text-gray-500'
                      )}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <p className="font-medium text-gray-100 truncate">
                          {playbook.name}
                        </p>
                        <span
                          className={cn(
                            'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold flex-shrink-0',
                            getSeverityBadgeColor(playbook.severity)
                          )}
                        >
                          {playbook.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-sm text-gray-400 line-clamp-1">
                        {playbook.description}
                      </p>
                      {playbook.mitre?.technique && (
                        <div className="flex items-center gap-2 mt-1">
                          <FileCode size={12} className="text-gray-600" />
                          <code className="text-xs text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">
                            {playbook.mitre.technique}
                          </code>
                          {playbook.mitre.tactic && (
                            <span className="text-xs text-gray-600">
                              {playbook.mitre.tactic}
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="border-t border-gray-800 bg-gray-900/50 px-4 py-2">
            <div className="flex items-center justify-between text-xs text-gray-500">
              <div className="flex items-center gap-4">
                <span>
                  <kbd className="rounded bg-gray-800 px-1.5 py-0.5">↑↓</kbd> Navigate
                </span>
                <span>
                  <kbd className="rounded bg-gray-800 px-1.5 py-0.5">Enter</kbd> Select
                </span>
                <span>
                  <kbd className="rounded bg-gray-800 px-1.5 py-0.5">Esc</kbd> Close
                </span>
              </div>
              {filteredResults.length > 0 && (
                <span>{filteredResults.length} result{filteredResults.length !== 1 ? 's' : ''}</span>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
