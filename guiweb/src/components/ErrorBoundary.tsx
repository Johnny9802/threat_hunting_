import { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      error,
      errorInfo: null,
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    this.setState({
      error,
      errorInfo,
    });
  }

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
  };

  handleGoHome = () => {
    window.location.href = '/';
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
          <div className="max-w-2xl w-full">
            <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-8">
              <div className="flex items-start gap-4">
                <div className="rounded-lg bg-red-500/10 p-3 border border-red-500/20">
                  <AlertTriangle className="h-8 w-8 text-red-500" />
                </div>
                <div className="flex-1">
                  <h1 className="text-2xl font-bold text-red-400 mb-2">
                    Something went wrong
                  </h1>
                  <p className="text-red-300/80 mb-4">
                    An unexpected error occurred while rendering this component.
                    Please try refreshing the page or return to the home page.
                  </p>

                  {/* Error Details */}
                  {this.state.error && (
                    <details className="mb-6 rounded-lg bg-gray-900 border border-gray-800 p-4">
                      <summary className="cursor-pointer text-sm font-medium text-gray-300 hover:text-gray-100 transition-colors">
                        Technical details
                      </summary>
                      <div className="mt-3 space-y-2">
                        <div>
                          <p className="text-xs font-semibold text-gray-400 mb-1">
                            Error:
                          </p>
                          <pre className="text-xs text-red-400 bg-gray-950 p-3 rounded overflow-x-auto">
                            {this.state.error.toString()}
                          </pre>
                        </div>
                        {this.state.errorInfo && (
                          <div>
                            <p className="text-xs font-semibold text-gray-400 mb-1">
                              Component Stack:
                            </p>
                            <pre className="text-xs text-gray-400 bg-gray-950 p-3 rounded overflow-x-auto max-h-48 overflow-y-auto">
                              {this.state.errorInfo.componentStack}
                            </pre>
                          </div>
                        )}
                      </div>
                    </details>
                  )}

                  {/* Action Buttons */}
                  <div className="flex flex-wrap gap-3">
                    <button
                      onClick={this.handleReset}
                      className="inline-flex items-center gap-2 rounded-lg bg-red-500/20 px-4 py-2.5 text-sm font-medium text-red-400 hover:bg-red-500/30 transition-colors"
                    >
                      <RefreshCw size={16} />
                      Try again
                    </button>
                    <button
                      onClick={this.handleGoHome}
                      className="inline-flex items-center gap-2 rounded-lg bg-gray-800 px-4 py-2.5 text-sm font-medium text-gray-300 hover:bg-gray-700 transition-colors"
                    >
                      <Home size={16} />
                      Go to home
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Additional Help */}
            <div className="mt-6 rounded-lg border border-gray-800 bg-gray-900 p-4">
              <h2 className="text-sm font-semibold text-gray-300 mb-2">
                Need help?
              </h2>
              <ul className="text-sm text-gray-400 space-y-1">
                <li>Check your browser console for more details</li>
                <li>Try clearing your browser cache and cookies</li>
                <li>Make sure your internet connection is stable</li>
                <li>Contact support if the problem persists</li>
              </ul>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
