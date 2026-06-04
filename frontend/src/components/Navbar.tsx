import { useState, useEffect } from 'react';
import { Shield, Github, Menu, X, ChevronDown } from 'lucide-react';

interface Props {
  onReset?: () => void;
}

export default function Navbar({ onReset }: Props) {
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollTo = (id: string) => {
    setMenuOpen(false);
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <header
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled
          ? 'bg-white/95 backdrop-blur-md shadow-sm border-b border-gray-100'
          : 'bg-transparent'
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <button
            onClick={onReset || (() => scrollTo('hero'))}
            className="flex items-center gap-2.5 group"
            id="nav-logo"
          >
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center shadow-md group-hover:bg-blue-700 transition-colors">
              <Shield size={16} className="text-white" />
            </div>
            <div className="flex flex-col leading-none">
              <span className={`font-bold text-sm tracking-tight transition-colors ${scrolled ? 'text-gray-900' : 'text-white'}`}>
                HybridURL
              </span>
              <span className={`text-[10px] font-medium transition-colors ${scrolled ? 'text-blue-600' : 'text-blue-300'}`}>
                DETECTION SYSTEM
              </span>
            </div>
          </button>

          {/* Desktop Nav */}
          <nav className="hidden md:flex items-center gap-1">
            {[
              { label: 'Features', id: 'features' },
              { label: 'Methodology', id: 'methodology' },
              { label: 'Statistics', id: 'stats' },
            ].map(({ label, id }) => (
              <button
                key={id}
                onClick={() => scrollTo(id)}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-150 ${
                  scrolled
                    ? 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                    : 'text-white/80 hover:text-white hover:bg-white/10'
                }`}
              >
                {label}
              </button>
            ))}
          </nav>

          {/* Right Actions */}
          <div className="hidden md:flex items-center gap-3">
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className={`flex items-center gap-1.5 text-sm font-medium transition-colors ${
                scrolled ? 'text-gray-500 hover:text-gray-900' : 'text-white/70 hover:text-white'
              }`}
              id="nav-github"
            >
              <Github size={16} />
              <span>GitHub</span>
            </a>
            <button
              onClick={() => scrollTo('hero')}
              className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-all duration-150 shadow-sm hover:shadow-md"
              id="nav-scan-btn"
            >
              <Shield size={14} />
              Scan a URL
            </button>
          </div>

          {/* Mobile menu button */}
          <button
            className={`md:hidden p-2 rounded-lg transition-colors ${
              scrolled ? 'text-gray-700 hover:bg-gray-100' : 'text-white hover:bg-white/10'
            }`}
            onClick={() => setMenuOpen(!menuOpen)}
            aria-label="Toggle menu"
          >
            {menuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </div>

      {/* Mobile menu */}
      {menuOpen && (
        <div className="md:hidden bg-white border-b border-gray-100 shadow-lg animate-fade-in">
          <div className="max-w-7xl mx-auto px-4 py-4 space-y-1">
            {[
              { label: 'Features', id: 'features' },
              { label: 'Methodology', id: 'methodology' },
              { label: 'Statistics', id: 'stats' },
            ].map(({ label, id }) => (
              <button
                key={id}
                onClick={() => scrollTo(id)}
                className="w-full text-left px-4 py-2.5 text-sm font-medium text-gray-700 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-all"
              >
                {label}
              </button>
            ))}
            <div className="pt-2 border-t border-gray-100">
              <button
                onClick={() => scrollTo('hero')}
                className="w-full flex items-center justify-center gap-2 bg-blue-600 text-white text-sm font-semibold px-4 py-2.5 rounded-lg"
              >
                <Shield size={14} /> Scan a URL
              </button>
            </div>
          </div>
        </div>
      )}
    </header>
  );
}
