import { Link, useLocation } from 'react-router-dom';
import { Shield, Layers, Search, Activity } from 'lucide-react';

const navLinks = [
  { to: '/',          label: 'Home',         icon: Shield },
  { to: '/pipeline1', label: 'Batch DAA',    icon: Layers },
  { to: '/pipeline2', label: 'Deep Scan',    icon: Search },
];

export default function Navbar() {
  const { pathname } = useLocation();

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 h-16 border-b border-white/[0.07]"
         style={{ background: 'rgba(11,13,20,0.85)', backdropFilter: 'blur(16px)' }}>
      <div className="max-w-7xl mx-auto px-6 h-full flex items-center justify-between">
        {/* Logo */}
        <Link to="/" className="flex items-center gap-2.5 group">
          <div className="w-8 h-8 rounded-lg bg-brand/20 border border-brand/30 flex items-center justify-center
                          group-hover:bg-brand/30 transition-all duration-200">
            <Shield size={16} className="text-brand-light" />
          </div>
          <div>
            <span className="text-sm font-semibold text-white">DAA</span>
            <span className="text-sm font-semibold text-brand-light"> Shield</span>
          </div>
          <span className="hidden sm:block text-[10px] text-white/30 font-mono ml-1 border border-white/10 rounded px-1.5 py-0.5">
            DISTILBERT
          </span>
        </Link>

        {/* Nav links */}
        <div className="flex items-center gap-1">
          {navLinks.map(({ to, label, icon: Icon }) => {
            const active = pathname === to;
            return (
              <Link
                key={to}
                to={to}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium
                            transition-all duration-200 ${
                  active
                    ? 'bg-brand/20 text-brand-light border border-brand/30'
                    : 'text-white/50 hover:text-white hover:bg-white/[0.06]'
                }`}
              >
                <Icon size={14} />
                <span className="hidden sm:block">{label}</span>
              </Link>
            );
          })}
        </div>

        {/* Status pill */}
        <div className="flex items-center gap-2 text-[11px] text-white/40">
          <Activity size={12} className="text-safe" />
          <span className="hidden md:block">port 8002</span>
        </div>
      </div>
    </nav>
  );
}
