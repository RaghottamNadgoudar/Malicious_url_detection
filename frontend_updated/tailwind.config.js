/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          base:  '#0b0d14',
          card:  '#111420',
          hover: '#161928',
        },
        brand: {
          DEFAULT: '#7c3aed',
          light:   '#a78bfa',
          glow:    'rgba(124,58,237,0.35)',
        },
        safe:       '#22c55e',
        suspicious: '#f59e0b',
        malicious:  '#ef4444',
        border:     'rgba(255,255,255,0.08)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        glass:   '0 4px 24px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.06)',
        glow:    '0 0 20px rgba(124,58,237,0.4)',
        safe:    '0 0 16px rgba(34,197,94,0.3)',
        danger:  '0 0 16px rgba(239,68,68,0.3)',
        warning: '0 0 16px rgba(245,158,11,0.3)',
      },
      backdropBlur: { card: '12px' },
      animation: {
        'fade-in':    'fadeIn 0.4s ease-out',
        'slide-up':   'slideUp 0.5s ease-out',
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        'scan-line':  'scanLine 2s linear infinite',
        'count-up':   'countUp 0.6s ease-out',
      },
      keyframes: {
        fadeIn:   { from: { opacity: '0' }, to: { opacity: '1' } },
        slideUp:  { from: { opacity: '0', transform: 'translateY(20px)' }, to: { opacity: '1', transform: 'translateY(0)' } },
        scanLine: { '0%': { transform: 'translateY(-100%)' }, '100%': { transform: 'translateY(100%)' } },
        countUp:  { from: { transform: 'translateY(8px)', opacity: '0' }, to: { transform: 'translateY(0)', opacity: '1' } },
      },
    },
  },
  plugins: [],
};
