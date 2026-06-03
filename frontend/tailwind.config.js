/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          primary: '#0d1117',
          secondary: '#161b22',
          card: '#1c2128',
          elevated: '#21262d',
        },
        border: { DEFAULT: '#30363d', subtle: '#21262d' },
        accent: {
          cyan: '#00d2ff',
          green: '#3fb950',
          purple: '#a371f7',
        },
        severity: {
          critical: '#ff4444',
          high: '#ff8c00',
          medium: '#ffd700',
          low: '#00bfff',
          info: '#6e7681',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-fast': 'pulse 0.8s cubic-bezier(0.4,0,0.6,1) infinite',
        'slide-in': 'slideIn 0.3s ease-out',
        'glow': 'glow 2s ease-in-out infinite',
      },
      keyframes: {
        slideIn: { from: { transform: 'translateY(-10px)', opacity: '0' }, to: { transform: 'translateY(0)', opacity: '1' } },
        glow: { '0%,100%': { boxShadow: '0 0 4px #00d2ff44' }, '50%': { boxShadow: '0 0 12px #00d2ff88' } },
      },
    },
  },
  plugins: [],
};
