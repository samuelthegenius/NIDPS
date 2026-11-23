/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0a0d14',
          card: '#111726',
          border: '#1e293b',
          input: '#0f172a',
          accent: '#38bdf8',
          danger: '#ef4444',
          warning: '#f59e0b',
          success: '#10b981',
        }
      },
      fontFamily: {
        // System fonts only: the dashboard must work offline on a lab LAN.
        sans: ['system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'Ubuntu', 'sans-serif'],
        mono: ['ui-monospace', 'Cascadia Code', 'Consolas', 'Ubuntu Mono', 'Menlo', 'monospace'],
      }
    },
  },
  plugins: [],
}
