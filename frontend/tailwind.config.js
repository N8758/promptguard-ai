/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Instrument Sans"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      colors: {
        paper: '#EDF0F3',
        ink: { DEFAULT: '#0E1A2B', soft: '#44546A', mute: '#7A8799' },
        line: '#D5DBE3',
        block: { DEFAULT: '#C8321F', bg: '#FBEAE7' },
        allow: { DEFAULT: '#0F7B66', bg: '#E4F4F0' },
        sanitize: { DEFAULT: '#A8650B', bg: '#FBF0DC' },
      },
    },
  },
  plugins: [],
}
