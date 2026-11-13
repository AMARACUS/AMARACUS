/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        background: '#F8F7F4',
        surface: '#FFFFFF',
        border: '#E9EDE7',
        forest: {
          DEFAULT: '#008031',
          hover: '#006827',
          dark: '#00521F',
          sidebar: '#008631',
          subtle: '#EAF3EC',
          border: '#C8E0CF',
        },
        amaracus: {
          text: '#1A1A1A',
          muted: '#636863',
          light: '#8C928C',
          subtle: '#F0EFEA',
        }
      },
      fontFamily: {
        serif: ['var(--font-newsreader)', 'Georgia', 'Cambria', '"Times New Roman"', 'Times', 'serif'],
        sans: ['var(--font-inter)', 'system-ui', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
        mono: ['var(--font-mono)', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      boxShadow: {
        soft: '0 1px 3px rgba(0,0,0,0.03), 0 1px 2px rgba(0,0,0,0.02)',
        card: '0 2px 6px -1px rgba(0, 0, 0, 0.04), 0 1px 4px -1px rgba(0, 0, 0, 0.02)',
      }
    },
  },
  plugins: [],
};
