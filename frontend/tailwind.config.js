/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#E6F1FB',
          100: '#B5D4F4',
          500: '#185FA5',
          600: '#0C447C',
          700: '#042C53',
        },
        success: {
          50: '#EAF3DE',
          500: '#3B6D11',
          600: '#27500A',
        },
        warning: {
          50: '#FAEEDA',
          500: '#854F0B',
          600: '#633806',
        },
        danger: {
          50: '#FCEBEB',
          500: '#A32D2D',
          600: '#791F1F',
        }
      }
    },
  },
  plugins: [],
}
