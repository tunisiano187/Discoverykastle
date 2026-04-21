/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          0: "#0d1117",
          1: "#161b22",
          2: "#21262d",
          3: "#30363d",
        },
        brand: "#58a6ff",
      },
    },
  },
  plugins: [],
};
