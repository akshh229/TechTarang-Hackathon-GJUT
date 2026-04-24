/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        panel: "rgb(var(--panel) / <alpha-value>)",
        panelSoft: "rgb(var(--panel-soft) / <alpha-value>)",
        borderGlass: "rgb(var(--border-glass) / <alpha-value>)",
        accent: "rgb(var(--accent) / <alpha-value>)",
        accentAlt: "rgb(var(--accent-alt) / <alpha-value>)",
        danger: "rgb(var(--danger) / <alpha-value>)",
        warning: "rgb(var(--warning) / <alpha-value>)",
        success: "rgb(var(--success) / <alpha-value>)",
        ink: "rgb(var(--ink) / <alpha-value>)",
        muted: "rgb(var(--muted) / <alpha-value>)",
      },
      boxShadow: {
        glass: "0 24px 80px rgba(5, 7, 22, 0.42)",
      },
      backgroundImage: {
        grid: "linear-gradient(rgba(122, 167, 255, 0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(122, 167, 255, 0.08) 1px, transparent 1px)",
      },
      fontFamily: {
        display: ["'Space Grotesk'", "system-ui", "sans-serif"],
        body: ["'IBM Plex Sans'", "system-ui", "sans-serif"],
      },
    },
  },
  plugins: [],
};
