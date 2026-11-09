export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // "Ops room at night" — blue-black chrome; teal = the system acting,
        // violet = the AI analyst speaking, severity colors = data only.
        void:  "#0A0E16",
        panel: "#0E1420",
        raise: "#121A2A",
        line:  "#1C2739",
        signal: { DEFAULT: "#2DD4BF", dim: "#0F3D38" },
        ai:     { DEFAULT: "#A78BFA", dim: "#2E2650" },
        sev: {
          critical: "#F87171",
          high:     "#FB923C",
          medium:   "#FBBF24",
          low:      "#60A5FA",
        },
      },
      fontFamily: {
        display: ["Rajdhani", "sans-serif"],
        sans: ["'IBM Plex Sans'", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "monospace"],
      },
      keyframes: {
        "alert-in": {
          from: { opacity: "0", transform: "translateY(-6px)" },
          to:   { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "alert-in": "alert-in 0.35s ease-out both",
      },
    },
  },
  plugins: [],
}
