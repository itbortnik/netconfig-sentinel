import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/ui/",
  server: {
    proxy: { "/api/v1": "http://127.0.0.1:8000" },
  },
  test: {
    include: ["src/**/*.test.ts"],
    restoreMocks: true,
  },
});
