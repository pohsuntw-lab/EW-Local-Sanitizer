import { copyFileSync, mkdirSync } from "node:fs";
import { build } from "esbuild-wasm";

mkdirSync("dist/renderer", { recursive: true });
await build({ entryPoints: ["src/renderer/app.tsx"], outfile: "dist/renderer/app.js", bundle: true, format: "esm",
  platform: "browser", target: "chrome142", sourcemap: true, minify: false, logLevel: "warning" });
copyFileSync("src/renderer/index.html", "dist/renderer/index.html");
copyFileSync("src/renderer/styles.css", "dist/renderer/styles.css");
