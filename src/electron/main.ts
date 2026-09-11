import { app, BrowserWindow, dialog, ipcMain, session } from "electron";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { LocalSessionService } from "./session-service.js";
import type { ExportOptions, ExportResult, ScanOptions, ScanResponse } from "../ui/contracts.js";

const currentDirectory = dirname(fileURLToPath(import.meta.url));
const service = new LocalSessionService();
app.setName("EW Local Sanitizer");

app.whenReady().then(() => {
  hardenSession();
  registerIpc();
  createWindow();
});

app.on("window-all-closed", () => { service.close(); app.quit(); });
app.on("before-quit", () => service.close());

function createWindow(): void {
  const window = new BrowserWindow({
    width: 1180, height: 820, minWidth: 900, minHeight: 650, backgroundColor: "#07120f", show: false,
    webPreferences: { preload: join(currentDirectory, "preload.js"), contextIsolation: true, nodeIntegration: false,
      sandbox: true, webSecurity: true, allowRunningInsecureContent: false, devTools: !app.isPackaged },
  });
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.webContents.on("will-navigate", (event) => event.preventDefault());
  window.webContents.on("render-process-gone", () => service.close());
  window.on("closed", () => service.close());
  void window.loadFile(join(currentDirectory, "../renderer/index.html"));
  window.once("ready-to-show", () => window.show());
}

function hardenSession(): void {
  session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
    const protocol = new URL(details.url).protocol;
    callback({ cancel: protocol !== "file:" && protocol !== "devtools:" });
  });
}

function registerIpc(): void {
  ipcMain.handle("ew:pick-and-scan", async (_event, options: ScanOptions): Promise<ScanResponse> => {
    if (!validScanOptions(options)) return { status: "error", code: "INVALID_REQUEST" };
    const selected = await dialog.showOpenDialog({ properties: ["openFile", "multiSelections"], filters: [{ name: "Supported documents", extensions: ["txt", "md", "markdown", "csv", "tsv", "docx", "xlsx", "pptx", "pdf", "png", "jpg", "jpeg"] }] });
    if (selected.canceled || selected.filePaths.length === 0) return { status: "cancelled" };
    try { return await service.scanPaths(selected.filePaths, options); }
    catch { return { status: "error", code: "PROCESSING_FAILED" }; }
  });

  ipcMain.handle("ew:export-reviewed", async (_event, options: ExportOptions): Promise<ExportResult> => {
    if (!validExportOptions(options)) return { status: "error", code: "INVALID_REQUEST" };
    const packageChoice = await dialog.showSaveDialog({ defaultPath: "EW-SAFE-PACKAGE.zip", filters: [{ name: "EW Safe Package", extensions: ["zip"] }] });
    if (packageChoice.canceled || !packageChoice.filePath) return { status: "cancelled" };
    let tokenMapPath: string | undefined;
    if (service.needsTokenMap(options.decisions)) {
      const mapChoice = await dialog.showSaveDialog({ defaultPath: "EW-project.ewmap", filters: [{ name: "Encrypted EW token map", extensions: ["ewmap"] }] });
      if (mapChoice.canceled || !mapChoice.filePath) return { status: "cancelled" };
      tokenMapPath = mapChoice.filePath;
    }
    return service.export(options, packageChoice.filePath, tokenMapPath);
  });
  ipcMain.handle("ew:close-session", () => service.close());
}

function validScanOptions(value: ScanOptions): boolean {
  return Boolean(value && Array.isArray(value.dictionaryTerms) && value.dictionaryTerms.length <= 5_000 &&
    value.dictionaryTerms.every((term) => typeof term === "string") && typeof value.latinCaseSensitive === "boolean" &&
    typeof value.approveAllVisibleWorksheets === "boolean" && (value.ocrLanguage === "eng" || value.ocrLanguage === "chi_tra"));
}

function validExportOptions(value: ExportOptions): boolean {
  return Boolean(value && typeof value.sessionId === "string" && Array.isArray(value.decisions) && value.decisions.length <= 50_000 &&
    new Set(["P0", "P1", "P2", "P3"]).has(value.classification) && new Set(["cloud-approved", "cloud-sanitized", "local-only"]).has(value.allowedRoute) &&
    typeof value.p2Confirmed === "boolean" && (value.tokenMapPassphrase === undefined || typeof value.tokenMapPassphrase === "string"));
}
