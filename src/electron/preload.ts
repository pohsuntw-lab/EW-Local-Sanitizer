import { contextBridge, ipcRenderer } from "electron";
import type { EwDesktopApi, ExportOptions, ExportResult, ScanOptions, ScanResponse } from "../ui/contracts.js";

const api: EwDesktopApi = Object.freeze({
  pickAndScan: (options: ScanOptions): Promise<ScanResponse> => ipcRenderer.invoke("ew:pick-and-scan", options),
  exportReviewed: (options: ExportOptions): Promise<ExportResult> => ipcRenderer.invoke("ew:export-reviewed", options),
  closeSession: (): Promise<void> => ipcRenderer.invoke("ew:close-session"),
});

contextBridge.exposeInMainWorld("ewDesktop", api);
