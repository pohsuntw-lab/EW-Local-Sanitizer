import { closeSync, constants, fsyncSync, openSync, unlinkSync, writeFileSync } from "node:fs";

export function writeExclusiveFile(path: string, data: Buffer | string): void {
  let descriptor: number | undefined;
  let created = false;
  try {
    descriptor = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    created = true;
    writeFileSync(descriptor, data);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
  } catch (error) {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch { /* continue cleanup */ }
      descriptor = undefined;
    }
    if (created) {
      try { unlinkSync(path); } catch { /* best-effort cleanup after a file created by this call */ }
    }
    throw error;
  }
}
