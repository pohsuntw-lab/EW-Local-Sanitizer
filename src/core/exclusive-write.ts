import { closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";

export interface WrittenFileIdentity {
  readonly device: number;
  readonly inode: number;
  readonly size: number;
}

export function writeExclusiveFile(path: string, data: Buffer | string): WrittenFileIdentity {
  let descriptor: number | undefined;
  let created = false;
  let identity: WrittenFileIdentity | undefined;
  try {
    descriptor = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    created = true;
    const opened = fstatSync(descriptor);
    if (!opened.isFile()) throw new Error("Generated artifact is not a regular file");
    identity = Object.freeze({ device: opened.dev, inode: opened.ino, size: opened.size });
    writeFileSync(descriptor, data);
    fsyncSync(descriptor);
    const written = fstatSync(descriptor);
    if (!written.isFile()) throw new Error("Generated artifact is not a regular file");
    identity = Object.freeze({ device: written.dev, inode: written.ino, size: written.size });
    closeSync(descriptor);
    descriptor = undefined;
    return identity;
  } catch (error) {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch { /* continue cleanup */ }
      descriptor = undefined;
    }
    if (created && identity) removeSameFile(path, identity, false);
    throw error;
  }
}

export function readWrittenFile(path: string, identity: WrittenFileIdentity, maximumBytes: number): Buffer {
  let descriptor: number | undefined;
  try {
    const linked = lstatSync(path);
    if (!linked.isFile() || linked.isSymbolicLink()) throw new Error("Generated artifact path was replaced");
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || opened.dev !== identity.device || opened.ino !== identity.inode || opened.size !== identity.size ||
      opened.size > maximumBytes) {
      throw new Error("Generated artifact identity or size changed");
    }
    const bytes = readFileSync(descriptor);
    if (bytes.length !== identity.size) throw new Error("Generated artifact changed while reading");
    return bytes;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function removeWrittenFile(path: string, identity: WrittenFileIdentity): boolean {
  return removeSameFile(path, identity, true);
}

function removeSameFile(path: string, identity: WrittenFileIdentity, requireSize: boolean): boolean {
  try {
    const linked = lstatSync(path);
    if (!linked.isFile() || linked.isSymbolicLink() || linked.dev !== identity.device || linked.ino !== identity.inode ||
      (requireSize && linked.size !== identity.size)) {
      return false;
    }
    unlinkSync(path);
    return true;
  } catch {
    return false;
  }
}
