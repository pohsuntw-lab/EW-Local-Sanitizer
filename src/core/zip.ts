import { writeFileSync } from "node:fs";
import { MAX_ZIP_ENTRY_BYTES } from "./policy.js";

export interface ZipEntry { name: string; data: Buffer }
export interface InspectedZipEntry { name: string; size: number; data: Buffer }

export function writeStoreZip(path: string, entries: readonly ZipEntry[]): void {
  const names = new Set<string>();
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    validateEntry(entry.name, entry.data.length);
    if (names.has(entry.name)) throw new Error(`Duplicate ZIP entry: ${entry.name}`);
    names.add(entry.name);
    const name = Buffer.from(entry.name, "utf8");
    const crc = crc32(entry.data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(0, 8); local.writeUInt32LE(0, 10); local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(entry.data.length, 18); local.writeUInt32LE(entry.data.length, 22);
    local.writeUInt16LE(name.length, 26); local.writeUInt16LE(0, 28);
    localParts.push(local, name, entry.data);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8); central.writeUInt16LE(0, 10); central.writeUInt32LE(0, 12);
    central.writeUInt32LE(crc, 16); central.writeUInt32LE(entry.data.length, 20); central.writeUInt32LE(entry.data.length, 24);
    central.writeUInt16LE(name.length, 28); central.writeUInt32LE(0, 38); central.writeUInt32LE(offset, 42);
    centralParts.push(central, name);
    offset += local.length + name.length + entry.data.length;
  }
  if (entries.length > 65_535) throw new Error("Too many ZIP entries");
  const centralData = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralData.length, 12); end.writeUInt32LE(offset, 16);
  writeFileSync(path, Buffer.concat([...localParts, centralData, end]), { flag: "wx", mode: 0o600 });
}

export function inspectStoreZip(buffer: Buffer, allowlist: ReadonlySet<string>): InspectedZipEntry[] {
  const endOffset = findEndRecord(buffer);
  const diskNumber = readUInt16(buffer, endOffset + 4);
  const centralDisk = readUInt16(buffer, endOffset + 6);
  const diskCount = readUInt16(buffer, endOffset + 8);
  const count = readUInt16(buffer, endOffset + 10);
  const centralSize = readUInt32(buffer, endOffset + 12);
  const centralOffset = readUInt32(buffer, endOffset + 16);
  const commentLength = readUInt16(buffer, endOffset + 20);
  if (diskNumber !== 0 || centralDisk !== 0 || diskCount !== count) throw new Error("Multi-disk ZIP is unsupported");
  if (commentLength !== 0 || endOffset + 22 !== buffer.length) throw new Error("ZIP contains a comment, trailing or malformed data");
  if (centralOffset + centralSize !== endOffset) throw new Error("Invalid ZIP central directory bounds");
  const localEntries: Array<InspectedZipEntry & { offset: number }> = [];
  const localNames = new Set<string>();
  let offset = 0;
  while (offset < centralOffset) {
    const localOffset = offset;
    requireSignature(buffer, offset, 0x04034b50, "local header");
    const flags = readUInt16(buffer, offset + 6);
    const method = readUInt16(buffer, offset + 8);
    const compressedSize = readUInt32(buffer, offset + 18);
    const size = readUInt32(buffer, offset + 22);
    const expectedCrc = readUInt32(buffer, offset + 14);
    const nameLength = readUInt16(buffer, offset + 26);
    const extraLength = readUInt16(buffer, offset + 28);
    if (flags !== 0x0800 || method !== 0 || compressedSize !== size || extraLength !== 0) throw new Error("Unsupported ZIP encoding, compression or hidden extra data");
    const nameStart = offset + 30;
    const dataStart = nameStart + nameLength + extraLength;
    const dataEnd = dataStart + size;
    if (dataEnd > centralOffset) throw new Error("ZIP entry exceeds local data bounds");
    const name = decodeZipName(buffer.subarray(nameStart, nameStart + nameLength));
    validateAllowedEntry(name, size, allowlist, localNames);
    const data = buffer.subarray(dataStart, dataEnd);
    if (crc32(data) !== expectedCrc) throw new Error(`ZIP CRC mismatch: ${name}`);
    localEntries.push({ name, size, data, offset: localOffset });
    offset = dataEnd;
  }
  if (offset !== centralOffset || localEntries.length !== count) throw new Error("ZIP entry count mismatch");

  const centralNames = new Set<string>();
  let centralCursor = centralOffset;
  for (let index = 0; index < count; index += 1) {
    requireSignature(buffer, centralCursor, 0x02014b50, "central header");
    const flags = readUInt16(buffer, centralCursor + 8);
    const method = readUInt16(buffer, centralCursor + 10);
    const expectedCrc = readUInt32(buffer, centralCursor + 16);
    const compressedSize = readUInt32(buffer, centralCursor + 20);
    const size = readUInt32(buffer, centralCursor + 24);
    const nameLength = readUInt16(buffer, centralCursor + 28);
    const extraLength = readUInt16(buffer, centralCursor + 30);
    const commentLength = readUInt16(buffer, centralCursor + 32);
    const diskStart = readUInt16(buffer, centralCursor + 34);
    const localOffset = readUInt32(buffer, centralCursor + 42);
    const nameStart = centralCursor + 46;
    const next = nameStart + nameLength + extraLength + commentLength;
    if (next > endOffset) throw new Error("ZIP central entry exceeds bounds");
    const name = decodeZipName(buffer.subarray(nameStart, nameStart + nameLength));
    if (flags !== 0x0800 || method !== 0 || compressedSize !== size || extraLength !== 0 || commentLength !== 0 || diskStart !== 0) {
      throw new Error("Unsupported central ZIP encoding, compression or hidden data");
    }
    validateAllowedEntry(name, size, allowlist, centralNames);
    const local = localEntries[index];
    if (!local || local.name !== name || local.size !== size || local.offset !== localOffset || crc32(local.data) !== expectedCrc) throw new Error("ZIP local and central entries disagree");
    centralCursor = next;
  }
  if (centralCursor !== endOffset || localNames.size !== allowlist.size || [...allowlist].some((name) => !localNames.has(name))) {
    throw new Error("ZIP allowlist mismatch");
  }
  return localEntries.map(({ name, size, data }) => ({ name, size, data }));
}

function validateAllowedEntry(name: string, size: number, allowlist: ReadonlySet<string>, seen: Set<string>): void {
  validateEntry(name, size);
  if (!allowlist.has(name)) throw new Error(`Non-allowlisted ZIP entry: ${name}`);
  if (seen.has(name)) throw new Error(`Duplicate ZIP entry: ${name}`);
  seen.add(name);
}

function validateEntry(name: string, size: number): void {
  const segments = name.split("/");
  if (!name || name.startsWith("/") || /^[A-Za-z]:/.test(name) || name.includes("\\") || /[\u0000-\u001f\u007f]/u.test(name) ||
    segments.includes("..") || segments.some((segment) => !segment || segment.startsWith("."))) {
    throw new Error(`Unsafe ZIP entry: ${name}`);
  }
  if (size < 0 || size > MAX_ZIP_ENTRY_BYTES) throw new Error(`ZIP entry exceeds size policy: ${name}`);
}

function decodeZipName(value: Buffer): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  } catch {
    throw new Error("ZIP entry name is not valid UTF-8");
  }
}

function findEndRecord(buffer: Buffer): number {
  const minimum = Math.max(0, buffer.length - 65_557);
  for (let offset = buffer.length - 22; offset >= minimum; offset -= 1) if (buffer.readUInt32LE(offset) === 0x06054b50) return offset;
  throw new Error("ZIP end record not found");
}

function requireSignature(buffer: Buffer, offset: number, signature: number, label: string): void {
  if (offset < 0 || offset + 4 > buffer.length || buffer.readUInt32LE(offset) !== signature) throw new Error(`Invalid ZIP ${label}`);
}

function readUInt16(buffer: Buffer, offset: number): number {
  if (offset < 0 || offset + 2 > buffer.length) throw new Error("Truncated ZIP");
  return buffer.readUInt16LE(offset);
}

function readUInt32(buffer: Buffer, offset: number): number {
  if (offset < 0 || offset + 4 > buffer.length) throw new Error("Truncated ZIP");
  return buffer.readUInt32LE(offset);
}

function crc32(data: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}
