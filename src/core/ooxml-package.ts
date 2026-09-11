import { unzipSync } from "fflate";
import { MAX_OOXML_ENTRIES, MAX_OOXML_ENTRY_BYTES, MAX_OOXML_EXPANDED_BYTES } from "./policy.js";

export interface OoxmlPackage {
  readonly entries: ReadonlyMap<string, Buffer>;
}

interface CentralEntry { name: string; compressedSize: number; expandedSize: number; compression: number; localOffset: number; dataStart: number; dataEnd: number }

export function openOoxmlPackage(bytes: Buffer): OoxmlPackage {
  const central = inspectCentralDirectory(bytes);
  const expected = new Map(central.filter((entry) => !entry.name.endsWith("/")).map((entry) => [entry.name, entry]));
  let expanded: ReturnType<typeof unzipSync>;
  try {
    expanded = unzipSync(bytes, { filter: (entry) => expected.has(entry.name) });
  } catch {
    throw new Error("OOXML ZIP decompression failed");
  }
  const entries = new Map<string, Buffer>();
  for (const [name, value] of Object.entries(expanded)) {
    const metadata = expected.get(name);
    if (!metadata || value.length !== metadata.expandedSize) throw new Error("OOXML ZIP entry size mismatch");
    entries.set(name, Buffer.from(value));
  }
  if (entries.size !== expected.size) throw new Error("OOXML ZIP entry set mismatch");
  return Object.freeze({ entries });
}

function inspectCentralDirectory(bytes: Buffer): CentralEntry[] {
  if (bytes.length < 22) throw new Error("OOXML source is not a supported ZIP package");
  const end = bytes.length - 22;
  if (bytes.readUInt32LE(end) !== 0x06054b50 || bytes.readUInt16LE(end + 20) !== 0) {
    throw new Error("OOXML ZIP must have a canonical end record without comments");
  }
  const disk = bytes.readUInt16LE(end + 4);
  const centralDisk = bytes.readUInt16LE(end + 6);
  const diskEntries = bytes.readUInt16LE(end + 8);
  const totalEntries = bytes.readUInt16LE(end + 10);
  const centralSize = bytes.readUInt32LE(end + 12);
  const centralOffset = bytes.readUInt32LE(end + 16);
  if (disk !== 0 || centralDisk !== 0 || diskEntries !== totalEntries || totalEntries > MAX_OOXML_ENTRIES ||
    totalEntries === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff || centralOffset + centralSize !== end) {
    throw new Error("OOXML ZIP uses unsupported spanning, ZIP64 or entry limits");
  }

  const entries: CentralEntry[] = [];
  const names = new Set<string>();
  let expandedTotal = 0;
  let cursor = centralOffset;
  for (let count = 0; count < totalEntries; count += 1) {
    if (cursor + 46 > end || bytes.readUInt32LE(cursor) !== 0x02014b50) throw new Error("OOXML ZIP central directory is malformed");
    const flags = bytes.readUInt16LE(cursor + 8);
    const compression = bytes.readUInt16LE(cursor + 10);
    const compressedSize = bytes.readUInt32LE(cursor + 20);
    const expandedSize = bytes.readUInt32LE(cursor + 24);
    const nameLength = bytes.readUInt16LE(cursor + 28);
    const extraLength = bytes.readUInt16LE(cursor + 30);
    const commentLength = bytes.readUInt16LE(cursor + 32);
    const diskStart = bytes.readUInt16LE(cursor + 34);
    const externalAttributes = bytes.readUInt32LE(cursor + 38);
    const localOffset = bytes.readUInt32LE(cursor + 42);
    const next = cursor + 46 + nameLength + extraLength + commentLength;
    if (next > end || nameLength === 0 || extraLength !== 0 || commentLength !== 0 || diskStart !== 0 || localOffset >= centralOffset) {
      throw new Error("OOXML ZIP contains noncanonical entry metadata");
    }
    if ((flags & 0x1) !== 0) throw new Error("Encrypted OOXML ZIP entries are unsupported");
    const allowedFlags = 0x800 | (compression === 8 ? 0x6 : 0);
    if ((flags & ~allowedFlags) !== 0) throw new Error("OOXML ZIP entry flags are unsupported");
    if (compression !== 0 && compression !== 8) throw new Error("OOXML ZIP compression method is unsupported");
    const nameBytes = bytes.subarray(cursor + 46, cursor + 46 + nameLength);
    const name = decodeName(nameBytes, (flags & 0x800) !== 0);
    validateName(name);
    const folded = name.toLowerCase();
    if (names.has(folded)) throw new Error("OOXML ZIP contains duplicate entry names");
    names.add(folded);
    if (expandedSize > MAX_OOXML_ENTRY_BYTES) throw new Error("OOXML ZIP entry exceeds expanded size policy");
    expandedTotal += expandedSize;
    if (expandedTotal > MAX_OOXML_EXPANDED_BYTES) throw new Error("OOXML ZIP exceeds aggregate expanded size policy");
    const unixMode = externalAttributes >>> 16;
    if ((unixMode & 0o170000) === 0o120000) throw new Error("OOXML ZIP symbolic links are unsupported");
    const local = inspectLocalHeader(bytes, localOffset, name, flags, compression, compressedSize, expandedSize, centralOffset);
    entries.push({ name, compressedSize, expandedSize, compression, localOffset, ...local });
    cursor = next;
  }
  if (cursor !== end) throw new Error("OOXML ZIP central directory has trailing data");
  const ranges = [...entries].sort((left, right) => left.localOffset - right.localOffset);
  if (ranges[0]?.localOffset !== 0 || ranges.at(-1)?.dataEnd !== centralOffset) throw new Error("OOXML ZIP contains unreferenced local data");
  for (let index = 1; index < ranges.length; index += 1) {
    if (ranges[index]!.localOffset !== ranges[index - 1]!.dataEnd) throw new Error("OOXML ZIP local entries overlap or contain hidden gaps");
  }
  return entries;
}

function inspectLocalHeader(bytes: Buffer, offset: number, expectedName: string, flags: number, compression: number,
  compressedSize: number, expandedSize: number, centralOffset: number): { dataStart: number; dataEnd: number } {
  if (offset + 30 > centralOffset || bytes.readUInt32LE(offset) !== 0x04034b50) throw new Error("OOXML ZIP local header is malformed");
  const localFlags = bytes.readUInt16LE(offset + 6);
  const localCompression = bytes.readUInt16LE(offset + 8);
  const localCompressedSize = bytes.readUInt32LE(offset + 18);
  const localExpandedSize = bytes.readUInt32LE(offset + 22);
  const nameLength = bytes.readUInt16LE(offset + 26);
  const extraLength = bytes.readUInt16LE(offset + 28);
  const dataStart = offset + 30 + nameLength + extraLength;
  const dataEnd = dataStart + compressedSize;
  if (extraLength !== 0 || dataEnd > centralOffset || localFlags !== flags || localCompression !== compression ||
    localCompressedSize !== compressedSize || localExpandedSize !== expandedSize) {
    throw new Error("OOXML ZIP local and central metadata differ");
  }
  const localName = decodeName(bytes.subarray(offset + 30, offset + 30 + nameLength), (flags & 0x800) !== 0);
  if (localName !== expectedName) throw new Error("OOXML ZIP local and central entry names differ");
  return { dataStart, dataEnd };
}

function decodeName(bytes: Buffer, utf8: boolean): string {
  if (!utf8 && bytes.some((value) => value > 0x7f)) throw new Error("OOXML ZIP entry name encoding is unsupported");
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("OOXML ZIP entry name is invalid UTF-8");
  }
}

function validateName(name: string): void {
  if (name.includes("\\") || name.includes("\0") || name.startsWith("/") || /^[A-Za-z]:/.test(name)) {
    throw new Error("OOXML ZIP contains an unsafe entry path");
  }
  const parts = name.split("/");
  if (parts.some((part) => part === ".." || part === "." || (part.startsWith(".") && part.length > 1) ||
    new Set(["__proto__", "prototype", "constructor"]).has(part.toLowerCase()))) {
    throw new Error("OOXML ZIP contains an unsafe entry path");
  }
}
