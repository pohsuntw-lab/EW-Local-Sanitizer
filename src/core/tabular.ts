import { MAX_TABULAR_CELL_CHARS, MAX_TABULAR_CELLS, MAX_TABULAR_COLUMNS, MAX_TABULAR_ROWS } from "./policy.js";

export interface TabularCell {
  readonly value: string;
  readonly valueStarts: readonly number[];
  readonly valueEnds: readonly number[];
}

export interface TabularDocument {
  readonly format: "csv" | "tsv";
  readonly rows: readonly (readonly TabularCell[])[];
}

export function parseTabularText(text: string, format: "csv" | "tsv"): TabularDocument {
  const delimiter = format === "csv" ? "," : "\t";
  const rows: TabularCell[][] = [];
  let row: TabularCell[] = [];
  let index = 0;
  let cells = 0;

  const pushCell = (cell: TabularCell): void => {
    if (cell.value.length > MAX_TABULAR_CELL_CHARS) throw new Error("Tabular cell exceeds character policy limit");
    row.push(Object.freeze(cell));
    cells += 1;
    if (row.length > MAX_TABULAR_COLUMNS) throw new Error("Tabular source exceeds column policy limit");
    if (cells > MAX_TABULAR_CELLS) throw new Error("Tabular source exceeds cell policy limit");
  };
  const pushRow = (): void => {
    rows.push(row);
    row = [];
    if (rows.length > MAX_TABULAR_ROWS) throw new Error("Tabular source exceeds row policy limit");
  };

  while (index < text.length) {
    const value: string[] = [];
    const starts: number[] = [];
    const ends: number[] = [];
    if (text[index] === '"') {
      index += 1;
      let closed = false;
      while (index < text.length) {
        if (text[index] === '"') {
          if (text[index + 1] === '"') {
            value.push('"'); starts.push(index); ends.push(index + 2); index += 2; continue;
          }
          index += 1; closed = true; break;
        }
        if (text[index] === "\r" && text[index + 1] !== "\n") throw new Error("Tabular source contains a lone carriage return");
        const width = text.codePointAt(index)! > 0xffff ? 2 : 1;
        value.push(text.slice(index, index + width));
        for (let unit = 0; unit < width; unit += 1) { starts.push(index); ends.push(index + width); }
        index += width;
      }
      if (!closed) throw new Error("Tabular source has an unterminated quoted field");
      if (index < text.length && text[index] !== delimiter && text[index] !== "\n" && text[index] !== "\r") {
        throw new Error("Tabular source has characters after a closing quote");
      }
    } else {
      while (index < text.length && text[index] !== delimiter && text[index] !== "\n" && text[index] !== "\r") {
        if (text[index] === '"') throw new Error("Tabular source has a quote inside an unquoted field");
        const width = text.codePointAt(index)! > 0xffff ? 2 : 1;
        value.push(text.slice(index, index + width));
        for (let unit = 0; unit < width; unit += 1) { starts.push(index); ends.push(index + width); }
        index += width;
      }
    }
    pushCell({ value: value.join(""), valueStarts: Object.freeze(starts), valueEnds: Object.freeze(ends) });
    if (index >= text.length) { pushRow(); break; }
    if (text[index] === delimiter) { index += 1; if (index === text.length) { pushCell({ value: "", valueStarts: [], valueEnds: [] }); pushRow(); } continue; }
    if (text[index] === "\r") { if (text[index + 1] !== "\n") throw new Error("Tabular source contains a lone carriage return"); index += 2; }
    else index += 1;
    pushRow();
    if (index === text.length) break;
  }
  if (text.length === 0) throw new Error("Tabular source must not be empty");
  if (rows.length === 0) pushRow();
  const columns = rows[0]?.length ?? 0;
  if (columns === 0 || rows.some((candidate) => candidate.length !== columns)) throw new Error("Tabular source has inconsistent column counts");
  return Object.freeze({ format, rows: Object.freeze(rows.map((candidate) => Object.freeze(candidate))) });
}
