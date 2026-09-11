import { strToU8, zipSync } from "fflate";

type FixtureEntries = Record<string, string | Uint8Array>;

export function docxFixture(extra: FixtureEntries = {}): Buffer {
  return officeZip({
    "[Content_Types].xml": contentTypes("/word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
    "word/document.xml": xml(`<w:document xmlns:w="urn:w"><w:body><w:p><w:r><w:t>Visible contact visible.person@example.com</w:t></w:r></w:p><w:tbl><w:tr><w:tc><w:p><w:r><w:t>Example Foundry table</w:t></w:r></w:p></w:tc></w:tr></w:tbl><w:del><w:r><w:t>deleted.person@example.com</w:t></w:r></w:del></w:body></w:document>`),
    "word/header1.xml": xml(`<w:hdr xmlns:w="urn:w"><w:p><w:r><w:t>Header 0912-345-678</w:t></w:r></w:p></w:hdr>`),
    "word/footer1.xml": xml(`<w:ftr xmlns:w="urn:w"><w:p><w:r><w:t>Controlled footer</w:t></w:r></w:p></w:ftr>`),
    "word/comments.xml": xml(`<w:comments xmlns:w="urn:w"><w:comment><w:p><w:r><w:t>comment.person@example.com</w:t></w:r></w:p></w:comment></w:comments>`),
    "word/_rels/document.xml.rels": relationships(`<Relationship Id="rIdExternal" Target="mailto:synthetic@example.invalid" TargetMode="External"/>`),
    "docProps/core.xml": xml(`<cp:coreProperties xmlns:cp="urn:cp"><cp:creator>Synthetic Author</cp:creator></cp:coreProperties>`),
    ...extra,
  });
}

export function xlsxFixture(extra: FixtureEntries = {}): Buffer {
  return officeZip({
    "[Content_Types].xml": contentTypes("/xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"),
    "xl/workbook.xml": xml(`<workbook xmlns="urn:x" xmlns:r="urn:r"><sheets><sheet name="Visible Synthetic" sheetId="1" r:id="rId1"/><sheet name="Hidden Synthetic" sheetId="2" state="hidden" r:id="rId2"/></sheets></workbook>`),
    "xl/_rels/workbook.xml.rels": relationships(`<Relationship Id="rId1" Type="urn:worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="urn:worksheet" Target="worksheets/sheet2.xml"/>`),
    "xl/sharedStrings.xml": xml(`<sst xmlns="urn:x"><si><t>sheet.person@example.com</t></si></sst>`),
    "xl/worksheets/sheet1.xml": xml(`<worksheet xmlns="urn:x"><cols><col min="3" max="3" hidden="1"/></cols><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1"><f>SUM(1,2)</f><v>3</v></c><c r="C1" t="inlineStr"><is><t>hidden.column@example.com</t></is></c></row><row r="2" hidden="1"><c r="A2" t="inlineStr"><is><t>hidden.row@example.com</t></is></c></row></sheetData></worksheet>`),
    "xl/worksheets/sheet2.xml": xml(`<worksheet xmlns="urn:x"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>hidden.sheet@example.com</t></is></c></row></sheetData></worksheet>`),
    "xl/comments1.xml": xml(`<comments xmlns="urn:x"><commentList><comment><text><t>comment.sheet@example.com</t></text></comment></commentList></comments>`),
    "xl/worksheets/_rels/sheet1.xml.rels": relationships(`<Relationship Id="rIdExternal" Target="mailto:sheet@example.invalid" TargetMode="External"/>`),
    "docProps/core.xml": xml(`<cp:coreProperties xmlns:cp="urn:cp"><cp:creator>Synthetic Author</cp:creator></cp:coreProperties>`),
    ...extra,
  });
}

export function pptxFixture(extra: FixtureEntries = {}): Buffer {
  return officeZip({
    "[Content_Types].xml": contentTypes("/ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"),
    "ppt/presentation.xml": xml(`<p:presentation xmlns:p="urn:p" xmlns:r="urn:r"><p:sldIdLst><p:sldId id="1" r:id="rId1"/><p:sldId id="2" r:id="rId2"/></p:sldIdLst></p:presentation>`),
    "ppt/_rels/presentation.xml.rels": relationships(`<Relationship Id="rId1" Type="urn:slide" Target="slides/slide1.xml"/><Relationship Id="rId2" Type="urn:slide" Target="slides/slide2.xml"/>`),
    "ppt/slides/slide1.xml": xml(`<p:sld xmlns:p="urn:p" xmlns:a="urn:a"><p:cSld><a:t>Visible slide.person@example.com</a:t><a:t>Slide body</a:t></p:cSld></p:sld>`),
    "ppt/slides/slide2.xml": xml(`<p:sld xmlns:p="urn:p" xmlns:a="urn:a" show="0"><p:cSld><a:t>hidden.slide@example.com</a:t></p:cSld></p:sld>`),
    "ppt/notesSlides/notesSlide1.xml": xml(`<p:notes xmlns:p="urn:p" xmlns:a="urn:a"><a:t>speaker.notes@example.com</a:t></p:notes>`),
    "ppt/comments/comment1.xml": xml(`<p:cmLst xmlns:p="urn:p" xmlns:a="urn:a"><p:cm><a:t>comment.slide@example.com</a:t></p:cm></p:cmLst>`),
    "ppt/slides/_rels/slide1.xml.rels": relationships(`<Relationship Id="rIdExternal" Target="mailto:slide@example.invalid" TargetMode="External"/>`),
    "docProps/core.xml": xml(`<cp:coreProperties xmlns:cp="urn:cp"><cp:creator>Synthetic Author</cp:creator></cp:coreProperties>`),
    ...extra,
  });
}

export function officeZip(entries: FixtureEntries): Buffer {
  return Buffer.from(zipSync(Object.fromEntries(Object.entries(entries).map(([name, value]) => [name, typeof value === "string" ? strToU8(value) : value])), { level: 6 }));
}

export function contentTypes(part: string, type: string): string {
  return xml(`<Types xmlns="urn:types"><Override PartName="${part}" ContentType="${type}"/></Types>`);
}

function relationships(body: string): string { return xml(`<Relationships xmlns="urn:rels">${body}</Relationships>`); }
function xml(body: string): string { return `<?xml version="1.0" encoding="UTF-8"?>${body}`; }
