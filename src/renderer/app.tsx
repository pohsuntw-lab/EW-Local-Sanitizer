import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import type { Action, AllowedRoute, Classification, ReasonCode } from "../core/types.js";
import type { ExportResult, ScanOptions, ScanResult, UiDecision, UiFinding } from "../ui/contracts.js";

const reasonCodes: ReasonCode[] = ["PUBLICLY_APPROVED", "OPERATIONAL_CONTEXT", "LOW_SENSITIVITY_ACCEPTED"];

function App(): React.JSX.Element {
  const [scan, setScan] = useState<ScanResult>();
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("尚未選擇檔案");
  const [dictionaryText, setDictionaryText] = useState("");
  const [ocrLanguage, setOcrLanguage] = useState<ScanOptions["ocrLanguage"]>("eng");
  const [approveSheets, setApproveSheets] = useState(false);
  const [decisions, setDecisions] = useState<Record<string, UiDecision>>({});
  const [classification, setClassification] = useState<Classification>("P2");
  const [route, setRoute] = useState<AllowedRoute>("cloud-sanitized");
  const [confirmed, setConfirmed] = useState(false);
  const [passphrase, setPassphrase] = useState("");
  const [result, setResult] = useState<ExportResult>();
  const needsMap = Object.values(decisions).some((decision) => decision.action === "tokenize");
  const complete = scan !== undefined && scan.findings.every((finding) => decisions[finding.findingId] !== undefined);
  const coverageComplete = scan?.sources.every((source) => source.coverage === "complete") ?? false;
  const findingGroups = useMemo(() => scan?.sources.map((source) => ({ source, findings: scan.findings.filter((finding) => finding.sourceId === source.sourceId) })) ?? [], [scan]);

  useEffect(() => {
    setRoute(classification === "P0" ? "cloud-approved" : classification === "P3" ? "local-only" : "cloud-sanitized");
    setConfirmed(false);
  }, [classification]);

  async function chooseFiles(): Promise<void> {
    setBusy(true); setResult(undefined); setNotice("正在本機解析與掃描…");
    try {
      const response = await window.ewDesktop.pickAndScan({ dictionaryTerms: dictionaryText.split(/\r?\n/u).map((term) => term.trim()).filter(Boolean),
        latinCaseSensitive: false, ocrLanguage, approveAllVisibleWorksheets: approveSheets });
      if (response.status === "ready") { setScan(response); setDecisions({}); setDictionaryText(""); setNotice(`完成：${response.sources.length} 個檔案，${response.findings.length} 個 findings`); }
      else if (response.status === "cancelled") setNotice("已取消選檔");
      else setNotice(safeMessage(response.code));
    } finally { setBusy(false); }
  }

  function decide(finding: UiFinding, action: Action): void {
    setResult(undefined);
    setDecisions((current) => ({ ...current, [finding.findingId]: { findingId: finding.findingId, action,
      ...(action === "keep" ? { reasonCode: "OPERATIONAL_CONTEXT" as const } : {}),
      ...(action === "generalize" && finding.generalizationRules[0] ? { generalizationRuleId: finding.generalizationRules[0] } : {}) } }));
  }

  async function exportReviewed(): Promise<void> {
    if (!scan || !complete) return;
    setBusy(true); setNotice("正在執行第二掃描與建立 Safe Package…");
    try {
      const response = await window.ewDesktop.exportReviewed({ sessionId: scan.sessionId, classification, allowedRoute: route,
        p2Confirmed: confirmed, ...(needsMap ? { tokenMapPassphrase: passphrase } : {}), decisions: Object.values(decisions) });
      setPassphrase("");
      setResult(response);
      setNotice(response.status === "exported" ? "Safe Package 已完成；應用程式不會自動上傳。" : response.status === "blocked" ? `匯出已阻擋：${response.unresolved.join("、")}` : response.status === "cancelled" ? "已取消輸出" : safeMessage(response.code));
    } finally { setBusy(false); }
  }

  async function clearSession(): Promise<void> {
    await window.ewDesktop.closeSession();
    setScan(undefined); setDecisions({}); setResult(undefined); setPassphrase(""); setConfirmed(false); setNotice("Session 已從記憶體清除");
  }

  return <main>
    <header className="hero"><div><p className="eyebrow">EW LOCAL SANITIZER · v0.1.0</p><h1>上傳之前，先在本機把敏感內容處理乾淨。</h1><p className="lead">所有解析、OCR、審查與第二掃描都留在這台電腦。工具不會替你上傳，也無法追回已經上傳的內容。</p></div><div className="privacy-seal"><span>LOCAL</span><strong>零自動上傳</strong><small>防禦縱深，不保證零漏報</small></div></header>
    <nav className="steps"><span className={scan ? "done" : "active"}>1 選擇檔案</span><span className={scan ? "active" : ""}>2 審查 findings</span><span className={result?.status === "exported" ? "done" : ""}>3 複掃與匯出</span></nav>

    <section className="panel setup"><div><h2>本機掃描設定</h2><p>支援 TXT、Markdown、CSV/TSV、Office、文字型 PDF 與 PNG/JPEG。</p></div>
      <label>Exact-data 字典（每行一個，僅保留於本次記憶體）<textarea value={dictionaryText} onChange={(event) => setDictionaryText(event.target.value)} placeholder="例如：專案代號、客戶名稱" /></label>
      <div className="inline"><label>影像 OCR 語言<select value={ocrLanguage} onChange={(event) => setOcrLanguage(event.target.value as ScanOptions["ocrLanguage"])}><option value="eng">English</option><option value="chi_tra">繁體中文</option></select></label>
      <label className="check"><input type="checkbox" checked={approveSheets} onChange={(event) => setApproveSheets(event.target.checked)} />我已確認要檢查所有可見 XLSX 工作表</label></div>
      <button className="primary" disabled={busy} onClick={() => void chooseFiles()}>{busy ? "處理中…" : "選擇檔案並開始掃描"}</button>
    </section>

    {scan && <section className="workspace"><div className="section-title"><div><p className="eyebrow">REVIEW</p><h2>逐項決定如何處理</h2></div><div className="review-tools"><button className="secondary" onClick={() => void clearSession()}>清除 session</button><div className="counter">{Object.keys(decisions).length}/{scan.findings.length}</div></div></div>
      {findingGroups.map(({ source, findings }) => <article className="file-card" key={source.sourceId}><div className="file-head"><div><strong>{source.displayName}</strong><small>{source.format.toUpperCase()} · coverage {source.coverage}</small></div><span className={source.coverage === "complete" ? "status ok" : "status danger"}>{source.coverage === "complete" ? "可審查" : "匯出阻擋"}</span></div>
        {findings.length === 0 ? <p className="empty">未偵測到 finding；這不代表檔案一定安全。</p> : findings.map((finding) => <div className="finding" key={finding.findingId}><div><span className={`severity ${finding.severity}`}>{finding.severity}</span><strong>{finding.type}</strong><code>{finding.maskedPreview}</code><small>{finding.detector}</small></div><label>處置<select value={decisions[finding.findingId]?.action ?? ""} onChange={(event) => decide(finding, event.target.value as Action)}><option value="" disabled>請選擇</option>{finding.allowedActions.map((action) => <option value={action} key={action}>{action}</option>)}</select></label>
          {decisions[finding.findingId]?.action === "keep" && <label>理由代碼<select value={decisions[finding.findingId]?.reasonCode} onChange={(event) => setDecisions((current) => ({ ...current, [finding.findingId]: { ...current[finding.findingId]!, reasonCode: event.target.value as ReasonCode } }))}>{reasonCodes.map((reason) => <option key={reason}>{reason}</option>)}</select></label>}
          {decisions[finding.findingId]?.action === "generalize" && finding.generalizationRules.length > 1 && <label>規則<select value={decisions[finding.findingId]?.generalizationRuleId} onChange={(event) => setDecisions((current) => ({ ...current, [finding.findingId]: { ...current[finding.findingId]!, generalizationRuleId: event.target.value } }))}>{finding.generalizationRules.map((rule) => <option key={rule}>{rule}</option>)}</select></label>}</div>)}</article>)}
    </section>}

    {scan && <section className="panel export"><div><p className="eyebrow">EXPORT GATE</p><h2>分類、確認、第二掃描</h2></div><div className="inline"><label>資料分級<select value={classification} onChange={(event) => setClassification(event.target.value as Classification)}>{["P0", "P1", "P2", "P3"].map((value) => <option key={value}>{value}</option>)}</select></label><label>允許路由<input readOnly value={route} /></label></div>
      {classification === "P2" && <label className="check prominent"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />我已在本機完成明確人工審查，確認目前 decisions 與衍生內容</label>}
      {classification === "P3" && <p className="warning">P3 永遠 local-only，重新命名或 tokenization 不會開放 Safe Package。</p>}
      {needsMap && <label>本機 .ewmap 密碼（至少 12 字元，不會儲存）<input type="password" autoComplete="new-password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} /></label>}
      <button className="primary" disabled={busy || !complete || !coverageComplete || classification === "P3" || (classification === "P2" && !confirmed) || (needsMap && passphrase.length < 12)} onClick={() => void exportReviewed()}>執行複掃並選擇輸出位置</button>
      <p className="gate-note">{!coverageComplete ? "Parser／OCR coverage 不完整，匯出維持阻擋。" : !complete ? "所有 findings 都必須先作出 decision。" : "第二掃描通過後才會取得不可偽造的匯出 capability。"}</p>
    </section>}

    <footer className="notice" aria-live="polite"><span className={busy ? "pulse" : "dot"} />{notice}</footer>
    {result?.status === "exported" && <section className="receipt"><h2>匯出完成</h2><dl><dt>Safe Package</dt><dd>{result.packagePath}</dd><dt>SHA-256</dt><dd><code>{result.packageHash}</code></dd><dt>Checksum</dt><dd>{result.checksumPath}</dd>{result.tokenMapPath && <><dt>本機 token map</dt><dd>{result.tokenMapPath}</dd></>}</dl><p>只上傳 <strong>SAFE-PACKAGE.zip</strong>；`.ewmap` 與原始檔必須留在本機。</p></section>}
  </main>;
}

function safeMessage(code: string): string {
  return ({ INVALID_REQUEST: "輸入無效，未執行任何匯出。", PROCESSING_FAILED: "本機處理失敗，安全狀態維持阻擋。", OUTPUT_EXISTS: "輸出檔已存在；為避免覆寫，請選擇新的檔名。", NO_SESSION: "Session 已關閉，請重新選擇檔案。" } as Record<string, string>)[code] ?? "操作未完成";
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
