"use client";

import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { selectionAfterSearch } from "../lib/cve-selection.mjs";

const API = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");
type Cve = {
  cveID: string; vendorProject: string; product: string; vulnerabilityName: string;
  dateAdded?: string; shortDescription: string; requiredAction?: string;
  dueDate?: string; knownRansomwareCampaignUse?: string; notes?: string;
};
type Catalog = { count: number; total: number; retrieval_strategy: string; items: Cve[] };
type Source = { cve_id: string; title: string; description: string; vendor: string; product: string; url: string };
type ChatResult = { answer: string; answer_status: string; retrieval_strategy: string; sources: Source[]; evidence: Cve[] };
type Message = { role: "analyst" | "user"; text: string; sources?: Source[]; status?: string };
type View = "overview" | "analyst" | "cves";

function Icon({ children }: { children: string }) { return <span className="inline-flex w-5 justify-center text-base">{children}</span>; }
function ErrorState({ text, retry }: { text: string; retry: () => void }) {
  return <div className="rounded-xl border border-rose-900/60 bg-rose-950/30 p-5 text-sm text-rose-200"><p>{text}</p><button onClick={retry} className="mt-3 rounded-lg border border-rose-800 px-3 py-2 hover:bg-rose-900/40">Retry connection</button></div>;
}

export default function Home() {
  const [view, setView] = useState<View>("overview");
  const [health, setHealth] = useState<{ retrieval_strategy: string; gemini_configured: boolean } | null>(null);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [apiError, setApiError] = useState("");
  const [loadingCatalog, setLoadingCatalog] = useState(false);
  const [query, setQuery] = useState("");
  const [vendorFilter, setVendorFilter] = useState("");
  const [selected, setSelected] = useState<Cve | null>(null);
  const selectionRequest = useRef(0);
  const [messages, setMessages] = useState<Message[]>([{ role: "analyst", text: "I can help investigate vulnerabilities in the CISA KEV catalogue. Ask a question or enter a CVE identifier. Responses are grounded in retrieved records." }]);
  const [question, setQuestion] = useState("");
  const [chatLoading, setChatLoading] = useState(false);

  const loadCatalog = useCallback(async (search = "", vendor = "") => {
    const requestId = ++selectionRequest.current;
    setSelected(null);
    setLoadingCatalog(true); setApiError("");
    try {
      const params = new URLSearchParams({ limit: "30" });
      if (search.trim()) params.set("q", search.trim());
      if (vendor.trim()) params.set("vendor", vendor.trim());
      const response = await fetch(`${API}/api/v1/cves?${params}`, { cache: "no-store" });
      if (!response.ok) throw new Error(`Catalogue request failed (${response.status}).`);
      const result: Catalog = await response.json();
      if (requestId !== selectionRequest.current) return;
      setCatalog(result);
      setSelected(selectionAfterSearch(search, result.items));
    } catch (error) {
      if (requestId === selectionRequest.current) setApiError(error instanceof Error ? error.message : "Could not connect to the API.");
    } finally { if (requestId === selectionRequest.current) setLoadingCatalog(false); }
  }, []);

  const loadHealth = useCallback(async () => {
    try {
      const response = await fetch(`${API}/health`, { cache: "no-store" });
      if (!response.ok) throw new Error("API health request failed.");
      setHealth(await response.json());
    } catch { setHealth(null); }
  }, []);

  useEffect(() => { void loadHealth(); void loadCatalog(); }, [loadCatalog, loadHealth]);

  async function openCve(id: string) {
    const requestId = ++selectionRequest.current;
    setSelected(null);
    try {
      const response = await fetch(`${API}/api/v1/cves/${encodeURIComponent(id)}`, { cache: "no-store" });
      if (!response.ok) throw new Error(`CVE lookup failed (${response.status}).`);
      const result: Cve = await response.json();
      if (requestId === selectionRequest.current) setSelected(result);
    } catch (error) { if (requestId === selectionRequest.current) setApiError(error instanceof Error ? error.message : "CVE lookup failed."); }
  }

  async function submitChat(event: FormEvent) {
    event.preventDefault();
    const text = question.trim();
    if (!text || chatLoading) return;
    setMessages(previous => [...previous, { role: "user", text }]); setQuestion(""); setChatLoading(true);
    try {
      const response = await fetch(`${API}/api/v1/chat`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: text, top_k: 5 }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || `Analyst request failed (${response.status}).`);
      const result = body as ChatResult;
      setMessages(previous => [...previous, { role: "analyst", text: result.answer, sources: result.sources, status: result.answer_status }]);
      setHealth(current => current ? { ...current, retrieval_strategy: result.retrieval_strategy } : current);
    } catch (error) {
      setMessages(previous => [...previous, { role: "analyst", text: error instanceof Error ? error.message : "The analyst API is unavailable." }]);
    } finally { setChatLoading(false); }
  }

  const nav = [
    { id: "overview" as const, label: "Overview", icon: "▦" },
    { id: "analyst" as const, label: "AI Analyst", icon: "✳" },
    { id: "cves" as const, label: "CVE Explorer", icon: "⌕" },
  ];

  return <div className="min-h-screen bg-[#080b10] text-slate-100">
    <aside className="fixed inset-y-0 left-0 z-20 hidden w-64 flex-col border-r border-[#202833] bg-[#0b0f15] px-4 py-5 lg:flex">
      <div className="flex items-center gap-3 px-2"><div className="grid h-10 w-10 place-items-center rounded-xl border border-teal-800/70 bg-teal-950/60 text-teal-300">⌁</div><div><p className="font-semibold tracking-wide">CEREBRO</p><p className="text-[9px] uppercase tracking-[.14em] text-slate-500">Cyber Intelligence</p></div></div>
      <div className="mt-12 px-3 text-[10px] font-semibold uppercase tracking-[.18em] text-slate-600">Workspace</div>
      <nav className="mt-3 space-y-1">{nav.map(item => <button key={item.id} onClick={() => setView(item.id)} className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm transition ${view === item.id ? "bg-[#142521] text-teal-200" : "text-slate-400 hover:bg-white/[.04] hover:text-slate-100"}`}><Icon>{item.icon}</Icon>{item.label}</button>)}</nav>
      <div className="mt-auto rounded-xl border border-[#222d38] bg-[#10161e] p-4"><div className="flex items-center gap-2 text-xs font-medium"><span className={`h-2 w-2 rounded-full ${health ? "bg-teal-400 shadow-[0_0_10px_#4dd7c4]" : "bg-rose-400"}`} />{health ? "API connected" : "API unavailable"}</div><p className="mt-2 text-xs leading-5 text-slate-500">{health ? `Retrieval: ${health.retrieval_strategy.toUpperCase()}` : "Start the FastAPI server to load live CISA KEV data."}</p><p className="mt-3 border-t border-[#242d37] pt-3 text-[10px] text-slate-600">Evidence source · CISA KEV</p></div>
    </aside>

    <main className="min-h-screen lg:pl-64">
      <header className="sticky top-0 z-10 flex h-[68px] items-center justify-between border-b border-[#202833] bg-[#080b10]/90 px-4 backdrop-blur-xl sm:px-8">
        <div className="flex items-center gap-3"><div className="grid h-9 w-9 place-items-center rounded-lg border border-teal-900/70 bg-teal-950/40 text-teal-300 lg:hidden">⌁</div><div><p className="text-sm font-medium">{view === "overview" ? "Cerebro Intelligence Overview" : view === "analyst" ? "AI Security Analyst" : "CVE Explorer"}</p><p className="hidden text-[11px] text-slate-500 sm:block">{view === "overview" ? "Think smarter. Investigate deeper." : "Evidence-first vulnerability intelligence"}</p></div></div>
        <div className="flex items-center gap-3"><span className="hidden items-center gap-2 rounded-full border border-[#29343e] px-3 py-1.5 text-[11px] text-slate-400 sm:flex"><span className="h-1.5 w-1.5 rounded-full bg-teal-400" />{health ? `Retrieval · ${health.retrieval_strategy}` : "Connecting"}</span><button onClick={() => { void loadHealth(); void loadCatalog(query, vendorFilter); }} className="rounded-lg border border-[#29343e] px-3 py-2 text-xs text-slate-300 hover:bg-white/[.05]">↻ <span className="hidden sm:inline">Refresh</span></button></div>
      </header>

      <div className="mx-auto max-w-[1450px] p-4 sm:p-7 lg:p-9">
        {apiError && <div className="mb-5"><ErrorState text={apiError} retry={() => { void loadHealth(); void loadCatalog(query, vendorFilter); }} /></div>}
        {view === "overview" && <>
          <div className="mb-8 flex flex-col justify-between gap-4 sm:flex-row sm:items-end"><div><div className="mb-2 flex items-center gap-2 text-[11px] uppercase tracking-[.2em] text-teal-300"><span>●</span> AI-Powered Cybersecurity Intelligence Assistant</div><h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">Good day, Analyst</h1><p className="mt-2 text-sm text-slate-500">Think smarter. Investigate deeper. Monitor known exploited vulnerabilities with source-backed evidence.</p></div><button onClick={() => setView("analyst")} className="w-fit rounded-lg bg-teal-400 px-4 py-2.5 text-sm font-semibold text-[#06110f] hover:bg-teal-300">＋ New investigation</button></div>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            <Metric label="CISA KEV records" value={catalog ? catalog.total.toLocaleString() : "—"} note={catalog ? "Live catalogue records" : "Waiting for API"} icon="◈" />
            <Metric label="Retrieval strategy" value={health?.retrieval_strategy.toUpperCase() || "—"} note="Configured for this API" icon="⌘" />
            <Metric label="AI analyst" value={health?.gemini_configured ? "Ready" : "Evidence mode"} note={health?.gemini_configured ? "Gemini credentials configured" : "Gemini key optional"} icon="✳" />
          </div>
          <div className="mt-7 grid gap-5 xl:grid-cols-[1.55fr_1fr]">
            <section className="rounded-2xl border border-[#222c37] bg-[#0e131a] p-5 sm:p-6"><div className="flex items-center justify-between"><div><h2 className="font-medium">Recently added to KEV</h2><p className="mt-1 text-xs text-slate-500">Records from the live CISA catalogue</p></div><button onClick={() => setView("cves")} className="text-xs text-teal-300 hover:text-teal-200">Explore all →</button></div>
              {loadingCatalog && !catalog ? <div className="py-10 text-center text-sm text-slate-500">Loading CISA catalogue…</div> : <div className="mt-4 divide-y divide-[#202833]">{catalog?.items.slice(0, 6).map(item => <button key={item.cveID} onClick={() => { setView("cves"); void openCve(item.cveID); }} className="flex w-full items-center justify-between gap-3 py-3 text-left hover:bg-white/[.02]"><div className="min-w-0"><p className="truncate text-sm text-slate-200">{item.vulnerabilityName}</p><p className="mt-1 text-xs text-slate-500">{item.vendorProject} · {item.product}</p></div><span className="shrink-0 font-mono text-[11px] text-teal-300">{item.cveID}</span></button>)}</div>}
              {!catalog && !loadingCatalog && <p className="py-8 text-center text-sm text-slate-500">CISA data will appear when the API connects.</p>}
            </section>
            <section className="rounded-2xl border border-[#222c37] bg-[#0e131a] p-5 sm:p-6"><div className="flex items-center gap-3"><span className="grid h-9 w-9 place-items-center rounded-lg bg-teal-950/60 text-teal-300">✳</span><div><h2 className="font-medium">Ask the analyst</h2><p className="text-xs text-slate-500">Search CISA KEV with evidence</p></div></div><p className="mt-5 text-sm leading-6 text-slate-400">Investigate a CVE, vendor, product, or vulnerability behavior. Retrieved records are shown with every response.</p><button onClick={() => setView("analyst")} className="mt-5 w-full rounded-lg border border-teal-900/70 bg-teal-950/30 px-4 py-3 text-left text-sm text-teal-100 hover:bg-teal-950/60">Start a conversation <span className="float-right">→</span></button><p className="mt-3 text-[11px] text-slate-600">Answers require Gemini credentials. Retrieval remains available without them.</p></section>
          </div>
        </>}

        {view === "analyst" && <section className="mx-auto flex min-h-[calc(100vh-145px)] max-w-4xl flex-col overflow-hidden rounded-2xl border border-[#222c37] bg-[#0e131a]
          "><div className="flex items-center justify-between border-b border-[#222c37] px-5 py-4"><div className="flex items-center gap-3"><span className="grid h-10 w-10 place-items-center rounded-xl border border-teal-900/70 bg-teal-950/50 text-teal-300">✳</span><div><h1 className="text-sm font-medium">AI Security Analyst</h1><p className="mt-1 text-xs text-slate-500">Grounded in CISA KEV · {health?.retrieval_strategy || "connecting"}</p></div></div><button onClick={() => setMessages([{ role: "analyst", text: "New investigation started. Ask about CISA KEV vulnerabilities or enter a CVE identifier." }])} className="rounded-lg border border-[#29343e] px-3 py-2 text-xs text-slate-300 hover:bg-white/[.05]">New chat</button></div>
            <div className="scrollbar-thin flex-1 space-y-5 overflow-y-auto p-4 sm:p-6">{messages.map((message, index) => <div key={index} className={`flex gap-3 ${message.role === "user" ? "flex-row-reverse" : ""}`}><div className={`grid h-8 w-8 shrink-0 place-items-center rounded-lg text-xs ${message.role === "analyst" ? "bg-teal-950/70 text-teal-300" : "bg-[#252d37] text-slate-300"}`}>{message.role === "analyst" ? "✳" : "A"}</div><div className={`max-w-[88%] rounded-2xl px-4 py-3 text-sm leading-6 ${message.role === "user" ? "bg-[#183a35] text-teal-50" : "border border-[#242e39] bg-[#121922] text-slate-200"}`}><p className="whitespace-pre-wrap">{message.text}</p>{message.status && message.status !== "generated" && <p className="mt-2 text-[11px] uppercase tracking-wide text-amber-300">{message.status.replaceAll("_", " ")}</p>}{message.sources && message.sources.length > 0 && <div className="mt-4 border-t border-[#29343e] pt-3"><p className="mb-2 text-[10px] font-semibold uppercase tracking-[.16em] text-slate-500">Retrieved source records</p><div className="flex flex-wrap gap-2">{message.sources.map(source => <a key={source.cve_id} href={source.url} target="_blank" rel="noreferrer" className="rounded-md border border-teal-900/60 bg-teal-950/30 px-2.5 py-1 font-mono text-[11px] text-teal-200 hover:bg-teal-900/40">{source.cve_id} ↗</a>)}</div>{message.sources.map(source => <p key={source.cve_id} className="mt-2 text-xs text-slate-400"><span className="text-slate-300">{source.title}:</span> {source.description}</p>)}</div>}</div></div>)}{chatLoading && <div className="flex gap-3"><div className="grid h-8 w-8 place-items-center rounded-lg bg-teal-950/70 text-teal-300">✳</div><div className="rounded-xl border border-[#242e39] bg-[#121922] px-4 py-3 text-sm text-slate-400">Searching CISA KEV and preparing evidence…</div></div>}</div>
            <form onSubmit={submitChat} className="border-t border-[#222c37] p-4 sm:p-5"><label className="sr-only" htmlFor="question">Ask a vulnerability question</label><div className="flex items-end gap-2 rounded-xl border border-[#2a3540] bg-[#090d12] p-2 focus-within:border-teal-800"><textarea id="question" value={question} onChange={event => setQuestion(event.target.value)} onKeyDown={event => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); event.currentTarget.form?.requestSubmit(); } }} rows={2} maxLength={4000} placeholder="Ask about a vulnerability, product, vendor, or CVE…" className="max-h-36 min-h-12 flex-1 resize-y bg-transparent px-2 py-2 text-sm outline-none placeholder:text-slate-600"/><button disabled={chatLoading || !question.trim()} className="rounded-lg bg-teal-400 px-4 py-2.5 text-sm font-semibold text-[#06110f] disabled:cursor-not-allowed disabled:opacity-40">Send</button></div><p className="mt-2 px-1 text-[10px] text-slate-600">AI output can be wrong. Verify details against cited CISA records.</p></form>
          </section>}

        {view === "cves" && <div className="grid gap-5 xl:grid-cols-[1.25fr_.75fr]"><section className="rounded-2xl border border-[#222c37] bg-[#0e131a] p-5 sm:p-6"><div><p className="text-[11px] uppercase tracking-[.18em] text-teal-300">CISA KEV catalogue</p><h1 className="mt-2 text-xl font-semibold">CVE Explorer</h1><p className="mt-1 text-sm text-slate-500">Search and inspect known exploited vulnerability records.</p></div><form onSubmit={event => { event.preventDefault(); void loadCatalog(query, vendorFilter); }} className="mt-5 grid gap-2 sm:grid-cols-[1fr_220px_auto]"><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search CVE, vendor, product, or keyword" className="min-w-0 rounded-lg border border-[#29343e] bg-[#090d12] px-3 py-2.5 text-sm outline-none focus:border-teal-800"/><input value={vendorFilter} onChange={event => setVendorFilter(event.target.value)} aria-label="Exact vendor filter" placeholder="Exact vendor (optional)" className="min-w-0 rounded-lg border border-[#29343e] bg-[#090d12] px-3 py-2.5 text-sm outline-none focus:border-teal-800"/><button className="rounded-lg bg-teal-400 px-4 py-2.5 text-sm font-semibold text-[#06110f]">Search</button></form><p className="mt-2 text-[11px] text-slate-600">Vendor filter matches the CISA vendor field exactly (case-insensitive); keyword ranking alone may include other vendors.</p><div className="mt-4 flex justify-between text-xs text-slate-500"><span>{catalog ? `${catalog.count} shown · ${catalog.total.toLocaleString()} records` : "Catalogue not loaded"}</span><button onClick={() => { setQuery(""); setVendorFilter(""); void loadCatalog("", ""); }} className="text-teal-300">Clear search</button></div>
            <div className="mt-3 divide-y divide-[#202833]">{loadingCatalog ? <p className="py-8 text-center text-sm text-slate-500">Searching catalogue…</p> : catalog?.items.map(item => <button key={item.cveID} onClick={() => void openCve(item.cveID)} className={`w-full py-4 text-left ${selected?.cveID === item.cveID ? "bg-teal-950/20" : "hover:bg-white/[.025]"}`}><div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="text-sm font-medium text-slate-200">{item.vulnerabilityName}</p><p className="mt-1 text-xs text-slate-500">{item.vendorProject} · {item.product}</p></div><span className="shrink-0 font-mono text-[11px] text-teal-300">{item.cveID}</span></div></button>)}{catalog?.items.length === 0 && <div className="py-10 text-center text-sm text-slate-500">No matching CISA KEV records found.</div>}</div></section>
            <section className="h-fit rounded-2xl border border-[#222c37] bg-[#0e131a] p-5 sm:p-6">{selected ? <><div className="flex items-start justify-between gap-3"><span className="rounded-md border border-teal-900/70 bg-teal-950/30 px-2 py-1 font-mono text-xs text-teal-200">{selected.cveID}</span><a href={`https://www.cisa.gov/known-exploited-vulnerabilities-catalog#${selected.cveID}`} target="_blank" rel="noreferrer" className="text-xs text-teal-300 hover:underline">CISA source ↗</a></div><h2 className="mt-5 text-lg font-semibold leading-7">{selected.vulnerabilityName}</h2><p className="mt-3 text-sm leading-6 text-slate-400">{selected.shortDescription}</p><dl className="mt-5 divide-y divide-[#222c37]">{[["Vendor", selected.vendorProject], ["Product", selected.product], ["Added to KEV", selected.dateAdded || "Not provided"], ["Required action", selected.requiredAction || "Not provided"], ["Due date", selected.dueDate || "Not provided"], ["Ransomware use", selected.knownRansomwareCampaignUse || "Not provided"]].map(([label, value]) => <div key={label} className="grid grid-cols-[110px_1fr] gap-3 py-3 text-xs"><dt className="text-slate-500">{label}</dt><dd className="text-slate-300">{value}</dd></div>)}</dl>{selected.notes && <p className="mt-4 text-xs leading-5 text-slate-500">{selected.notes}</p>}</> : <div className="py-10 text-center"><span className="text-3xl text-slate-700">⌕</span><h2 className="mt-3 text-sm font-medium text-slate-300">Vulnerability details</h2><p className="mt-2 text-xs leading-5 text-slate-500">Select a CVE from the catalogue to inspect its source fields and remediation action.</p></div>}</section></div>}
      </div>
      <nav className="fixed inset-x-0 bottom-0 z-20 grid grid-cols-3 border-t border-[#222c37] bg-[#0b0f15] p-1 lg:hidden">{nav.map(item => <button key={item.id} onClick={() => setView(item.id)} className={`rounded-lg py-2 text-[10px] ${view === item.id ? "text-teal-200" : "text-slate-500"}`}><span className="mb-0.5 block text-base">{item.icon}</span>{item.label}</button>)}</nav>
      <div className="h-14 lg:hidden" />
    </main>
  </div>;
}

function Metric({ label, value, note, icon }: { label: string; value: string; note: string; icon: string }) {
  return <div className="rounded-2xl border border-[#222c37] bg-[#0e131a] p-5"><div className="flex items-start justify-between"><p className="text-xs text-slate-500">{label}</p><span className="text-teal-300">{icon}</span></div><p className="mt-4 text-2xl font-semibold tracking-tight">{value}</p><p className="mt-1 text-[11px] text-slate-600">{note}</p></div>;
}
