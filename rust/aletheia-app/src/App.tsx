import { forwardRef, useCallback, useEffect, useMemo, useRef, useState } from "react"
import { invoke } from "@tauri-apps/api/core"
import { getCurrentWindow } from "@tauri-apps/api/window"
import { open as openDialog } from "@tauri-apps/plugin-dialog"

// ==========================================================================
// Types (mirror aletheia-core serde shapes)
// ==========================================================================
type Section = {
    name: string; vaddr: number; vsize: number; raw_ptr: number; raw_size: number
    entropy: number; readable: boolean; writable: boolean; executable: boolean
}
type PeInfo = {
    ok: boolean; error: string | null; arch: string; is_dll: boolean; is_dotnet: boolean
    entry_rva: number; image_base: number; machine: number; n_sections: number
    sections: Section[]; entry_section: string | null
    import_dlls: string[]; import_func_count: number; overall_entropy: number
}
type Verdict = { packed: boolean; confidence: number; likely_packer: string | null; signals: string[] }
type Analysis = { pe: PeInfo; verdict: Verdict }
type UnpackResult = { detected: boolean; oep: number | null; main_base: number; exit_code: number | null; gave_up: boolean; reason: string; events: RunEvent[] }
// (RunEvent is declared at the bottom of the file next to its only consumer.)
type Instruction = {
    address: number; size: number; mnemonic: string; op_str: string; bytes: string
    target: number | null; is_call: boolean; is_ret: boolean; is_jmp: boolean; is_cond_jmp: boolean
}
type BasicBlock = { start: number; end: number; instructions: number[]; succs: number[] }
type DisasmView = { base_rva: number; instructions: Instruction[]; blocks: BasicBlock[] }
type EngineInfo = { engine: string; version: string; target_arch: string; target_os: string }
type Toast = { id: number; kind: "error" | "info" | "ok"; text: string }
const RECENT_KEY = "aletheia.recent"

// ==========================================================================
// Small helpers
// ==========================================================================
const hex = (n: number) => "0x" + n.toString(16)
const addr = (n: number) => "0x" + n.toString(16).padStart(8, "0")
const pct = (n: number) => `${Math.round(n * 100)}%`
const basename = (p: string) => (p.split(/[\\/]/).pop() || p)
const flags = (s: Section) =>
    (s.readable ? "R" : "-") + (s.writable ? "W" : "-") + (s.executable ? "X" : "-")
const entropyClass = (e: number) =>
    e >= 7.2 ? "text-[var(--color-al-warn)]"
    : e >= 6.5 ? "text-[var(--color-al-text)]"
    : "text-[var(--color-al-text-mute)]"
const insnClass = (i: Instruction) =>
    i.is_ret ? "text-[var(--color-al-warn)]"
    : i.is_call ? "text-[var(--color-al-accent)]"
    : (i.is_jmp || i.is_cond_jmp) ? "text-[var(--color-al-accent-hi)]"
    : "text-[var(--color-al-text)]"

// ==========================================================================
// Icons (inline SVG -- one component keeps stroke width + colors consistent)
// ==========================================================================
type IconName =
    | "file" | "folder" | "analyze" | "close" | "minimize" | "maximize" | "restore"
    | "cpu" | "layers" | "target" | "package" | "warning" | "check" | "x"
    | "chevron-down" | "chevron-right" | "search" | "sparkle" | "external"
    | "github" | "info" | "lock" | "unlock" | "zap"

function Icon({ name, className = "w-4 h-4" }: { name: IconName; className?: string }) {
    const p = ICON_PATHS[name] ?? ICON_PATHS.file
    return (
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"
             className={className} aria-hidden="true">
            <g dangerouslySetInnerHTML={{ __html: p }} />
        </svg>
    )
}
const ICON_PATHS: Record<IconName, string> = {
    file:        '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
    folder:      '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    analyze:     '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
    close:       '<path d="M18 6 6 18M6 6l12 12"/>',
    minimize:    '<path d="M5 12h14"/>',
    maximize:    '<rect x="4" y="4" width="16" height="16" rx="1"/>',
    restore:     '<rect x="8" y="8" width="12" height="12" rx="1"/><path d="M16 8V4H4v12h4"/>',
    cpu:         '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/>',
    layers:      '<path d="m12 2 10 5-10 5L2 7z"/><path d="m2 17 10 5 10-5"/><path d="m2 12 10 5 10-5"/>',
    target:      '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>',
    package:     '<path d="M16.5 9.4 7.5 4.2"/><path d="M21 16V8a2 2 0 0 0-1-1.7l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.7l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><path d="M3.3 7 12 12l8.7-5"/><path d="M12 22V12"/>',
    warning:     '<path d="M10.3 3.6 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.6a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
    check:       '<path d="m5 12 5 5L20 7"/>',
    x:           '<path d="M18 6 6 18M6 6l12 12"/>',
    "chevron-down":  '<path d="m6 9 6 6 6-6"/>',
    "chevron-right": '<path d="m9 6 6 6-6 6"/>',
    search:      '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
    sparkle:     '<path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M5.6 18.4l2.8-2.8M15.6 8.4l2.8-2.8"/>',
    external:    '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
    github:      '<path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.9a3.4 3.4 0 0 0-.9-2.6c3-.3 6.1-1.5 6.1-6.6 0-1.3-.5-2.5-1.4-3.5.3-.9.3-1.9 0-2.9 0 0-1.1-.3-3.6 1.4a12.5 12.5 0 0 0-6.4 0C4.7 1.7 3.6 2 3.6 2c-.3 1-.3 2 0 2.9A5 5 0 0 0 2.2 8.4c0 5.1 3.1 6.3 6.1 6.6a3.4 3.4 0 0 0-1 2.6V22"/>',
    info:        '<circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11 12h1v4h1"/>',
    lock:        '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 1 1 8 0v4"/>',
    unlock:      '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0"/>',
    zap:         '<path d="M13 2 3 14h8l-1 8 10-12h-8z"/>',
}

// ==========================================================================
// Root App
// ==========================================================================
export default function App() {
    const [path, setPath] = useState<string>("")
    const [analysis, setAnalysis] = useState<Analysis | null>(null)
    const [loadedPath, setLoadedPath] = useState<string | null>(null)
    const [disasm, setDisasm] = useState<DisasmView | null>(null)
    const [selectedFn, setSelectedFn] = useState<number | null>(null)
    const [busy, setBusy] = useState(false)
    const [phase, setPhase] = useState<string>("")
    const [engine, setEngine] = useState<EngineInfo | null>(null)
    const [toasts, setToasts] = useState<Toast[]>([])
    const [recent, setRecent] = useState<string[]>([])
    const [dropActive, setDropActive] = useState(false)
    const toastId = useRef(0)

    // Engine info + recent files (per-viewer localStorage; not shared)
    useEffect(() => {
        invoke<EngineInfo>("engine_info").then(setEngine).catch(() => setEngine(null))
        try { setRecent(JSON.parse(localStorage.getItem(RECENT_KEY) || "[]")) } catch { /* empty */ }
    }, [])

    function toast(kind: Toast["kind"], text: string, ttl_ms = 4200) {
        const id = ++toastId.current
        setToasts(t => [...t, { id, kind, text }])
        setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), ttl_ms)
    }

    function pushRecent(p: string) {
        setRecent(prev => {
            const next = [p, ...prev.filter(x => x !== p)].slice(0, 8)
            try { localStorage.setItem(RECENT_KEY, JSON.stringify(next)) } catch { /* empty */ }
            return next
        })
    }

    const runAnalyze = useCallback(async (overridePath?: string) => {
        const p = overridePath ?? path
        if (!p) { toast("info", "No file selected."); return }
        setBusy(true); setPhase("parsing PE"); setAnalysis(null); setDisasm(null); setSelectedFn(null)
        try {
            setPhase("running detect")
            const a = await invoke<Analysis>("analyze", { path: p })
            setAnalysis(a)
            setLoadedPath(p)
            setPhase("disassembling")
            pushRecent(p)
            try { getCurrentWindow().setTitle(`${basename(p)}  -  Aletheia`) } catch { /* empty */ }
            if (a.pe.ok && a.pe.entry_rva) {
                try {
                    const d = await invoke<DisasmView>("disasm_at", { path: p, addr: a.pe.entry_rva, count: 400 })
                    setDisasm(d); setSelectedFn(a.pe.entry_rva)
                } catch (e) {
                    toast("info", `disasm: ${String(e)}`)
                }
            }
            if (a.pe.ok) {
                toast("ok",
                    a.verdict.packed
                        ? `PACKED ${pct(a.verdict.confidence)}${a.verdict.likely_packer ? " - " + a.verdict.likely_packer : ""}`
                        : `Clean (${pct(1 - a.verdict.confidence)})`)
            } else {
                toast("error", `parse failed: ${a.pe.error}`)
            }
        } catch (e) {
            toast("error", String(e))
        } finally {
            setBusy(false); setPhase("")
        }
    }, [path])

    async function openAndAnalyze() {
        try {
            const p = await openDialog({
                multiple: false, directory: false,
                filters: [{ name: "Executables", extensions: ["exe", "dll", "sys", "cpl", "ocx"] }],
            })
            if (typeof p === "string") { setPath(p); runAnalyze(p) }
        } catch (e) { toast("error", String(e)) }
    }

    // Drag-and-drop a file onto the window (Tauri v2 drag-drop event)
    useEffect(() => {
        const w = getCurrentWindow()
        const un = w.onDragDropEvent(e => {
            if (e.payload.type === "enter" || e.payload.type === "over") setDropActive(true)
            else if (e.payload.type === "leave") setDropActive(false)
            else if (e.payload.type === "drop") {
                setDropActive(false)
                const paths = e.payload.paths as string[]
                if (paths && paths.length > 0) { setPath(paths[0]); runAnalyze(paths[0]) }
            }
        })
        return () => { un.then(f => f()) }
    }, [runAnalyze])

    // Keyboard shortcuts
    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            if (e.ctrlKey && (e.key === "o" || e.key === "O")) { e.preventDefault(); openAndAnalyze() }
            else if ((e.ctrlKey && (e.key === "r" || e.key === "R")) || e.key === "F5") { e.preventDefault(); runAnalyze() }
            else if (e.key === "Escape") { setToasts([]) }
        }
        window.addEventListener("keydown", onKey)
        return () => window.removeEventListener("keydown", onKey)
    }, [runAnalyze])

    return (
        <div className={"h-screen flex flex-col bg-[var(--color-al-bg)] text-[var(--color-al-text)] " + (dropActive ? "drop-active" : "")}
             style={dropActive ? { borderRadius: "6px", border: "2px solid var(--color-al-accent)" } : undefined}>
            <TitleBar onOpen={openAndAnalyze} onAnalyze={() => runAnalyze()} engine={engine}
                      recent={recent} onPickRecent={(p) => { setPath(p); runAnalyze(p) }} />
            <CommandBar path={path} setPath={setPath}
                        onPick={openAndAnalyze} onAnalyze={() => runAnalyze()}
                        busy={busy} />
            <Breadcrumb path={path} analysis={analysis} />
            {analysis === null && !busy
                ? <Welcome onOpen={openAndAnalyze} recent={recent}
                           onPickRecent={(p) => { setPath(p); runAnalyze(p) }} />
                : <Workbench analysis={analysis} disasm={disasm} busy={busy}
                             selectedFn={selectedFn} setSelectedFn={setSelectedFn}
                             loadedPath={loadedPath} />}
            <StatusBar analysis={analysis} disasm={disasm} engine={engine} path={path} busy={busy} phase={phase} />
            <ToastStack toasts={toasts} onDismiss={(id) => setToasts(t => t.filter(x => x.id !== id))} />
        </div>
    )
}

// ==========================================================================
// Title bar
// ==========================================================================
function TitleBar({ onOpen, onAnalyze, engine, recent, onPickRecent }: {
    onOpen: () => void; onAnalyze: () => void; engine: EngineInfo | null
    recent: string[]; onPickRecent: (p: string) => void
}) {
    const w = useMemo(() => getCurrentWindow(), [])
    const [menuOpen, setMenuOpen] = useState<string | null>(null)
    const [maximized, setMaximized] = useState(false)
    const menuRef = useRef<HTMLDivElement>(null)
    useEffect(() => {
        const off = (e: MouseEvent) => {
            if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(null)
        }
        window.addEventListener("mousedown", off)
        return () => window.removeEventListener("mousedown", off)
    }, [])
    useEffect(() => { w.isMaximized().then(setMaximized).catch(() => {}) }, [w])
    return (
        <div data-tauri-drag-region
             className="h-9 flex items-center gap-2 px-2 bg-[var(--color-al-surface-2)] border-b border-[var(--color-al-border)] select-none">
            <span className="text-sm font-semibold tracking-widest text-[var(--color-al-text)] ml-2 mr-3" data-tauri-drag-region>ALETHEIA</span>
            <div ref={menuRef} className="flex items-center">
                <Menu label="File" open={menuOpen === "File"} onOpen={() => setMenuOpen(menuOpen === "File" ? null : "File")}>
                    <MenuItem icon="folder" label="Open PE..." shortcut="Ctrl+O" onClick={() => { setMenuOpen(null); onOpen() }} />
                    {recent.length > 0 && <>
                        <MenuSep />
                        <MenuLabel>Recent</MenuLabel>
                        {recent.slice(0, 5).map((p, i) => (
                            <MenuItem key={i} icon="file" label={basename(p)} hint={p}
                                      onClick={() => { setMenuOpen(null); onPickRecent(p) }} />
                        ))}
                    </>}
                    <MenuSep />
                    <MenuItem icon="close" label="Exit" onClick={() => { setMenuOpen(null); w.close() }} />
                </Menu>
                <Menu label="Analysis" open={menuOpen === "Analysis"} onOpen={() => setMenuOpen(menuOpen === "Analysis" ? null : "Analysis")}>
                    <MenuItem icon="analyze" label="Analyze" shortcut="Ctrl+R" onClick={() => { setMenuOpen(null); onAnalyze() }} />
                </Menu>
                <Menu label="View" open={menuOpen === "View"} onOpen={() => setMenuOpen(menuOpen === "View" ? null : "View")}>
                    <MenuItem icon="sparkle" label="Reload UI" shortcut="Ctrl+Shift+R" onClick={() => location.reload()} />
                </Menu>
                <Menu label="Help" open={menuOpen === "Help"} onOpen={() => setMenuOpen(menuOpen === "Help" ? null : "Help")}>
                    <MenuItem icon="github" label="GitHub" onClick={() => window.open("https://github.com/zaehuncho/Aletheia", "_blank")} />
                    <MenuItem icon="info" label="About" onClick={() => alert(`Aletheia\nengine: ${engine?.engine ?? "?"} ${engine?.version ?? ""}\ntarget: ${engine?.target_arch ?? "?"} ${engine?.target_os ?? ""}`)} />
                </Menu>
            </div>
            <div className="ml-auto flex items-center h-full">
                <TitleBtn onClick={() => w.minimize()} title="Minimize"><Icon name="minimize" className="w-3.5 h-3.5" /></TitleBtn>
                <TitleBtn onClick={() => w.toggleMaximize().then(() => w.isMaximized().then(setMaximized))} title="Maximize">
                    <Icon name={maximized ? "restore" : "maximize"} className="w-3 h-3" />
                </TitleBtn>
                <TitleBtn danger onClick={() => w.close()} title="Close">
                    <Icon name="close" className="w-3.5 h-3.5" />
                </TitleBtn>
            </div>
        </div>
    )
}
function Menu({ label, open, onOpen, children }: {
    label: string; open: boolean; onOpen: () => void; children: React.ReactNode
}) {
    return (
        <div className="relative">
            <button onMouseDown={(e) => { e.preventDefault(); onOpen() }}
                className={"px-3 h-7 text-xs " + (open
                    ? "bg-[var(--color-al-surface)] text-[var(--color-al-text)]"
                    : "text-[var(--color-al-text-mute)] hover:text-[var(--color-al-text)]")}>
                {label}
            </button>
            {open && (
                <div className="absolute top-8 left-0 min-w-56 bg-[var(--color-al-surface)] border border-[var(--color-al-border)] shadow-xl z-50 py-1 fade-in">
                    {children}
                </div>
            )}
        </div>
    )
}
function MenuItem({ icon, label, shortcut, hint, onClick }:
    { icon?: IconName; label: string; shortcut?: string; hint?: string; onClick: () => void }) {
    return (
        <button onClick={onClick}
            className="w-full text-left px-3 py-1.5 text-xs hover:bg-[var(--color-al-surface-2)] flex items-center gap-2"
            title={hint}>
            {icon && <span className="text-[var(--color-al-text-mute)]"><Icon name={icon} className="w-3.5 h-3.5" /></span>}
            <span className="truncate">{label}</span>
            {shortcut && <span className="ml-auto text-[var(--color-al-text-mute)] mono text-[10px]">{shortcut}</span>}
        </button>
    )
}
function MenuLabel({ children }: { children: React.ReactNode }) {
    return <div className="px-3 py-0.5 text-[10px] uppercase tracking-widest text-[var(--color-al-text-mute)]">{children}</div>
}
function MenuSep() {
    return <div className="my-1 border-t border-[var(--color-al-border)]" />
}
function TitleBtn({ children, onClick, danger, title }: {
    children: React.ReactNode; onClick: () => void; danger?: boolean; title?: string
}) {
    return (
        <button onClick={onClick} title={title}
            className={"h-full w-10 flex items-center justify-center text-[var(--color-al-text-mute)] " +
                (danger ? "hover:bg-[var(--color-al-danger)] hover:text-white"
                        : "hover:bg-[var(--color-al-surface)] hover:text-[var(--color-al-text)]")}>
            {children}
        </button>
    )
}

// ==========================================================================
// Command bar
// ==========================================================================

function Breadcrumb({ path, analysis }: { path: string; analysis: Analysis | null }) {
    if (!path) return null
    const parts = path.split(/[\\/]/).filter(Boolean)
    const last = parts.pop() || ""
    return (
        <div className="h-7 px-3 flex items-center gap-2 bg-[var(--color-al-surface)] border-b border-[var(--color-al-border)] mono text-[11px] text-[var(--color-al-text-mute)] overflow-hidden">
            <Icon name="folder" className="w-3 h-3 flex-shrink-0" />
            <span className="truncate">
                {parts.map((p, i) => (
                    <span key={i}>{p}<span className="text-[var(--color-al-text-dim)] mx-1">/</span></span>
                ))}
                <span className="text-[var(--color-al-accent)]">{last}</span>
            </span>
            {analysis && (
                <span className="ml-auto flex items-center gap-2 flex-shrink-0">
                    <span className="text-[var(--color-al-text)]">{analysis.pe.arch}</span>
                    <span className="text-[var(--color-al-text-dim)]">.</span>
                    <span className="text-[var(--color-al-text)]">{analysis.pe.is_dll ? "DLL" : "EXE"}</span>
                    <span className="text-[var(--color-al-text-dim)]">.</span>
                    <span className={analysis.verdict.packed ? "text-[var(--color-al-warn)]" : "text-[var(--color-al-ok)]"}>
                        {analysis.verdict.packed ? "PACKED" : "CLEAN"}
                    </span>
                </span>
            )}
        </div>
    )
}

function CommandBar({ path, setPath, onPick, onAnalyze, busy }: {
    path: string; setPath: (s: string) => void; onPick: () => void
    onAnalyze: () => void; busy: boolean
}) {
    return (
        <div className="flex items-center gap-2 px-3 py-2 border-b border-[var(--color-al-border)] bg-[var(--color-al-surface-2)]">
            <div className="flex-1 flex items-center bg-[var(--color-al-bg)] border border-[var(--color-al-border)] focus-within:border-[var(--color-al-accent)] h-8 px-2 gap-2">
                <Icon name="file" className="w-4 h-4 text-[var(--color-al-text-mute)]" />
                <input
                    value={path}
                    onChange={(e) => setPath(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter" && !busy) onAnalyze() }}
                    spellCheck={false}
                    className="flex-1 mono text-xs bg-transparent border-none focus:outline-none selectable-text"
                    placeholder="Absolute path to a PE file  (or drop a file anywhere on the window)"
                />
                {path && (
                    <button onClick={() => setPath("")} className="text-[var(--color-al-text-mute)] hover:text-[var(--color-al-text)]" title="Clear">
                        <Icon name="x" className="w-3.5 h-3.5" />
                    </button>
                )}
            </div>
            <button onClick={onPick} className="h-8 px-3 mono text-xs border border-[var(--color-al-border)] hover:border-[var(--color-al-accent-hi)] text-[var(--color-al-text-mute)] hover:text-[var(--color-al-accent-hi)] flex items-center gap-1.5">
                <Icon name="folder" className="w-3.5 h-3.5" /><span>Browse</span>
            </button>
            <button onClick={onAnalyze} disabled={busy || !path}
                className="h-8 px-4 mono text-xs bg-[var(--color-al-accent)] text-[var(--color-al-bg)] font-semibold hover:bg-[var(--color-al-accent-hi)] disabled:opacity-40 flex items-center gap-1.5">
                {busy ? <><Spinner /><span>Analyzing</span></>
                      : <><Icon name="analyze" className="w-3.5 h-3.5" /><span>Analyze</span></>}
            </button>
        </div>
    )
}
function Spinner() {
    return (
        <span className="inline-block w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full"
              style={{ animation: "spin 0.7s linear infinite" }} />
    )
}

// ==========================================================================
// Welcome screen (no analysis loaded yet)
// ==========================================================================
function Welcome({ onOpen, recent, onPickRecent }: {
    onOpen: () => void; recent: string[]; onPickRecent: (p: string) => void
}) {
    const bgRef = useRef<HTMLDivElement>(null)
    // Cursor tracking: sets --mx / --my on the background div; CSS radial-
    // gradient centered on that point paints the accent glow.
    function onMouseMove(e: React.MouseEvent<HTMLDivElement>) {
        const el = bgRef.current; if (!el) return
        const r = el.getBoundingClientRect()
        el.style.setProperty("--mx", `${e.clientX - r.left}px`)
        el.style.setProperty("--my", `${e.clientY - r.top}px`)
    }
    return (
        <div ref={bgRef} onMouseMove={onMouseMove}
             className="relative flex-1 min-h-0 flex items-center justify-center px-8 grid-bg overflow-hidden">
            <div className="absolute inset-0 pointer-events-none"
                 style={{
                     background: "radial-gradient(600px circle at var(--mx, 50%) var(--my, 50%), rgba(62,224,208,0.10), transparent 60%)",
                 }} />
            <div className="absolute inset-0 pointer-events-none constellation" />
            <div className="max-w-2xl w-full text-center">
                <img src="/logo.png" alt="" className="h-20 w-20 mx-auto mb-6 opacity-90" />
                <h2 className="text-2xl font-semibold tracking-wider mb-2">Welcome to Aletheia</h2>
                <p className="text-sm text-[var(--color-al-text-mute)] mb-8 max-w-md mx-auto">
                    Defensive reverse-engineering workbench. Drop a Windows PE (.exe / .dll / .sys)
                    onto the window, or open one from disk to get started.
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-6">
                    <ActionCard icon="folder" title="Open PE" desc="Pick a binary from disk" shortcut="Ctrl+O" onClick={onOpen} accent />
                    <ActionCard icon="sparkle" title="Try Sample"
                        desc="Analyze C:\Windows\System32\notepad.exe"
                        onClick={() => onPickRecent(String.raw`C:\Windows\System32\notepad.exe`)} />
                </div>
                {recent.length > 0 && (
                    <div className="text-left">
                        <h3 className="text-[10px] uppercase tracking-widest text-[var(--color-al-text-mute)] mb-2 flex items-center gap-1.5">
                            <Icon name="file" className="w-3 h-3" /> Recent
                        </h3>
                        <ul className="border border-[var(--color-al-border)]">
                            {recent.slice(0, 6).map((p, i) => (
                                <li key={i}>
                                    <button onClick={() => onPickRecent(p)}
                                        className="w-full flex items-center gap-3 px-3 py-2 text-left hover:bg-[var(--color-al-surface)] group">
                                        <Icon name="file" className="w-4 h-4 text-[var(--color-al-text-mute)] group-hover:text-[var(--color-al-accent)]" />
                                        <span className="text-sm truncate">{basename(p)}</span>
                                        <span className="mono text-[10px] text-[var(--color-al-text-mute)] truncate ml-auto max-w-[280px]">{p}</span>
                                    </button>
                                </li>
                            ))}
                        </ul>
                    </div>
                )}
                <p className="mt-8 text-[10px] text-[var(--color-al-text-mute)] mono">
                    Tip: drop a .exe anywhere on this window
                </p>
            </div>
        </div>
    )
}
function ActionCard({ icon, title, desc, shortcut, onClick, accent }: {
    icon: IconName; title: string; desc: string; shortcut?: string; onClick: () => void; accent?: boolean
}) {
    return (
        <button onClick={onClick}
            className={"clickable rise-on-hover text-left p-4 border flex gap-3 items-start " + (accent
                ? "border-[var(--color-al-accent)] bg-[var(--color-al-surface)] hover:bg-[var(--color-al-surface-2)]"
                : "border-[var(--color-al-border)] bg-[var(--color-al-surface)] hover:border-[var(--color-al-accent-hi)]")}>
            <span className={accent ? "text-[var(--color-al-accent)]" : "text-[var(--color-al-text-mute)]"}>
                <Icon name={icon} className="w-5 h-5" />
            </span>
            <div className="flex-1">
                <div className={"text-sm font-medium mb-0.5 " + (accent ? "text-[var(--color-al-accent)]" : "")}>{title}</div>
                <div className="text-xs text-[var(--color-al-text-mute)]">{desc}</div>
            </div>
            {shortcut && <span className="mono text-[10px] text-[var(--color-al-text-mute)] border border-[var(--color-al-border)] px-1.5 py-0.5">{shortcut}</span>}
        </button>
    )
}

// ==========================================================================
// Workbench + panes
// ==========================================================================
function Workbench({ analysis, disasm, selectedFn, setSelectedFn, busy, loadedPath }: {
    analysis: Analysis | null; disasm: DisasmView | null; busy: boolean
    selectedFn: number | null; setSelectedFn: (n: number | null) => void
    loadedPath: string | null
}) {
    // Rail widths persist per-viewer via localStorage. Wrapped in a try so a
    // sandboxed / cleared / cross-origin environment falls back to defaults
    // instead of throwing on mount.
    const [leftW,  setLeftW ] = useState(() => persistedNumber("al.leftW",  280, 200, 500))
    const [rightW, setRightW] = useState(() => persistedNumber("al.rightW", 340, 260, 560))
    useEffect(() => { try { localStorage.setItem("al.leftW",  String(leftW))  } catch {} }, [leftW])
    useEffect(() => { try { localStorage.setItem("al.rightW", String(rightW)) } catch {} }, [rightW])

    return (
        <div className="flex-1 min-h-0 flex fade-in">
            <div style={{ width: leftW, flexShrink: 0 }} className="min-h-0">
                <LeftRail analysis={analysis} disasm={disasm} busy={busy}
                          selectedFn={selectedFn} setSelectedFn={setSelectedFn} />
            </div>
            <Splitter direction="col" onDrag={d => setLeftW(w => clamp(w + d, 200, 500))} />
            <div className="flex-1 min-w-0 min-h-0">
                <Center disasm={disasm} busy={busy} loadedPath={loadedPath} selectedFn={selectedFn} />
            </div>
            <Splitter direction="col" onDrag={d => setRightW(w => clamp(w - d, 260, 560))} />
            <div style={{ width: rightW, flexShrink: 0 }} className="min-h-0">
                <RightRail analysis={analysis} busy={busy} loadedPath={loadedPath} />
            </div>
        </div>
    )
}

// ---------------------------------------------------------------------------
// Splitter — pane divider you drag to resize the rails / center split.
// direction="col" = vertical bar between horizontally-arranged panes (drag
//                   left/right); direction="row" = horizontal bar between
//                   vertically-stacked panes (drag up/down).
// The bar itself is 1px wide; the hit-target is 5px (using padding+negative
// margin so the layout stays exact-pixel).
// ---------------------------------------------------------------------------
function Splitter({ direction, onDrag }: { direction: "col" | "row"; onDrag: (delta: number) => void }) {
    // Pointer events + setPointerCapture bind the drag stream to the splitter
    // element itself. That's the fix for two related bugs from the old
    // window-listener implementation: (a) mouse-wheel on a scroll container
    // *under* the pointer during drag could steal focus / interrupt the
    // stream, and (b) letting up over a different iframe / element sometimes
    // never delivered mouseup at all.
    const last = useRef(0)
    const captured = useRef(false)
    const onPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
        e.preventDefault()
        e.stopPropagation()
        e.currentTarget.setPointerCapture(e.pointerId)
        captured.current = true
        last.current = direction === "col" ? e.clientX : e.clientY
        document.body.style.cursor = direction === "col" ? "col-resize" : "row-resize"
        document.body.style.userSelect = "none"
    }
    const onPointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
        if (!captured.current) return
        const now = direction === "col" ? e.clientX : e.clientY
        const delta = now - last.current
        last.current = now
        if (delta !== 0) onDrag(delta)
    }
    const onPointerUp = (e: React.PointerEvent<HTMLDivElement>) => {
        if (!captured.current) return
        captured.current = false
        try { e.currentTarget.releasePointerCapture(e.pointerId) } catch {}
        document.body.style.cursor = ""
        document.body.style.userSelect = ""
    }
    // 4px visible bar with hover/active accent + wider 8px hit target via
    // negative-inset overlay. `touch-none` prevents mobile-style pan-scroll
    // from intercepting the drag on hybrid devices.
    const cls = direction === "col"
        ? "w-1 shrink-0 bg-[var(--color-al-surface-3)] hover:bg-[var(--color-al-accent)] transition-colors relative cursor-col-resize touch-none"
        : "h-1 shrink-0 bg-[var(--color-al-surface-3)] hover:bg-[var(--color-al-accent)] transition-colors relative cursor-row-resize touch-none"
    const hitCls = direction === "col"
        ? "absolute inset-y-0 -left-1 -right-1"
        : "absolute inset-x-0 -top-1 -bottom-1"
    return (
        <div
            className={cls}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerCancel={onPointerUp}
            title={direction === "col" ? "Drag to resize the rails" : "Drag to resize the split — up shrinks the top pane, down grows it"}
        >
            <div className={hitCls} />
        </div>
    )
}
function clamp(v: number, lo: number, hi: number) { return Math.max(lo, Math.min(hi, v)) }
function persistedNumber(key: string, fallback: number, lo: number, hi: number): number {
    try {
        const v = localStorage.getItem(key)
        if (v == null) return fallback
        const n = Number(v)
        return Number.isFinite(n) ? clamp(n, lo, hi) : fallback
    } catch {
        return fallback
    }
}

function LeftRail({ analysis, disasm, busy, selectedFn, setSelectedFn }: {
    analysis: Analysis | null; disasm: DisasmView | null; busy: boolean
    selectedFn: number | null; setSelectedFn: (n: number | null) => void
}) {
    const [tab, setTab] = useState<"functions" | "sections">("functions")
    const [query, setQuery] = useState("")
    return (
        <div className="border-r border-[var(--color-al-border)] bg-[var(--color-al-surface)] flex flex-col min-h-0">
            <div className="flex items-center border-b border-[var(--color-al-border)]">
                <RailTab icon="target" label="Functions" active={tab === "functions"} onClick={() => setTab("functions")} />
                <RailTab icon="layers" label="Sections"  active={tab === "sections"}  onClick={() => setTab("sections")} />
            </div>
            <div className="px-2 pt-2 pb-1">
                <div className="flex items-center bg-[var(--color-al-bg)] border border-[var(--color-al-border)] focus-within:border-[var(--color-al-accent)] h-7 px-2 gap-1.5">
                    <Icon name="search" className="w-3 h-3 text-[var(--color-al-text-mute)]" />
                    <input value={query} onChange={(e) => setQuery(e.target.value)} spellCheck={false}
                        placeholder={tab === "functions" ? "filter functions..." : "filter sections..."}
                        className="flex-1 bg-transparent mono text-[11px] focus:outline-none selectable-text" />
                </div>
            </div>
            <div className="flex-1 min-h-0 overflow-y-auto">
                {busy && <SkeletonList rows={12} />}
                {!busy && tab === "functions" &&
                    <FunctionsList disasm={disasm} entry={analysis?.pe.entry_rva ?? 0}
                                   query={query} selected={selectedFn} onSelect={setSelectedFn} />}
                {!busy && tab === "sections" &&
                    <SectionsList sections={analysis?.pe.sections ?? []}
                                  entrySection={analysis?.pe.entry_section ?? null} query={query} />}
            </div>
        </div>
    )
}
function RailTab({ icon, label, active, onClick }: { icon: IconName; label: string; active: boolean; onClick: () => void }) {
    return (
        <button onClick={onClick}
            className={"px-3 h-9 text-xs font-medium uppercase tracking-wider flex items-center gap-1.5 " + (active
                ? "text-[var(--color-al-accent)] border-b-2 border-[var(--color-al-accent)]"
                : "text-[var(--color-al-text-mute)] hover:text-[var(--color-al-text)]")}>
            <Icon name={icon} className="w-3.5 h-3.5" />
            {label}
        </button>
    )
}
function SkeletonList({ rows }: { rows: number }) {
    return (
        <div className="py-1 px-3 space-y-1.5">
            {Array.from({ length: rows }).map((_, i) => (
                <div key={i} className="skeleton h-4" style={{ width: `${45 + ((i * 37) % 50)}%` }} />
            ))}
        </div>
    )
}

function FunctionsList({ disasm, entry, query, selected, onSelect }: {
    disasm: DisasmView | null; entry: number; query: string
    selected: number | null; onSelect: (n: number) => void
}) {
    const funcs = useMemo(() => {
        if (!disasm) return [] as { addr: number; xrefs: number; isEntry: boolean }[]
        const counts = new Map<number, number>()
        counts.set(entry, 0)
        for (const i of disasm.instructions) {
            if (i.is_call && i.target != null) counts.set(i.target, (counts.get(i.target) ?? 0) + 1)
        }
        const q = query.toLowerCase()
        return Array.from(counts.entries())
            .map(([a, c]) => ({ addr: a, xrefs: c, isEntry: a === entry }))
            .filter(f => !q || f.addr.toString(16).includes(q) || (f.isEntry && "entry".includes(q)))
            .sort((x, y) => x.addr - y.addr)
    }, [disasm, entry, query])
    if (!disasm) return <EmptyPane icon="target" msg="Analyze a binary to populate." />
    if (funcs.length === 0) return <EmptyPane icon="search" msg="No functions match." />
    return (
        <ul className="py-1">
            {funcs.map((f, i) => (
                <li key={i}>
                    <button onClick={() => onSelect(f.addr)}
                        className={"clickable w-full text-left flex items-center gap-2 mono text-xs px-3 py-1 " + (selected === f.addr
                            ? "bg-[var(--color-al-surface-2)] text-[var(--color-al-accent)] border-l-2 border-[var(--color-al-accent)]"
                            : "text-[var(--color-al-text)] hover:bg-[var(--color-al-surface-2)] border-l-2 border-transparent")}>
                        <Icon name="target" className="w-3 h-3 text-[var(--color-al-text-mute)] flex-shrink-0" />
                        <span className="flex-1 truncate">{addr(f.addr)}</span>
                        {f.isEntry && <Pill color="warn">entry</Pill>}
                        {f.xrefs > 0 && <Pill color="mute">{f.xrefs}x</Pill>}
                    </button>
                </li>
            ))}
        </ul>
    )
}

function SectionsList({ sections, entrySection, query }: {
    sections: Section[]; entrySection: string | null; query: string
}) {
    const filtered = useMemo(() => {
        const q = query.toLowerCase()
        return sections.filter(s => !q || s.name.toLowerCase().includes(q))
    }, [sections, query])
    if (sections.length === 0) return <EmptyPane icon="layers" msg="Analyze a binary to populate." />
    if (filtered.length === 0) return <EmptyPane icon="search" msg="No sections match." />
    return (
        <ul className="py-1">
            {filtered.map((s, i) => (
                <li key={i} className="clickable mono text-xs px-3 py-1.5 hover:bg-[var(--color-al-surface-2)]">
                    <div className="flex items-center gap-2 mb-1">
                        <Icon name="layers" className="w-3 h-3 text-[var(--color-al-text-mute)] flex-shrink-0" />
                        <span className="text-[var(--color-al-accent)] flex-1 truncate">{s.name}</span>
                        <span className="text-[var(--color-al-text-mute)] text-[10px]">{flags(s)}</span>
                        {s.name === entrySection && <Pill color="warn">entry</Pill>}
                    </div>
                    <EntropyBar entropy={s.entropy} />
                </li>
            ))}
        </ul>
    )
}
function EntropyBar({ entropy }: { entropy: number }) {
    const pct = Math.min(100, Math.max(0, (entropy / 8) * 100))
    const color = entropy >= 7.2 ? "var(--color-al-warn)"
                : entropy >= 6.5 ? "var(--color-al-accent-hi)"
                : "var(--color-al-text-mute)"
    return (
        <div className="flex items-center gap-2">
            <div className="flex-1 h-1 bg-[var(--color-al-bg)] border border-[var(--color-al-border)]">
                <div className="h-full" style={{ width: `${pct}%`, background: color }} />
            </div>
            <span className={"text-[10px] " + entropyClass(entropy)}>{entropy.toFixed(2)}</span>
        </div>
    )
}

function Center({ disasm, busy, loadedPath, selectedFn }: {
    disasm: DisasmView | null; busy: boolean; loadedPath: string | null; selectedFn: number | null
}) {
    // Top-pane height in pixels; bottom takes the remaining space. Persisted
    // so the layout the analyst set up carries across sessions.
    const [topH, setTopH] = useState(() => persistedNumber("al.centerTopH", 460, 160, 2000))
    useEffect(() => { try { localStorage.setItem("al.centerTopH", String(topH)) } catch {} }, [topH])
    // Which pane is on top. Drag either header onto the other to flip.
    const [decompileOnTop, setDecompileOnTop] = useState(
        () => persistedBool("al.decompileOnTop", false))
    useEffect(() => { try { localStorage.setItem("al.decompileOnTop", String(decompileOnTop)) } catch {} }, [decompileOnTop])
    const flip = () => setDecompileOnTop(v => !v)

    // Per-pane search queries + refs so Ctrl+F focuses the visible top pane.
    const [disasmQ, setDisasmQ]     = useState("")
    const [decompileQ, setDecompileQ] = useState("")
    const disasmFindRef    = useRef<HTMLInputElement>(null)
    const decompileFindRef = useRef<HTMLInputElement>(null)
    // Match-navigation state per pane.
    const disasmCount = countDisasmMatches(disasm, disasmQ)
    const disasmNav = useMatchNav(disasmQ, disasmCount)
    const [decompileCount, setDecompileCount] = useState(0)
    const decompileNav = useMatchNav(decompileQ, decompileCount)

    // Ctrl+F focuses the top pane's search input (whichever is on top after
    // any drag-swap). Wrapping this at the Center level means it works no
    // matter which pane is focused, without stealing Ctrl+F from platform
    // shortcuts elsewhere.
    useEffect(() => {
        const on = (e: KeyboardEvent) => {
            if ((e.ctrlKey || e.metaKey) && e.key === "f") {
                e.preventDefault()
                const target = decompileOnTop ? decompileFindRef.current : disasmFindRef.current
                target?.focus()
                target?.select()
            }
        }
        window.addEventListener("keydown", on)
        return () => window.removeEventListener("keydown", on)
    }, [decompileOnTop])

    // Track the container's real pixel height so we can clamp topH against
    // "container - MIN_BOTTOM" and prevent the bottom pane from disappearing
    // when the user drags below the visible area (the previous 160..2000
    // clamp was wall-clock, not window-relative — small windows would let
    // the user push the decompile off-screen).
    const containerRef = useRef<HTMLDivElement>(null)
    const [containerH, setContainerH] = useState(0)
    useEffect(() => {
        const el = containerRef.current
        if (!el) return
        setContainerH(el.clientHeight)
        const ro = new ResizeObserver(entries => {
            for (const e of entries) setContainerH(e.contentRect.height)
        })
        ro.observe(el)
        return () => ro.disconnect()
    }, [])
    const MIN_TOP = 120
    const MIN_BOTTOM = 120
    const SPLITTER_H = 4
    const maxTopH = Math.max(MIN_TOP, containerH - MIN_BOTTOM - SPLITTER_H)
    // Also clamp whenever the container shrinks so a resized window doesn't
    // strand topH above the new maximum.
    useEffect(() => {
        if (containerH > 0) setTopH(h => clamp(h, MIN_TOP, maxTopH))
    }, [containerH, maxTopH])

    const disasmRight = (
        <div className="flex items-center gap-3 ml-auto">
            {disasm && (
                <span className="mono text-[10px] text-[var(--color-al-text-mute)]">
                    {disasm.instructions.length} insn | {disasm.blocks.length} blocks | from {hex(disasm.base_rva)}
                </span>
            )}
            <FindInput ref={disasmFindRef} value={disasmQ} onChange={setDisasmQ} placeholder="find instr"
                       matchCount={disasmQ ? disasmCount : undefined} matchIdx={disasmNav.idx}
                       onNext={disasmNav.next} onPrev={disasmNav.prev} />
        </div>
    )
    const decompileRight = (
        <div className="flex items-center gap-3 ml-auto">
            <span className="mono text-[10px] text-[var(--color-al-text-mute)]">lightweight lowering</span>
            <FindInput ref={decompileFindRef} value={decompileQ} onChange={setDecompileQ} placeholder="find text"
                       matchCount={decompileQ ? decompileCount : undefined} matchIdx={decompileNav.idx}
                       onNext={decompileNav.next} onPrev={decompileNav.prev} />
        </div>
    )

    const disasmNode = (
        <Pane icon="cpu" title="Disassembly" right={disasmRight}
              dragKey="disasm" onSwap={flip}>
            {busy ? <SkeletonRows rows={16} /> : <Disasm disasm={disasm} query={disasmQ} matchIdx={disasmNav.idx} />}
        </Pane>
    )
    const decompileNode = (
        <Pane icon="sparkle" title="Decompile" right={decompileRight}
              dragKey="decompile" onSwap={flip}>
            {busy ? <SkeletonRows rows={6} /> : (
                <DecompilePane path={loadedPath} rva={selectedFn ?? (disasm ? disasm.base_rva : null)}
                               query={decompileQ} matchIdx={decompileNav.idx} onCount={setDecompileCount} />
            )}
        </Pane>
    )

    // NOTE: the intermediate wrapper divs MUST carry `flex flex-col` so the
    // inner Pane's `flex-1 min-h-0` correctly consumes the wrapper's height.
    // Without it, Pane doesn't fill the wrapper and its overflow container
    // sizes wrong — scrollbars disappear and the drag feels non-linear.
    return (
        <div ref={containerRef} className="flex flex-col min-h-0 h-full">
            <div style={{ height: topH, flexShrink: 0 }} className="min-h-0 flex flex-col">
                {decompileOnTop ? decompileNode : disasmNode}
            </div>
            <Splitter direction="row" onDrag={d => setTopH(h => clamp(h + d, MIN_TOP, maxTopH))} />
            <div className="flex-1 min-h-0 flex flex-col">
                {decompileOnTop ? disasmNode : decompileNode}
            </div>
        </div>
    )
}

// Discriminated over Rust's DecompiledFunction — { name, source, warnings[] }.
type Decompiled = { name: string; source: string; warnings: string[] }

/// Split `text` into React nodes with every case-insensitive occurrence of
/// `needle` wrapped in a `<mark>`. The `currentIdx`-th match gets a stronger
/// accent + a ref-attached wrapper for scroll-into-view. Preserves format
/// since it renders into a <pre>.
function renderHighlighted(
    text: string,
    needle: string,
    currentIdx: number,
    setCurrentRef: (el: HTMLElement | null) => void,
): React.ReactNode {
    if (!needle) return text
    const nodes: React.ReactNode[] = []
    const lower = text.toLowerCase()
    const q = needle.toLowerCase()
    let i = 0
    let matchNo = 0
    let key = 0
    while (i < text.length) {
        const idx = lower.indexOf(q, i)
        if (idx < 0) {
            nodes.push(text.slice(i))
            break
        }
        if (idx > i) nodes.push(text.slice(i, idx))
        const isCurrent = matchNo === currentIdx
        nodes.push(
            <mark
                key={key++}
                ref={isCurrent ? setCurrentRef : undefined}
                className={
                    isCurrent
                        ? "bg-[var(--color-al-accent)] text-[var(--color-al-surface)] rounded-sm outline outline-1 outline-[var(--color-al-accent-hi)]"
                        : "bg-[color-mix(in_srgb,var(--color-al-accent)_35%,transparent)] text-[var(--color-al-text)] rounded-sm"
                }
            >
                {text.slice(idx, idx + needle.length)}
            </mark>
        )
        matchNo++
        i = idx + needle.length
    }
    return <>{nodes}</>
}

/// Count case-insensitive occurrences of `needle` in `text`.
function countOccurrences(text: string, needle: string): number {
    if (!needle) return 0
    const t = text.toLowerCase()
    const n = needle.toLowerCase()
    let count = 0, i = 0
    while (true) {
        const idx = t.indexOf(n, i)
        if (idx < 0) break
        count++
        i = idx + n.length
    }
    return count
}

function DecompilePane({ path, rva, query, matchIdx, onCount }: {
    path: string | null; rva: number | null; query?: string
    matchIdx?: number; onCount?: (n: number) => void
}) {
    const [d, setD] = useState<Decompiled | null>(null)
    const [busy, setBusy] = useState(false)
    const [err, setErr] = useState<string | null>(null)
    const currentMatchRef = useRef<HTMLElement | null>(null)

    // Auto-fetch whenever the loaded file or selected function changes.
    useEffect(() => {
        if (!path || rva == null) { setD(null); return }
        setBusy(true); setErr(null); setD(null)
        invoke<Decompiled>("decompile_at", { path, addr: rva, count: 400 })
            .then(setD).catch(e => setErr(String(e))).finally(() => setBusy(false))
    }, [path, rva])

    // Compute + report match count whenever source or query changes.
    const src = d?.source ?? ""
    const q = (query || "").trim()
    const total = countOccurrences(src, q)
    useEffect(() => { onCount?.(total) }, [total, onCount])

    // Scroll current match into view when matchIdx changes.
    useEffect(() => {
        currentMatchRef.current?.scrollIntoView({ block: "nearest", behavior: "smooth" })
    }, [matchIdx, total])

    if (!path || rva == null) {
        return <EmptyPane icon="sparkle" msg="Open a file and select a function." />
    }
    if (busy) return <SkeletonRows rows={8} />
    if (err) {
        return (
            <div className="p-3 text-xs text-[var(--color-al-warn)] whitespace-pre-wrap font-mono">
                {err}
            </div>
        )
    }
    if (!d) return <EmptyPane icon="sparkle" msg="No decompile output." />

    const rendered: React.ReactNode = q
        ? renderHighlighted(src, q, (matchIdx ?? 0) % Math.max(1, total),
            (el) => { currentMatchRef.current = el })
        : src
    return (
        <div className="h-full overflow-auto">
            <pre className="p-3 text-[12px] leading-snug mono text-[var(--color-al-text)] whitespace-pre">
{rendered}
            </pre>
            {d.warnings.length > 0 && (
                <div className="px-3 pb-3 space-y-1">
                    {d.warnings.map((w, i) => (
                        <div key={i} className="text-[10px] text-[var(--color-al-text-mute)] leading-relaxed border-l-2 border-[var(--color-al-border)] pl-2">
                            {w}
                        </div>
                    ))}
                </div>
            )}
        </div>
    )
}
function SkeletonRows({ rows }: { rows: number }) {
    return (
        <div className="px-3 py-3 space-y-2">
            {Array.from({ length: rows }).map((_, i) => (
                <div key={i} className="flex gap-3">
                    <div className="skeleton h-3" style={{ width: 60 }} />
                    <div className="skeleton h-3" style={{ width: 140 }} />
                    <div className="skeleton h-3 flex-1" style={{ maxWidth: `${180 + ((i * 41) % 240)}px` }} />
                </div>
            ))}
        </div>
    )
}

type RightPaneKey = "verdict" | "pe" | "imports" | "dynamic"
const RIGHT_DEFAULT: RightPaneKey[] = ["verdict", "pe", "imports", "dynamic"]

function persistedOrder(key: string, fallback: RightPaneKey[]): RightPaneKey[] {
    try {
        const raw = localStorage.getItem(key)
        if (!raw) return fallback
        const arr = JSON.parse(raw) as RightPaneKey[]
        if (!Array.isArray(arr)) return fallback
        // Validate — same set as default, no dups. Fall back on any drift.
        const valid = new Set(RIGHT_DEFAULT)
        if (arr.length !== RIGHT_DEFAULT.length || !arr.every(k => valid.has(k)) || new Set(arr).size !== arr.length) {
            return fallback
        }
        return arr
    } catch {
        return fallback
    }
}

function RightRail({ analysis, busy, loadedPath }: { analysis: Analysis | null; busy: boolean; loadedPath: string | null }) {
    const [order, setOrder] = useState<RightPaneKey[]>(() => persistedOrder("al.rightOrder", RIGHT_DEFAULT))
    useEffect(() => { try { localStorage.setItem("al.rightOrder", JSON.stringify(order)) } catch {} }, [order])
    const move = (src: RightPaneKey, dst: RightPaneKey) => setOrder(o => {
        if (src === dst) return o
        const s = o.indexOf(src), d = o.indexOf(dst)
        if (s < 0 || d < 0) return o
        const next = o.slice()
        const [it] = next.splice(s, 1)
        next.splice(d, 0, it)
        return next
    })
    return (
        <div className="border-l border-[var(--color-al-border)] bg-[var(--color-al-surface)] flex flex-col min-h-0 overflow-y-auto">
            {busy ? (
                <div className="p-4 space-y-4">
                    <div className="skeleton h-16" />
                    <div className="skeleton h-32" />
                    <div className="skeleton h-32" />
                </div>
            ) : !analysis ? <EmptyPane icon="package" msg="No file loaded." /> : (
                <>
                    {order.map(k => (
                        <RightSection key={k} paneKey={k} onMove={move}
                            icon={rightSectionIcon(k)} title={rightSectionTitle(k, analysis)}>
                            {k === "verdict"  && <VerdictInside v={analysis.verdict} />}
                            {k === "pe"       && <PeHeaderInside pe={analysis.pe} />}
                            {k === "imports"  && <ImportsInside pe={analysis.pe} />}
                            {k === "dynamic"  && <DynamicInside path={loadedPath} isDll={analysis.pe.is_dll} />}
                        </RightSection>
                    ))}
                </>
            )}
        </div>
    )
}

function rightSectionIcon(k: RightPaneKey): IconName {
    switch (k) {
        case "verdict":  return "target"
        case "pe":       return "cpu"
        case "imports":  return "package"
        case "dynamic":  return "zap"
    }
}
function rightSectionTitle(k: RightPaneKey, a: Analysis): string {
    switch (k) {
        case "verdict":  return "Verdict"
        case "pe":       return "PE Header"
        case "imports":  return `Imports (${a.pe.import_func_count} / ${a.pe.import_dlls.length} DLLs)`
        case "dynamic":  return "Dynamic Analysis"
    }
}

function Pane({ icon, title, right, children, dragKey, onSwap }: {
    icon: IconName; title: string; right?: React.ReactNode; children: React.ReactNode
    /// Optional key identifying this pane for drag-and-drop reorder. When
    /// provided, the title-row becomes draggable and a drop-target: dropping
    /// another pane's key here calls `onSwap`.
    dragKey?: string
    onSwap?: () => void
}) {
    const [dragOver, setDragOver] = useState(false)
    const dragProps = dragKey ? {
        draggable: true,
        onDragStart: (e: React.DragEvent) => {
            e.dataTransfer.setData("application/x-aletheia-pane", dragKey)
            e.dataTransfer.effectAllowed = "move"
        },
        onDragOver: (e: React.DragEvent) => {
            if (e.dataTransfer.types.includes("application/x-aletheia-pane")) {
                e.preventDefault(); e.dataTransfer.dropEffect = "move"
                if (!dragOver) setDragOver(true)
            }
        },
        onDragLeave: () => setDragOver(false),
        onDrop: (e: React.DragEvent) => {
            e.preventDefault(); setDragOver(false)
            const src = e.dataTransfer.getData("application/x-aletheia-pane")
            if (src && src !== dragKey && onSwap) onSwap()
        },
    } : {}
    const headerCls = "h-8 px-3 flex items-center border-b border-[var(--color-al-border)] gap-2 panel-depth transition-colors "
        + (dragOver ? "bg-[color-mix(in_srgb,var(--color-al-accent)_18%,var(--color-al-surface-2))]" : "bg-[var(--color-al-surface-2)]")
        + (dragKey ? " cursor-grab active:cursor-grabbing" : "")
    return (
        <div className="flex flex-col flex-1 min-h-0 border-b border-[var(--color-al-border)] last:border-b-0">
            <div className={headerCls} {...dragProps}>
                <Icon name={icon} className="w-3.5 h-3.5 text-[var(--color-al-text-mute)] shrink-0" />
                <span className="text-xs font-semibold uppercase tracking-wider text-[var(--color-al-text-mute)] shrink-0">{title}</span>
                {/* Right slot renders as a div (not a span) so flex children */}
                {/* line up correctly and the FindInput match-counter doesn't */}
                {/* cause the header title to shift when it appears. */}
                <div className="ml-auto flex items-center min-w-0">{right}</div>
            </div>
            <div className="flex-1 min-h-0 overflow-hidden">{children}</div>
        </div>
    )
}

function persistedBool(key: string, fallback: boolean): boolean {
    try {
        const v = localStorage.getItem(key)
        if (v == null) return fallback
        return v === "true"
    } catch {
        return fallback
    }
}


// Break an operand string like "qword ptr [rip + 0x1234], rax" into colored
// tokens: registers, immediates, memory bracket regions, punctuation.
const _REGISTERS = new Set([
    "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","rip",
    "r8","r9","r10","r11","r12","r13","r14","r15",
    "eax","ebx","ecx","edx","esi","edi","ebp","esp","eip",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
    "ax","bx","cx","dx","si","di","bp","sp",
    "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w",
    "al","bl","cl","dl","ah","bh","ch","dh","sil","dil","bpl","spl",
    "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b",
    "cs","ds","es","fs","gs","ss",
])
function OpTokens({ text }: { text: string }) {
    if (!text) return null
    const nodes: React.ReactNode[] = []
    // Tokenize on identifiers, hex numbers, and single symbols. Keeping
    // whitespace + memory brackets so the render mirrors capstone/iced output.
    const re = /(0x[0-9a-fA-F]+|[a-zA-Z_][a-zA-Z_0-9]*|\s+|[\[\]\+\-\*,\(\)])/g
    let m: RegExpExecArray | null
    let key = 0
    let inMem = 0
    while ((m = re.exec(text)) !== null) {
        const t = m[0]
        if (t === "[") { inMem++; nodes.push(<span key={key++} style={{ color: "var(--color-al-op-punct)" }}>[</span>); continue }
        if (t === "]") { inMem = Math.max(0, inMem - 1); nodes.push(<span key={key++} style={{ color: "var(--color-al-op-punct)" }}>]</span>); continue }
        if (/^0x[0-9a-fA-F]+$/.test(t)) {
            nodes.push(<span key={key++} style={{ color: inMem ? "var(--color-al-op-mem)" : "var(--color-al-op-imm)" }}>{t}</span>)
        } else if (/^[a-zA-Z_][a-zA-Z_0-9]*$/.test(t)) {
            const low = t.toLowerCase()
            if (_REGISTERS.has(low)) {
                nodes.push(<span key={key++} style={{ color: "var(--color-al-op-reg)" }}>{t}</span>)
            } else if (low === "ptr" || low === "qword" || low === "dword" || low === "word" || low === "byte" || low === "xmmword" || low === "ymmword") {
                nodes.push(<span key={key++} className="text-[var(--color-al-text-mute)]">{t}</span>)
            } else {
                nodes.push(<span key={key++}>{t}</span>)
            }
        } else if (/^\s+$/.test(t)) {
            nodes.push(t)
        } else {
            nodes.push(<span key={key++} style={{ color: "var(--color-al-op-punct)" }}>{t}</span>)
        }
    }
    return <>{nodes}</>
}

function Disasm({ disasm, query, matchIdx }: { disasm: DisasmView | null; query?: string; matchIdx?: number }) {
    const rowRefs = useRef<Array<HTMLDivElement | null>>([])
    if (!disasm) return <EmptyPane icon="cpu" msg="Analyze a binary to populate." />
    const blockStarts = new Set(disasm.blocks.map(b => b.start))
    const q = (query || "").trim().toLowerCase()
    // Index list of matching instruction positions (into disasm.instructions).
    // Kept — even in highlight-all mode — so the parent knows how many hits
    // exist and can drive jump-to-match navigation via matchIdx.
    const matches: number[] = []
    if (q) {
        disasm.instructions.forEach((i, idx) => {
            if (addr(i.address).toLowerCase().includes(q)
                || i.bytes.toLowerCase().includes(q)
                || i.mnemonic.toLowerCase().includes(q)
                || i.op_str.toLowerCase().includes(q)) {
                matches.push(idx)
            }
        })
    }
    // On matchIdx change, scroll the corresponding row into view.
    const currentAbs = (q && matchIdx != null && matches.length) ? matches[matchIdx % matches.length] : -1
    useEffect(() => {
        if (currentAbs < 0) return
        const el = rowRefs.current[currentAbs]
        if (el) el.scrollIntoView({ block: "nearest", behavior: "smooth" })
    }, [currentAbs])
    const matchSet = new Set(matches)
    return (
        <div className="mono text-xs overflow-auto h-full selectable-text zebra">
            {matches.length === 0 && q && (
                <div className="p-3 text-[var(--color-al-text-mute)] text-[11px]">No instructions match "{q}".</div>
            )}
            {disasm.instructions.map((i, idx) => {
                const isMatch = matchSet.has(idx)
                const isCurrent = idx === currentAbs
                const rowCls = "flex gap-3 px-3 py-0.5 whitespace-nowrap "
                    + (isCurrent
                        ? "bg-[color-mix(in_srgb,var(--color-al-accent)_25%,transparent)] outline outline-1 outline-[var(--color-al-accent)]"
                        : isMatch
                        ? "bg-[color-mix(in_srgb,var(--color-al-accent)_10%,transparent)]"
                        : "hover:bg-[var(--color-al-surface)]")
                return (
                    <div key={idx} ref={el => { rowRefs.current[idx] = el }} className={rowCls}>
                        <span className="text-[var(--color-al-accent-hi)] w-3 text-center">
                            {blockStarts.has(i.address) ? "|" : ""}
                        </span>
                        <span className="text-[var(--color-al-text-mute)] w-24">{addr(i.address)}</span>
                        <span className="text-[var(--color-al-text-mute)] w-40 truncate">{i.bytes}</span>
                        <span className={"w-16 " + insnClass(i)}>{i.mnemonic}</span>
                        <span className={insnClass(i)}><OpTokens text={i.op_str} /></span>
                        {i.target != null && <span className="text-[var(--color-al-text-mute)] ml-auto">{"->"} {hex(i.target)}</span>}
                    </div>
                )
            })}
        </div>
    )
}

// Small hook: given a query and a live count, return a bounded match index +
// navigation callbacks. Resets to 0 whenever the query changes.
function useMatchNav(query: string, count: number) {
    const [idx, setIdx] = useState(0)
    useEffect(() => { setIdx(0) }, [query])
    useEffect(() => { if (idx >= count) setIdx(0) }, [count, idx])
    const next = useCallback(() => setIdx(i => count ? (i + 1) % count : 0), [count])
    const prev = useCallback(() => setIdx(i => count ? (i - 1 + count) % count : 0), [count])
    return { idx, next, prev }
}

// Compute the count of Disasm matches for a query, cheap linear scan matching
// Disasm's own predicate. Shared so Center can wire the FindInput without
// duplicating the search predicate.
function countDisasmMatches(disasm: DisasmView | null, q: string): number {
    if (!disasm || !q) return 0
    const l = q.toLowerCase()
    let n = 0
    for (const i of disasm.instructions) {
        if (addr(i.address).toLowerCase().includes(l)
            || i.bytes.toLowerCase().includes(l)
            || i.mnemonic.toLowerCase().includes(l)
            || i.op_str.toLowerCase().includes(l)) n++
    }
    return n
}

// Compact search input rendered inside a pane header. Supports jump-to-match
// navigation via callbacks: Enter -> onNext, Shift+Enter -> onPrev. Shows
// "N of M" when a match count is supplied.
const FindInput = forwardRef<HTMLInputElement, {
    value: string; onChange: (v: string) => void; placeholder?: string
    matchCount?: number; matchIdx?: number
    onNext?: () => void; onPrev?: () => void
}>(function FindInput({ value, onChange, placeholder, matchCount, matchIdx, onNext, onPrev }, ref) {
    return (
        <div className="ml-2 flex items-center gap-1.5 h-6 px-2 rounded border border-[var(--color-al-border)] bg-[var(--color-al-surface)] focus-within:border-[var(--color-al-accent)] transition-colors">
            <Icon name="search" className="w-3 h-3 text-[var(--color-al-text-mute)]" />
            <input
                ref={ref}
                value={value}
                onChange={e => onChange(e.target.value)}
                onKeyDown={e => {
                    if (e.key === "Escape") { onChange(""); e.currentTarget.blur() }
                    else if (e.key === "Enter") {
                        e.preventDefault()
                        if (e.shiftKey) onPrev?.(); else onNext?.()
                    }
                }}
                placeholder={placeholder ?? "find"}
                className="bg-transparent outline-none text-[10px] mono w-32 text-[var(--color-al-text)] placeholder:text-[var(--color-al-text-mute)]"
            />
            {value && matchCount != null && (
                <span className="text-[10px] mono text-[var(--color-al-text-mute)] tabular-nums text-right inline-block" style={{ minWidth: "3.5rem" }}>
                    {matchCount === 0 ? "0/0" : `${(matchIdx ?? 0) + 1}/${matchCount}`}
                </span>
            )}
            {value && onPrev && onNext && (
                <>
                    <button onClick={onPrev} className="text-[var(--color-al-text-mute)] hover:text-[var(--color-al-text)] text-[10px] px-0.5" title="Prev (Shift+Enter)">↑</button>
                    <button onClick={onNext} className="text-[var(--color-al-text-mute)] hover:text-[var(--color-al-text)] text-[10px] px-0.5" title="Next (Enter)">↓</button>
                </>
            )}
            {value && (
                <button
                    onClick={() => onChange("")}
                    className="text-[var(--color-al-text-mute)] hover:text-[var(--color-al-text)] text-[10px]"
                    title="Clear (Esc)"
                >×</button>
            )}
        </div>
    )
})

function VerdictInside({ v }: { v: Verdict }) {
    const color = v.packed && v.likely_packer ? "danger"
                : v.packed ? "warn"
                : "ok"
    const colorVar = color === "danger" ? "var(--color-al-danger)"
                   : color === "warn"   ? "var(--color-al-warn)"
                   : "var(--color-al-ok)"
    const confidence = v.packed ? v.confidence : 1 - v.confidence
    return (
        <div className="fade-in">
            <div className="relative px-4 py-3 border-l-2" style={{ borderLeftColor: colorVar }}>
                <div className="flex items-baseline justify-between gap-3">
                    <div>
                        <div className="text-[10px] uppercase tracking-widest text-[var(--color-al-text-mute)] mb-1">Verdict</div>
                        <div className="text-lg font-semibold" style={{ color: colorVar }}>
                            {v.packed ? "PACKED" : "LIKELY CLEAN"}
                        </div>
                        {v.likely_packer && (
                            <div className="mt-0.5 mono text-xs" style={{ color: colorVar }}>
                                {v.likely_packer}
                            </div>
                        )}
                    </div>
                    <div className="text-right">
                        <div className="text-[10px] uppercase tracking-widest text-[var(--color-al-text-mute)] mb-1">Confidence</div>
                        <div className="text-2xl font-semibold mono tabular-nums" style={{ color: colorVar }}>
                            {Math.round(confidence * 100)}<span className="text-sm text-[var(--color-al-text-mute)]">%</span>
                        </div>
                    </div>
                </div>
                <div className="mt-2 h-1 bg-[var(--color-al-bg)] border border-[var(--color-al-border)]">
                    <div className="h-full transition-all" style={{ width: `${Math.round(confidence * 100)}%`, background: colorVar }} />
                </div>
            </div>
            {v.signals.length > 0 && (
                <div className="border-t border-[var(--color-al-border)] px-4 py-2">
                    <div className="text-[10px] uppercase tracking-widest text-[var(--color-al-text-mute)] mb-1">
                        Signals ({v.signals.length})
                    </div>
                    <ul className="mono text-[10px] text-[var(--color-al-text-mute)] space-y-1 selectable-text">
                        {v.signals.map((s, i) => (
                            <li key={i} className="flex items-start gap-2">
                                <span className="mt-0.5" style={{ color: colorVar }}>-</span>
                                <span className="text-[var(--color-al-text)]">{s}</span>
                            </li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    )
}

function PeHeaderInside({ pe }: { pe: PeInfo }) {
    return (
        <table className="w-full mono text-xs fade-in">
            <tbody className="selectable-text">
                <KV k="arch"       v={pe.arch} />
                <KV k="kind"       v={(pe.is_dll ? "DLL" : "EXE") + (pe.is_dotnet ? " (.NET)" : "")} />
                <KV k="machine"    v={hex(pe.machine)} />
                <KV k="entry"      v={hex(pe.entry_rva)} />
                <KV k="entry sect" v={pe.entry_section ?? "(none)"} />
                <KV k="image base" v={hex(pe.image_base)} />
                <KV k="sections"   v={String(pe.n_sections)} />
                <KV k="entropy"    v={pe.overall_entropy.toFixed(2) + " b/B"} />
            </tbody>
        </table>
    )
}
function KV({ k, v }: { k: string; v: string }) {
    return (
        <tr className="hover:bg-[var(--color-al-surface-2)]">
            <td className="text-[var(--color-al-text-mute)] py-0.5 pl-4 pr-4 w-24">{k}</td>
            <td className="text-[var(--color-al-text)] pr-4">{v}</td>
        </tr>
    )
}

function ImportsInside({ pe }: { pe: PeInfo }) {
    if (pe.import_dlls.length === 0)
        return (
            <div className="px-4 py-3 mono text-xs text-[var(--color-al-warn)] flex items-center gap-2 fade-in">
                <Icon name="warning" className="w-3.5 h-3.5" /> no import table
            </div>
        )
    return (
        <ul className="mono text-[11px] text-[var(--color-al-text)] py-2 selectable-text fade-in">
            {pe.import_dlls.slice(0, 80).map((d, i) => (
                <li key={i} className="px-4 py-0.5 hover:bg-[var(--color-al-surface-2)] flex items-center gap-2">
                    <Icon name="package" className="w-3 h-3 text-[var(--color-al-text-mute)]" />
                    <span className="truncate">{d}</span>
                </li>
            ))}
            {pe.import_dlls.length > 80 && (
                <li className="px-4 py-1 text-[var(--color-al-text-mute)]">... {pe.import_dlls.length - 80} more</li>
            )}
        </ul>
    )
}

function RightSection({ icon, title, children, paneKey, onMove }: {
    icon: IconName; title: string; children: React.ReactNode
    paneKey?: RightPaneKey; onMove?: (src: RightPaneKey, dst: RightPaneKey) => void
}) {
    const [dragOver, setDragOver] = useState(false)
    const dragProps = (paneKey && onMove) ? {
        draggable: true,
        onDragStart: (e: React.DragEvent) => {
            e.dataTransfer.setData("application/x-aletheia-right", paneKey)
            e.dataTransfer.effectAllowed = "move"
        },
        onDragOver: (e: React.DragEvent) => {
            if (e.dataTransfer.types.includes("application/x-aletheia-right")) {
                e.preventDefault(); e.dataTransfer.dropEffect = "move"
                if (!dragOver) setDragOver(true)
            }
        },
        onDragLeave: () => setDragOver(false),
        onDrop: (e: React.DragEvent) => {
            e.preventDefault(); setDragOver(false)
            const src = e.dataTransfer.getData("application/x-aletheia-right") as RightPaneKey
            if (src && src !== paneKey) onMove(src, paneKey)
        },
    } : {}
    const headerCls = "h-8 px-4 flex items-center gap-2 border-b border-[var(--color-al-border)] panel-depth transition-colors "
        + (dragOver ? "bg-[color-mix(in_srgb,var(--color-al-accent)_18%,var(--color-al-surface-2))]" : "bg-[var(--color-al-surface-2)]")
        + (paneKey ? " cursor-grab active:cursor-grabbing" : "")
    return (
        <section className="border-b border-[var(--color-al-border)] flex flex-col shrink-0">
            <div className={headerCls} {...dragProps}>
                <span className="w-1 h-1 rounded-full bg-[var(--color-al-accent)]" />
                <Icon name={icon} className="w-3 h-3 text-[var(--color-al-text-mute)]" />
                <span className="text-[10px] font-semibold uppercase tracking-widest text-[var(--color-al-text-mute)]">{title}</span>
            </div>
            {/* Each right-rail section caps its own height and scrolls
                independently, so a huge Imports list can't push Verdict / PE /
                Dynamic Analysis off the top of the rail. max-h-80 (320px)
                fits ~40 rows at the current row density. */}
            <div className="max-h-80 overflow-y-auto">
                {children}
            </div>
        </section>
    )
}

function EmptyPane({ icon, msg }: { icon: IconName; msg: string }) {
    return (
        <div className="h-full flex flex-col items-center justify-center gap-2 text-xs text-[var(--color-al-text-mute)] px-4 text-center">
            <Icon name={icon} className="w-8 h-8 opacity-40" />
            {msg}
        </div>
    )
}

// ==========================================================================
// Pills, Toasts, Status
// ==========================================================================
function Pill({ children, color = "mute" }: {
    children: React.ReactNode; color?: "warn" | "danger" | "ok" | "accent" | "mute"
}) {
    const cls = {
        warn:   "border-[var(--color-al-warn)] text-[var(--color-al-warn)]",
        danger: "border-[var(--color-al-danger)] text-[var(--color-al-danger)]",
        ok:     "border-[var(--color-al-ok)] text-[var(--color-al-ok)]",
        accent: "border-[var(--color-al-accent)] text-[var(--color-al-accent)]",
        mute:   "border-[var(--color-al-border)] text-[var(--color-al-text-mute)]",
    }[color]
    return <span className={"mono text-[9px] px-1.5 py-0.5 border uppercase tracking-wider " + cls}>{children}</span>
}

function ToastStack({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
    return (
        <div className="fixed right-4 bottom-8 z-[100] flex flex-col gap-2 pointer-events-none">
            {toasts.map(t => {
                const icon: IconName = t.kind === "error" ? "warning" : t.kind === "ok" ? "check" : "info"
                const cls = t.kind === "error"
                    ? "border-[var(--color-al-danger)] text-[var(--color-al-danger)]"
                    : t.kind === "ok"
                        ? "border-[var(--color-al-ok)] text-[var(--color-al-ok)]"
                        : "border-[var(--color-al-accent)] text-[var(--color-al-accent)]"
                return (
                    <div key={t.id} className={"toast pointer-events-auto flex items-start gap-2 px-3 py-2 bg-[var(--color-al-surface)] border shadow-xl max-w-md " + cls}>
                        <Icon name={icon} className="w-4 h-4 flex-shrink-0 mt-0.5" />
                        <span className="text-xs text-[var(--color-al-text)] flex-1 selectable-text">{t.text}</span>
                        <button onClick={() => onDismiss(t.id)}
                            className="text-[var(--color-al-text-mute)] hover:text-[var(--color-al-text)]">
                            <Icon name="close" className="w-3.5 h-3.5" />
                        </button>
                    </div>
                )
            })}
        </div>
    )
}

function StatusBar({ analysis, disasm, engine, path, busy, phase }: {
    analysis: Analysis | null; disasm: DisasmView | null
    engine: EngineInfo | null; path: string; busy: boolean; phase: string
}) {
    return (
        <div className="h-6 px-3 flex items-center gap-3 bg-[var(--color-al-surface-2)] border-t border-[var(--color-al-border)] mono text-[10px] text-[var(--color-al-text-mute)]">
            {busy && <><Spinner /><span className="text-[var(--color-al-accent)]">{phase || "working"}</span><StatusSep /></>}
            <span className="text-[var(--color-al-accent)] truncate max-w-[280px]">{basename(path) || "(no file)"}</span>
            {analysis && <><StatusSep /><StatusPill>{analysis.pe.arch}</StatusPill><StatusPill>{analysis.pe.is_dll ? "DLL" : "EXE"}</StatusPill><StatusPill>{analysis.pe.n_sections} sect</StatusPill><StatusPill>{analysis.pe.import_func_count} imp</StatusPill></>}
            {disasm && <><StatusSep /><StatusPill>{disasm.instructions.length} insn / {disasm.blocks.length} blk</StatusPill></>}
            <span className="ml-auto flex items-center gap-1.5">
                <span className={engine ? "w-1.5 h-1.5 rounded-full bg-[var(--color-al-ok)]" : "w-1.5 h-1.5 rounded-full bg-[var(--color-al-danger)]"}></span>
                {engine ? `${engine.engine} ${engine.version} / ${engine.target_arch} ${engine.target_os}` : "engine offline"}
            </span>
        </div>
    )
}
function StatusSep() { return <span className="text-[var(--color-al-border-hi)] mx-1">|</span> }
function StatusPill({ children }: { children: React.ReactNode }) {
    return <span className="px-1.5 py-0.5 border border-[var(--color-al-border)] text-[var(--color-al-text)]">{children}</span>
}



function DynamicInside({ path, isDll }: { path: string | null; isDll: boolean }) {
    const [busy, setBusy] = useState(false)
    const [result, setResult] = useState<UnpackResult | null>(null)
    const [err, setErr] = useState<string | null>(null)

    async function run() {
        if (!path) return
        setBusy(true); setErr(null); setResult(null)
        try {
            const r = await invoke<UnpackResult>("run_unpack", { path, timeoutMs: 15000, maxSteps: 200000 })
            setResult(r)
        } catch (e) {
            setErr(String(e))
        } finally {
            setBusy(false)
        }
    }

    const hex = (n: number | null | undefined) =>
        n == null ? "-" : "0x" + n.toString(16).padStart(12, "0")

    return (
        <div className="p-3 text-xs space-y-3">
            <div className="text-[var(--color-al-text-mute)] leading-relaxed">
                Spawns the binary under a Win32 debugger and single-steps from
                its entry point. Fires when execution reaches memory that is
                <span className="mono text-[var(--color-al-text)]"> MEM_PRIVATE + PAGE_EXECUTE_*</span>
                &nbsp;and outside every loaded module &mdash; the write-then-execute
                signature of a self-unpacked payload jump.
                {isDll && (
                    <span className="block mt-1 text-[var(--color-al-accent)]">
                        DLL detected &mdash; will host via
                        <span className="mono"> rundll32.exe &lt;path&gt;,#1</span>
                        &nbsp;so <span className="mono">DllMain</span> runs.
                    </span>
                )}
            </div>
            <button
                onClick={run}
                disabled={busy || !path}
                title={!path ? "Open a file first (Ctrl+O)" : (isDll ? "Host the DLL via rundll32 and watch DllMain for a write-then-execute jump" : "Spawn the loaded EXE under the debugger and watch for a write-then-execute jump")}
                className="w-full h-8 rounded border border-[var(--color-al-border)] bg-[var(--color-al-surface-2)] hover:bg-[var(--color-al-surface-3)] disabled:opacity-50 disabled:cursor-not-allowed text-xs font-semibold uppercase tracking-wider transition"
            >
                {busy ? "Running..." : (isDll ? "Run dynamic unpack (via rundll32)" : "Run dynamic unpack")}
            </button>
            {!path && (
                <div className="rounded border border-[var(--color-al-border)] bg-[var(--color-al-surface-2)] p-2 text-[var(--color-al-text-mute)] text-[11px] leading-relaxed">
                    Open a file first (<span className="mono">Ctrl+O</span>) — this button spawns the loaded
                    binary as a child process under our debugger, so we need something loaded to run.
                </div>
            )}
            {err && (
                <div className="rounded border border-[var(--color-al-warn)] bg-[color-mix(in_srgb,var(--color-al-warn)_10%,transparent)] p-2 text-[var(--color-al-warn)]">
                    {err}
                </div>
            )}
            {result && (
                <div className="rounded border border-[var(--color-al-border)] bg-[var(--color-al-surface-2)] overflow-hidden">
                    <div className={"px-3 py-2 border-b border-[var(--color-al-border)] flex items-center gap-2 " + (result.detected ? "bg-[color-mix(in_srgb,var(--color-al-warn)_18%,transparent)]" : "bg-[color-mix(in_srgb,var(--color-al-ok)_10%,transparent)]")}>
                        <span className={"text-[11px] font-bold uppercase tracking-wider " + (result.detected ? "text-[var(--color-al-warn)]" : "text-[var(--color-al-ok)]")}>
                            {result.detected ? "Unpack detected" : (result.gave_up ? "No unpack observed" : "Clean exit")}
                        </span>
                    </div>
                    <div className="p-3 space-y-1 mono text-[11px] text-[var(--color-al-text-mute)]">
                        <div><span className="text-[var(--color-al-text-dim)]">OEP:</span> <span className="text-[var(--color-al-text)]">{hex(result.oep)}</span></div>
                        <div><span className="text-[var(--color-al-text-dim)]">main_base:</span> <span className="text-[var(--color-al-text)]">{hex(result.main_base)}</span></div>
                        <div><span className="text-[var(--color-al-text-dim)]">exit_code:</span> <span className="text-[var(--color-al-text)]">{result.exit_code ?? "-"}</span></div>
                        {result.oep != null && result.main_base > 0 && (
                            <div><span className="text-[var(--color-al-text-dim)]">OEP - main_base:</span> <span className="text-[var(--color-al-text)]">{hex(result.oep - result.main_base)}</span></div>
                        )}
                        <div className="pt-1 text-[var(--color-al-text-mute)] leading-relaxed">{result.reason}</div>
                    </div>
                    {result.events && result.events.length > 0 && (
                        <div className="border-t border-[var(--color-al-border)] p-3 mono text-[10px] leading-relaxed">
                            <div className="text-[var(--color-al-text-mute)] uppercase tracking-widest mb-1.5 text-[9px]">
                                Events ({result.events.length})
                            </div>
                            <div className="space-y-1 max-h-40 overflow-y-auto">
                                {result.events.map((e: RunEvent, i: number) => (
                                    <div key={i} className="text-[var(--color-al-text)]">
                                        {e.kind === "Alloc"
                                          ? <><span className="text-[var(--color-al-accent)]">Alloc</span>{"  "}size={hex(e.size)} protect={hex(e.protect)}</>
                                          : e.kind === "ProtectFlipToX"
                                          ? <><span className="text-[var(--color-al-warn)]">ProtectFlipToX</span>{"  "}addr={hex(e.addr)} size={hex(e.size)}</>
                                          : e.kind === "ThreadFromNonImage"
                                          ? <><span className="text-[var(--color-al-warn)]">ThreadCreate</span>{"  "}start={hex(e.start)}</>
                                          : /* Wrote */
                                            <><span className="text-[var(--color-al-text-mute)]">Wrote</span>{"  "}page={hex(e.page)}</>
                                        }
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    )
}

// Discriminated union mirroring the Rust `UnpackEvent` tagged enum from
// aletheia-core::unpack. Serde emits `{ "kind": "Alloc", ... }`.
type RunEvent =
    | { kind: "Alloc"; addr: number; size: number; protect: number }
    | { kind: "ProtectFlipToX"; addr: number; size: number; old_protect: number; new_protect: number; dumped: string }
    | { kind: "ThreadFromNonImage"; start: number }
    | { kind: "Wrote"; page: number }

