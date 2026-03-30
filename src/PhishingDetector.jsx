import { useState, useRef } from "react";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";

const EXAMPLES = [
  { label: "✅ Safe: GitHub", val: "https://github.com/anthropics/anthropic-sdk-python", type: "url" },
  { label: "✅ Safe: Wikipedia", val: "https://en.wikipedia.org/wiki/Phishing", type: "url" },
  { label: "🚨 Phishing: PayPal fake", val: "http://paypal-secure-login.verify-account.xyz/signin?user=victim", type: "url" },
  { label: "🚨 Phishing: Amazon fake", val: "http://amazon-account-suspended.click-verify.com/restore?id=9823", type: "url" },
  { label: "🚨 Phishing: Email", val: "URGENT: Your account has been suspended. Verify credentials at secure-login.verify-billing-account.net immediately.", type: "email" },
];

export default function PhishingDetector() {
  const [input, setInput] = useState("");
  const [inputType, setInputType] = useState("url");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [activeTab, setActiveTab] = useState("scanner");
  const [scanCount, setScanCount] = useState(0);
  const inputRef = useRef(null);

  const safeCount = history.filter(h => h.label === "safe").length;
  const phishCount = history.filter(h => h.label === "phishing").length;

  const handleScan = async () => {
    const text = input.trim();
    if (!text) { setError("Please enter a URL or email text."); return; }
    if (text.length < 3) { setError("Input too short."); return; }
    if (text.length > 2000) { setError("Input too long (max 2000 chars)."); return; }

    setLoading(true); setError(null); setResult(null);

    try {
      const response = await fetch(`${API_URL}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, type: inputType }),
      });

      if (response.status === 429) throw new Error("Too many requests. Please wait a moment.");
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.error || `Server error (${response.status})`);
      }

      const data = await response.json();
      const enriched = {
        ...data,
        input: text,
        inputType,
        timestamp: new Date().toLocaleTimeString(),
      };
      setResult(enriched);
      setScanCount(c => c + 1);
      setHistory(h => [enriched, ...h].slice(0, 10));
    } catch (e) {
      if (e.message.toLowerCase().includes("fetch") || e.message.toLowerCase().includes("failed")) {
        setError(`Cannot connect to API at ${API_URL}. Make sure the backend is running.`);
      } else {
        setError(e.message || "Scan failed. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  const clearAll = () => {
    setInput(""); setResult(null); setError(null);
    inputRef.current?.focus();
  };

  const C = {
    bg: "#080c10", border: "#1c2128",
    green: "#00ff88", cyan: "#00d4ff", red: "#ff4444",
    text: "#e2e8f0", muted: "#64748b", dim: "#3d4a57",
  };

  return (
    <div style={{ minHeight: "100vh", background: `linear-gradient(135deg, ${C.bg} 0%, #0d1117 50%, #0a0f1a 100%)`, fontFamily: "'IBM Plex Mono','Courier New',monospace", color: C.text }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes slideIn { from { transform: translateY(14px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
        @keyframes glowPulse { 0%,100% { box-shadow: 0 0 8px rgba(0,255,136,0.3); } 50% { box-shadow: 0 0 24px rgba(0,255,136,0.7); } }
        .grid-bg { position: fixed; inset: 0; background-image: linear-gradient(rgba(0,255,136,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,136,0.025) 1px, transparent 1px); background-size: 40px 40px; pointer-events: none; }
        .scan-btn { background: linear-gradient(135deg, #00ff88, #00d4ff); border: none; color: #000; font-family: 'IBM Plex Mono', monospace; font-weight: 700; font-size: 12px; letter-spacing: 2px; padding: 13px 28px; cursor: pointer; transition: all 0.2s; clip-path: polygon(6px 0%, 100% 0%, calc(100% - 6px) 100%, 0% 100%); }
        .scan-btn:hover:not(:disabled) { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0,255,136,0.4); }
        .scan-btn:disabled { opacity: 0.4; cursor: not-allowed; }
        .tab { background: transparent; border: none; border-bottom: 2px solid transparent; color: #64748b; font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: 1.5px; padding: 8px 14px; cursor: pointer; transition: all 0.2s; text-transform: uppercase; }
        .tab.on { color: #00ff88; border-bottom-color: #00ff88; }
        .tab:hover:not(.on) { color: #94a3b8; }
        .inp { width: 100%; background: rgba(255,255,255,0.025); border: 1px solid #1c2128; border-radius: 4px; color: #e2e8f0; font-family: 'IBM Plex Mono', monospace; font-size: 12px; padding: 13px 15px; outline: none; transition: border-color 0.2s, box-shadow 0.2s; resize: vertical; }
        .inp:focus { border-color: rgba(0,255,136,0.4); box-shadow: 0 0 0 3px rgba(0,255,136,0.06); }
        .inp::placeholder { color: #2d3748; }
        .ex-btn { background: rgba(255,255,255,0.02); border: 1px solid #1c2128; border-radius: 3px; color: #4a5568; font-family: 'IBM Plex Mono', monospace; font-size: 10px; padding: 5px 9px; cursor: pointer; transition: all 0.15s; white-space: nowrap; }
        .ex-btn:hover { border-color: rgba(0,255,136,0.3); color: #94a3b8; }
        .result { animation: slideIn 0.35s ease forwards; }
        .hist-row { transition: background 0.15s; cursor: pointer; border-radius: 5px; }
        .hist-row:hover { background: rgba(255,255,255,0.025); }
        .blink { animation: pulse 2s infinite; }
        .bar-fill { height: 100%; border-radius: 2px; transition: width 0.9s ease; }
      `}</style>

      <div className="grid-bg" />

      <div style={{ position: "relative", zIndex: 1, maxWidth: 860, margin: "0 auto", padding: "28px 18px" }}>

        {/* Header */}
        <header style={{ marginBottom: 28 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 10 }}>
            <div style={{ width: 38, height: 38, border: `2px solid ${C.green}`, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 17, position: "relative", flexShrink: 0, boxShadow: `0 0 12px ${C.green}33` }}>
              <div style={{ position: "absolute", inset: -7, border: "1px solid rgba(0,255,136,0.15)", borderRadius: "50%" }} className="blink" />
              🛡️
            </div>
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, color: C.green, letterSpacing: 2 }}>PHISHGUARD AI</div>
              <div style={{ fontSize: 9, color: C.dim, letterSpacing: 1.5 }}>REAL-TIME THREAT DETECTION · Flask + RandomForest ML · v2.4</div>
            </div>
            <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
              {[[scanCount, "TOTAL", C.cyan], [safeCount, "SAFE", C.green], [phishCount, "THREATS", C.red]].map(([v, l, c]) => (
                <div key={l} style={{ background: "rgba(255,255,255,0.025)", border: `1px solid ${C.border}`, borderRadius: 4, padding: "5px 10px", textAlign: "center", minWidth: 52 }}>
                  <div style={{ fontSize: 15, fontWeight: 700, color: c }}>{v}</div>
                  <div style={{ fontSize: 8, color: C.dim, letterSpacing: 1.5 }}>{l}</div>
                </div>
              ))}
            </div>
          </div>

          {/* API status bar */}
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: C.green, boxShadow: `0 0 6px ${C.green}`, animation: "pulse 2s infinite" }} />
            <span style={{ fontSize: 9, color: C.dim, letterSpacing: 1.5 }}>
              API · {API_URL} · RANDOMFOREST MODEL ACTIVE
            </span>
          </div>

          <div style={{ height: 1, background: `linear-gradient(90deg, ${C.green}44, ${C.cyan}22, transparent)` }} />
        </header>

        {/* Tabs */}
        <div style={{ display: "flex", borderBottom: `1px solid ${C.border}`, marginBottom: 22 }}>
          {[["scanner", "⚡ Scanner"], ["history", `📋 History (${history.length})`], ["about", "ℹ About"]].map(([t, l]) => (
            <button key={t} className={`tab ${activeTab === t ? "on" : ""}`} onClick={() => setActiveTab(t)}>{l}</button>
          ))}
        </div>

        {/* SCANNER TAB */}
        {activeTab === "scanner" && (
          <div>
            <div style={{ background: "rgba(255,255,255,0.018)", border: `1px solid ${C.border}`, borderRadius: 7, padding: 18, marginBottom: 18 }}>

              <div style={{ display: "flex", gap: 6, marginBottom: 11, alignItems: "center" }}>
                {[["url", "🔗 URL"], ["email", "📧 Email"]].map(([t, l]) => (
                  <button key={t} onClick={() => setInputType(t)} style={{ background: inputType === t ? "rgba(0,255,136,0.09)" : "transparent", border: `1px solid ${inputType === t ? "rgba(0,255,136,0.35)" : C.border}`, borderRadius: 3, color: inputType === t ? C.green : C.muted, fontFamily: "'IBM Plex Mono',monospace", fontSize: 10, letterSpacing: 1.5, padding: "5px 11px", cursor: "pointer", transition: "all 0.15s" }}>{l}</button>
                ))}
                <span style={{ marginLeft: "auto", fontSize: 9, color: C.dim }}>{input.length}/2000</span>
              </div>

              {inputType === "url"
                ? <input ref={inputRef} className="inp" placeholder="https://example.com/path?query=value" value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => { if (e.key === "Enter" && !loading) handleScan(); }} spellCheck={false} autoComplete="off" />
                : <textarea ref={inputRef} className="inp" placeholder="Paste suspicious email text here..." value={input} onChange={e => setInput(e.target.value)} rows={4} spellCheck={false} />
              }

              <div style={{ display: "flex", gap: 8, marginTop: 11, alignItems: "center" }}>
                <button className="scan-btn" onClick={handleScan} disabled={loading || !input.trim()}>
                  {loading
                    ? <><span style={{ display: "inline-block", width: 11, height: 11, border: "2px solid #000", borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.7s linear infinite", marginRight: 7, verticalAlign: "middle" }} />ANALYZING…</>
                    : "▶ SCAN NOW"}
                </button>
                {(input || result) && (
                  <button onClick={clearAll} style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: 3, color: C.muted, fontFamily: "'IBM Plex Mono',monospace", fontSize: 11, padding: "9px 14px", cursor: "pointer", transition: "color 0.2s" }}
                    onMouseEnter={e => e.target.style.color = C.text}
                    onMouseLeave={e => e.target.style.color = C.muted}>
                    ✕ Clear
                  </button>
                )}
                {inputType === "url" && <span style={{ fontSize: 9, color: C.dim, marginLeft: "auto" }}>↵ Enter to scan</span>}
              </div>
            </div>

            {/* Examples */}
            {!result && !loading && (
              <div style={{ marginBottom: 18 }}>
                <div style={{ fontSize: 9, color: C.dim, letterSpacing: 1.5, marginBottom: 7 }}>QUICK TEST EXAMPLES:</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                  {EXAMPLES.map(ex => (
                    <button key={ex.val} className="ex-btn" onClick={() => { setInput(ex.val); setInputType(ex.type); }}>{ex.label}</button>
                  ))}
                </div>
              </div>
            )}

            {/* Error */}
            {error && (
              <div style={{ background: "rgba(255,68,68,0.07)", border: "1px solid rgba(255,68,68,0.3)", borderRadius: 6, padding: "11px 15px", marginBottom: 14, animation: "slideIn 0.3s ease" }}>
                <div style={{ display: "flex", gap: 9, alignItems: "flex-start" }}>
                  <span style={{ fontSize: 13, flexShrink: 0 }}>⚠️</span>
                  <div>
                    <div style={{ fontSize: 11, color: "#ff6666", marginBottom: 4 }}>{error}</div>
                    {error.includes("connect") && (
                      <div style={{ fontSize: 10, color: C.muted }}>Backend: <span style={{ color: C.cyan }}>{API_URL}</span></div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Loading */}
            {loading && (
              <div style={{ background: "rgba(0,212,255,0.04)", border: "1px solid rgba(0,212,255,0.15)", borderRadius: 8, padding: 28, textAlign: "center" }}>
                <div style={{ width: 48, height: 48, margin: "0 auto 14px", border: "2px solid rgba(0,212,255,0.12)", borderTop: `2px solid ${C.cyan}`, borderRadius: "50%", animation: "spin 0.75s linear infinite" }} />
                <div style={{ fontSize: 11, color: C.cyan, letterSpacing: 2, marginBottom: 5 }}>ANALYZING THREAT SIGNATURES</div>
                <div style={{ fontSize: 10, color: C.dim }}>Extracting 28 features · Running RandomForest · Calculating risk score</div>
              </div>
            )}

            {/* Result */}
            {result && !loading && <ResultCard result={result} />}
          </div>
        )}

        {/* HISTORY TAB */}
        {activeTab === "history" && (
          <div>
            {history.length === 0
              ? <div style={{ textAlign: "center", padding: "56px 20px", color: C.dim }}><div style={{ fontSize: 28, marginBottom: 10 }}>📋</div><div style={{ fontSize: 11 }}>No scans yet.</div></div>
              : (
                <>
                  <div style={{ fontSize: 9, color: C.dim, letterSpacing: 1.5, marginBottom: 10 }}>RECENT SCANS — {history.length} RESULTS</div>
                  {history.map((h, i) => (
                    <div key={i} className="hist-row" onClick={() => { setInput(h.input); setInputType(h.inputType || "url"); setResult(h); setActiveTab("scanner"); }}
                      style={{ border: `1px solid ${C.border}`, borderRadius: 5, padding: "11px 14px", marginBottom: 7, display: "flex", alignItems: "center", gap: 11 }}>
                      <div style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: h.label === "phishing" ? C.red : C.green, boxShadow: `0 0 5px ${h.label === "phishing" ? C.red : C.green}` }} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 11, color: "#94a3b8", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{h.input}</div>
                      </div>
                      <div style={{ display: "flex", gap: 7, alignItems: "center", flexShrink: 0 }}>
                        <span style={{ fontSize: 9, letterSpacing: 1, padding: "2px 7px", borderRadius: 2, background: h.label === "phishing" ? "rgba(255,68,68,0.12)" : "rgba(0,255,136,0.08)", color: h.label === "phishing" ? "#ff6666" : C.green, border: `1px solid ${h.label === "phishing" ? "rgba(255,68,68,0.25)" : "rgba(0,255,136,0.25)"}` }}>
                          {h.label.toUpperCase()}
                        </span>
                        <span style={{ fontSize: 9, color: C.dim }}>{Math.round((h.confidence || 0) * 100)}%</span>
                        <span style={{ fontSize: 9, color: C.dim }}>{h.timestamp}</span>
                      </div>
                    </div>
                  ))}
                </>
              )
            }
          </div>
        )}

        {/* ABOUT TAB */}
        {activeTab === "about" && (
          <div style={{ fontSize: 12, color: "#64748b", lineHeight: 1.8 }}>
            <AboutSection title="HOW IT WORKS" color={C.green}>
              <p>Your input is sent to the <strong style={{ color: C.text }}>Flask API</strong> which extracts <strong style={{ color: C.text }}>28 features</strong> and runs them through a <strong style={{ color: C.text }}>RandomForest classifier</strong> (300 trees, ~96% accuracy). Results return in milliseconds with a confidence score and risk level.</p>
            </AboutSection>
            <AboutSection title="28 EXTRACTED FEATURES" color={C.cyan}>
              {[
                ["Length signals", "Total/domain/path length, slash count, dot count"],
                ["Special chars", "@ symbols, hyphens, URL encoding, query params"],
                ["Keyword matching", "34 terms: login, verify, urgent, suspended, billing..."],
                ["Domain trust", "Matched against 16 known-safe domains"],
                ["IP detection", "Direct IP address instead of domain = red flag"],
                ["Subdomain depth", "many.nested.sub.domains.evil.com = suspicious"],
                ["Brand mismatch", "paypal in path but NOT in domain = impersonation"],
                ["Entropy", "Random-looking domain names score high"],
              ].map(([k, v]) => (
                <div key={k} style={{ display: "flex", gap: 12, marginBottom: 5 }}>
                  <span style={{ color: C.cyan, minWidth: 140, flexShrink: 0 }}>{k}</span>
                  <span>{v}</span>
                </div>
              ))}
            </AboutSection>
            <AboutSection title="DEPLOYMENT" color={C.green}>
              <p>Frontend on <strong style={{ color: C.text }}>Vercel</strong>. Backend Flask API on <strong style={{ color: C.text }}>Railway</strong> at <span style={{ color: C.cyan }}>{API_URL}</span>.</p>
            </AboutSection>
            <AboutSection title="STACK" color={C.cyan}>
              <p>React 18 · Vite · Python 3.11 · Flask 3.0 · scikit-learn · RandomForest · joblib · Flask-Limiter · Railway · Vercel</p>
            </AboutSection>
            <div style={{ background: "rgba(0,255,136,0.04)", border: "1px solid rgba(0,255,136,0.15)", borderRadius: 6, padding: 12 }}>
              <strong style={{ color: C.green }}>⚠ Note:</strong> For higher accuracy in production, supplement with real phishing datasets from PhishTank or OpenPhish.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function AboutSection({ title, color, children }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ fontSize: 10, color, letterSpacing: 2, marginBottom: 8, fontWeight: 600 }}>{title}</div>
      {children}
    </div>
  );
}

function ResultCard({ result }) {
  const isPhish = result.label === "phishing";
  const conf = Math.round((result.confidence || 0) * 100);
  const pProb = Math.round((result.phishing_probability || 0) * 100);
  const sProb = Math.round((result.safe_probability || 0) * 100);

  const pal = {
    high: { bg: "rgba(255,68,68,0.07)", border: "rgba(255,68,68,0.4)", text: "#ff4444", accent: "#ff6666" },
    medium: { bg: "rgba(255,170,0,0.07)", border: "rgba(255,170,0,0.4)", text: "#ffaa00", accent: "#ffcc44" },
    low: { bg: "rgba(0,255,136,0.05)", border: "rgba(0,255,136,0.3)", text: "#00ff88", accent: "#00ff88" },
  };
  const p = pal[result.risk_level] || pal.low;

  return (
    <div className="result" style={{ background: p.bg, border: `1px solid ${p.border}`, borderRadius: 8, overflow: "hidden" }}>

      {/* Banner */}
      <div style={{ padding: "15px 18px", borderBottom: `1px solid ${p.border}44`, display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ width: 44, height: 44, borderRadius: "50%", background: `${p.text}1a`, border: `2px solid ${p.text}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, flexShrink: 0, boxShadow: `0 0 14px ${p.text}44`, animation: isPhish ? "glowPulse 2s infinite" : "none" }}>
          {isPhish ? "🚨" : "✅"}
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 18, fontWeight: 700, color: p.accent }}>{isPhish ? "PHISHING DETECTED" : "SAFE TO PROCEED"}</div>
          <div style={{ fontSize: 10, color: "#64748b", marginTop: 2, letterSpacing: 1 }}>
            RISK: <span style={{ color: p.text }}>{(result.risk_level || "").toUpperCase()}</span>
            {" · "}CONFIDENCE: <span style={{ color: p.text }}>{conf}%</span>
            {result.elapsed_ms && <span style={{ color: "#3d4a57" }}> · {result.elapsed_ms}ms</span>}
          </div>
        </div>
        <div style={{ fontSize: 32, fontWeight: 700, color: p.accent }}>{conf}%</div>
      </div>

      {/* Probability bars */}
      <div style={{ padding: "14px 18px", borderBottom: `1px solid ${p.border}22` }}>
        {[
          [pProb, "⚠ PHISHING PROBABILITY", "#ff4444", "linear-gradient(90deg,#ff4444,#ff7777)"],
          [sProb, "✓ SAFE PROBABILITY", "#00ff88", "linear-gradient(90deg,#00ff88,#00d4ff)"],
        ].map(([v, lbl, tc, fill]) => (
          <div key={lbl} style={{ marginBottom: v === pProb ? 10 : 0 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
              <span style={{ fontSize: 9, color: tc, letterSpacing: 1 }}>{lbl}</span>
              <span style={{ fontSize: 9, color: tc }}>{v}%</span>
            </div>
            <div style={{ height: 4, borderRadius: 2, background: "#21262d", overflow: "hidden" }}>
              <div className="bar-fill" style={{ width: `${v}%`, background: fill }} />
            </div>
          </div>
        ))}
      </div>

      {/* Input preview */}
      <div style={{ padding: "12px 18px", borderBottom: `1px solid ${p.border}22` }}>
        <div style={{ fontSize: 9, color: "#64748b", letterSpacing: 1.5, marginBottom: 5 }}>SCANNED INPUT:</div>
        <div style={{ fontSize: 10, color: "#94a3b8", wordBreak: "break-all", background: "rgba(0,0,0,0.2)", padding: "6px 10px", borderRadius: 3, borderLeft: `2px solid ${p.text}` }}>
          {result.input}
        </div>
      </div>

      {/* Stats */}
      <div style={{ padding: "12px 18px", display: "flex", gap: 16, flexWrap: "wrap" }}>
        {[
          ["INPUT LENGTH", `${result.input_length} chars`],
          ["RESPONSE TIME", `${result.elapsed_ms}ms`],
          ["MODEL", "RandomForest"],
          ["FEATURES", "28 signals"],
        ].map(([k, v]) => (
          <div key={k}>
            <div style={{ fontSize: 8, color: "#3d4a57", letterSpacing: 1.5, marginBottom: 2 }}>{k}</div>
            <div style={{ fontSize: 11, color: "#64748b" }}>{v}</div>
          </div>
        ))}
      </div>
    </div>
  );
}