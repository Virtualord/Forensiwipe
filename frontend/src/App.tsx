import { useEffect, useState } from "react";
import {
  Activity,
  FileSearch,
  HardDrive,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { api, Audit, Operation, SystemStatus } from "./api";
type View = "overview" | "erase" | "files" | "carve" | "audit";
const Nav = ({ view, setView }: { view: View; setView: (v: View) => void }) => (
  <aside>
    <div className="brand">
      <ShieldCheck /> Forensi<span>Wipe</span>
    </div>
    <p className="tagline">
      Secure Erasure · Intelligent Recovery · Evidential Audit
    </p>
    {(
      [
        ["overview", "Overview", Activity],
        ["erase", "Drive Eraser", HardDrive],
        ["files", "File Eraser", Trash2],
        ["carve", "Recovery", FileSearch],
        ["audit", "Audit Chain", ShieldCheck],
      ] as const
    ).map(([id, label, Icon]) => (
      <button
        className={view === id ? "nav active" : "nav"}
        onClick={() => setView(id)}
        key={id}
      >
        <Icon size={17} />
        {label}
      </button>
    ))}
    <div className="safe-side">
      DEMO MODE
      <br />
      <b>SAFE MODE ENABLED</b>
      <small>Only approved loopback images are writable.</small>
    </div>
  </aside>
);
function App() {
  const [view, setView] = useState<View>("overview");
  const [ops, setOps] = useState<Operation[]>([]);
  const [audit, setAudit] = useState<Audit>();
  const [system, setSystem] = useState<SystemStatus>();
  const [error, setError] = useState("");
  const refresh = async () => {
    try {
      const [o, a, s] = await Promise.all([
        api.ops(),
        api.audit(),
        api.status(),
      ]);
      setOps(o);
      setAudit(a);
      setSystem(s);
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Backend unavailable");
    }
  };
  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, []);
  return (
    <div className="shell">
      <Nav view={view} setView={setView} />
      <main>
        <header>
          <div>
            <p className="eyebrow">FORENSIC OPERATIONS CONSOLE</p>
            <h1>
              {view === "overview"
                ? "System Overview"
                : view === "erase"
                  ? "Secure Drive Eraser"
                  : view === "files"
                    ? "Secure File & Folder Eraser"
                    : view === "carve"
                      ? "Advanced File Recovery"
                      : "Audit Integrity"}
            </h1>
          </div>
          <button className="secondary" onClick={refresh}>
            Refresh
          </button>
        </header>
        {error && <div className="error">Backend unavailable: {error}</div>}
        {view === "overview" && (
          <Overview ops={ops} audit={audit} system={system} />
        )}{" "}
        {view === "erase" && <Erase />}
        {view === "files" && <Files />}
        {view === "carve" && <Carve />}
        {view === "audit" && <AuditPanel audit={audit} />}
      </main>
    </div>
  );
}
const Card = ({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) => (
  <section className="card">
    <p className="eyebrow">{title}</p>
    {children}
  </section>
);
function Overview({
  ops,
  audit,
  system,
}: {
  ops: Operation[];
  audit?: Audit;
  system?: SystemStatus;
}) {
  const safe = system?.safety.safe_mode;
  return (
    <>
      <div className="grid three">
        <Card title="System Safety">
          <strong className={safe === false ? "danger" : "success"}>
            {safe === false ? "SAFE MODE DISABLED" : "SAFE MODE"}
          </strong>
          <p>{system?.safety.demo_banner ?? "Loading backend safety state…"}</p>
        </Card>
        <Card title="Audit Integrity">
          <strong className={audit?.valid ? "success" : "danger"}>
            {audit?.valid ? "✓ HASH CHAIN VERIFIED" : "— CHECK REQUIRED"}
          </strong>
          <p>{audit?.checked_records ?? 0} records checked</p>
        </Card>
        <Card title="Active Operations">
          <strong>
            {
              ops.filter((x) =>
                ["RUNNING", "VALIDATING", "VERIFYING"].includes(x.status),
              ).length
            }
          </strong>
          <p>Operations currently executing</p>
        </Card>
      </div>
      <Card title="Operation Monitor">
        <table>
          <thead>
            <tr>
              <th>Operation</th>
              <th>Module</th>
              <th>Target</th>
              <th>Status</th>
              <th>Progress</th>
              <th>Report</th>
            </tr>
          </thead>
          <tbody>
            {ops.length ? (
              ops.map((o) => (
                <tr key={o.operation_id}>
                  <td>{o.operation_id}</td>
                  <td>{o.module}</td>
                  <td className="truncate">{o.target}</td>
                  <td>
                    <span className={"pill " + o.status.toLowerCase()}>
                      {o.status}
                    </span>
                  </td>
                  <td>
                    <div className="bar">
                      <i style={{ width: `${o.progress}%` }} />
                    </div>
                    {o.progress}%
                  </td>
                  <td>
                    {o.status === "COMPLETED" && (
                      <a href={api.report(o.operation_id)} target="_blank">
                        PDF
                      </a>
                    )}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={6} className="empty">
                  No in-session operations yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
    </>
  );
}
function Erase() {
  const [target, setTarget] = useState("");
  const [validation, setValidation] = useState<any>();
  const [standard, setStandard] = useState("DOD_3PASS");
  const [message, setMessage] = useState("");
  const validate = async () => {
    try {
      setValidation(await api.validate(target));
      setMessage("");
    } catch (e) {
      setMessage(String(e));
    }
  };
  const start = async () => {
    try {
      const r = await api.startErase({ target, standard, demo_mode: true });
      setMessage(`Queued ${r.operation_id}. Monitor it on Overview.`);
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Could not queue erase");
    }
  };
  return (
    <div className="workflow">
      <Card title="1 · Select demo loopback target">
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="/dev/loop10"
        />
        <button onClick={validate}>Validate target</button>
      </Card>
      {validation && (
        <Card title="2 · Security Validation">
          <strong className={validation.allowed ? "success" : "danger"}>
            {validation.allowed ? "ALLOWED" : "BLOCKED"}
          </strong>
          <p>{validation.reason}</p>
          <small>
            Risk: {validation.risk_level} ·{" "}
            {validation.safe_mode ? "Safe mode" : "Production mode"}
          </small>
        </Card>
      )}
      <Card title="3 · Sanitization method">
        <select value={standard} onChange={(e) => setStandard(e.target.value)}>
          <option value="ZERO_FILL">Zero fill</option>
          <option value="DOD_3PASS">DoD 3-pass — demonstration</option>
          <option value="NIST_CLEAR">NIST SP 800-88 Clear</option>
        </select>
        <p className="notice">
          For SSD/NVMe, repeated overwriting is not proof of purge. Hardware
          sanitize is not executed by this prototype.
        </p>
        <button disabled={!validation?.allowed} onClick={start}>
          Start simulated operation
        </button>
      </Card>
      {message && <p>{message}</p>}
    </div>
  );
}
function Files() {
  const [paths, setPaths] = useState("");
  const [preview, setPreview] = useState<any>();
  const [message, setMessage] = useState("");
  const request = {
    paths: paths
      .split("\n")
      .map((x) => x.trim())
      .filter(Boolean),
    recursive: true,
    glob_pattern: null,
    sanitise_metadata: true,
    scan_residuals: true,
    demo_mode: true,
  };
  return (
    <div className="workflow">
      <Card title="Select files or folders">
        <textarea
          value={paths}
          onChange={(e) => setPaths(e.target.value)}
          placeholder={"/path/to/file\n/path/to/folder"}
        />
        <button
          onClick={async () => setPreview(await api.previewFiles(request))}
        >
          Preview affected files
        </button>
      </Card>
      {preview && (
        <Card title="Review selection">
          <strong>
            {preview.total_files} files · {preview.total_size_human}
          </strong>
          <p>
            Filesystem: {preview.filesystem} · Support:{" "}
            {preview.filesystem_support}
          </p>
          {preview.warnings.map((w: string) => (
            <p className="notice" key={w}>
              {w}
            </p>
          ))}
          <button
            onClick={async () => {
              const r = await api.startFiles(request);
              setMessage(`Queued ${r.operation_id} in DEMO MODE.`);
            }}
          >
            Run simulated erase
          </button>
        </Card>
      )}
      {message && <p>{message}</p>}
    </div>
  );
}
function Carve() {
  const [path, setPath] = useState("");
  const [result, setResult] = useState<any>();
  const [message, setMessage] = useState("");
  return (
    <div className="workflow">
      <Card title="Evidence image">
        <input
          value={path}
          onChange={(e) => setPath(e.target.value)}
          placeholder="/absolute/path/to/evidence.img"
        />
        <button
          onClick={async () => {
            const r = await api.scan(path);
            setMessage(`Scan queued: ${r.operation_id}`);
            const timer = setInterval(async () => {
              try {
                const data = await api.carve(r.operation_id);
                setResult(data);
                clearInterval(timer);
              } catch {}
            }, 1500);
          }}
        >
          Start read-only scan
        </button>
        <p className="notice">
          The source evidence image is opened read-only. Recovered data is
          written separately.
        </p>
      </Card>
      {message && <p>{message}</p>}
      {result && (
        <Card title="Recovered files">
          <p>Evidence integrity: {result.evidence_integrity}</p>
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Offset</th>
                <th>Size</th>
                <th>Confidence</th>
                <th>SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {result.carved_files.map((f: any, i: number) => (
                <tr key={i}>
                  <td>{f.file_type}</td>
                  <td>{f.offset}</td>
                  <td>{f.size}</td>
                  <td>{f.confidence}%</td>
                  <td className="hash">{f.sha256}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
function AuditPanel({ audit }: { audit?: Audit }) {
  const [history, setHistory] = useState<any[]>([]);
  useEffect(() => {
    api
      .history()
      .then(setHistory)
      .catch(() => {});
  }, [audit]);
  return (
    <>
      <Card title="Verify report integrity">
        <strong className={audit?.valid ? "success" : "danger"}>
          {audit?.valid
            ? "✓ REPORT INTEGRITY VERIFIED"
            : "✕ INTEGRITY FAILURE DETECTED"}
        </strong>
        <p>{audit?.reason}</p>
      </Card>
      <Card title="Hash chain history">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Operation</th>
              <th>Action</th>
              <th>Previous hash</th>
              <th>Current hash</th>
            </tr>
          </thead>
          <tbody>
            {history.map((r) => (
              <tr key={r.sequence}>
                <td>{r.sequence}</td>
                <td>{r.operation_id}</td>
                <td>{r.action}</td>
                <td className="hash">{r.previous_hash}</td>
                <td className="hash">{r.current_hash}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </>
  );
}
export default App;
