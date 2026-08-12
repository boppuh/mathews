import { DocNav } from "../components/doc-nav";

const actions = [
  { action: "Frame scope & criteria", operator: "Owns", control: "Records", hermes: "Proposes", host: "—", github: "—" },
  { action: "Approve exact brief", operator: "Approves", control: "Enforces", hermes: "Never", host: "—", github: "—" },
  { action: "Advance task state", operator: "Decides gates", control: "Only executor", hermes: "Never", host: "Never", github: "Signals only" },
  { action: "Request a code change", operator: "Steers", control: "Authorizes", hermes: "Proposes", host: "Executes", github: "—" },
  { action: "Run Xcode / Simulator", operator: "Configures", control: "Dispatches", hermes: "Requests", host: "Only executor", github: "—" },
  { action: "Create commit & push", operator: "Configures", control: "Authorizes", hermes: "Never", host: "Only executor", github: "Receives" },
  { action: "Declare validation pass", operator: "Inspects", control: "Only authority", hermes: "Never", host: "Returns results", github: "—" },
  { action: "Open / update draft PR", operator: "Observes", control: "Authorizes", hermes: "Drafts copy", host: "Pushes SHA", github: "Executes API" },
  { action: "Authorize review repair", operator: "Approves risk", control: "Policy / human gate", hermes: "Never self-approves", host: "Executes", github: "Supplies review" },
  { action: "Mark ready & merge", operator: "Human only", control: "Never", hermes: "Never", host: "Never", github: "Human UI" },
  { action: "Deploy / release", operator: "Human only", control: "Never", hermes: "Never", host: "Never", github: "Not granted" },
];

const roles = [
  { code: "H", title: "Human operator", accent: "amber", statement: "Owns intent, approvals, terminal decisions, merge, and release.", boundary: "Must explicitly approve ambiguity, unsafe change, reusable rules, and final handoff." },
  { code: "CP", title: "Control plane", accent: "cyan", statement: "The sole workflow authority and durable system of record.", boundary: "Authorizes every tool call, evaluates gates, records evidence, and moves task state." },
  { code: "HE", title: "Hermes", accent: "lime", statement: "A bounded reasoning and proposal engine—not an authority.", boundary: "Cannot call the host directly, approve itself, commit, push, advance state, or declare success." },
  { code: "HA", title: "Host agent", accent: "violet", statement: "The narrow execution boundary on the developer’s Mac.", boundary: "Runs named allowlisted operations. It exposes no generic shell and makes no policy decision." },
  { code: "GH", title: "GitHub", accent: "rose", statement: "The collaboration surface and source of correlated CI/review signals.", boundary: "The App can observe checks and write draft PRs; it has no merge, release, workflow, or deployment authority." },
];

function cellClass(value: string) {
  if (value === "—") return "empty";
  if (/Never|Not granted/.test(value)) return "denied";
  if (/Only|Owns|Approves|Human only/.test(value)) return "primary";
  return "support";
}

export default function AuthorityMatrixPage() {
  return (
    <main className="doc-shell authority-shell">
      <DocNav current="authority" />
      <section className="doc-intro authority-intro">
        <div>
          <span className="section-number">03 / AUTHORITY MATRIX</span>
          <h1>Capability is not<br /><em>permission.</em></h1>
        </div>
        <p>Mathews separates the ability to propose, authorize, execute, verify, and approve. No component can quietly accumulate end-to-end power.</p>
      </section>

      <section className="role-grid" aria-label="Authority roles">
        {roles.map((role) => (
          <article className={`role-card ${role.accent}`} key={role.code}>
            <span className="role-code">{role.code}</span>
            <h2>{role.title}</h2>
            <p>{role.statement}</p>
            <div className="role-boundary"><span>BOUNDARY</span>{role.boundary}</div>
          </article>
        ))}
      </section>

      <section className="matrix-section">
        <div className="section-heading matrix-heading">
          <span>WHO MAY DO WHAT</span>
          <h2>One action. One accountable boundary.</h2>
          <div className="matrix-legend"><span><i className="key primary" />Owns / sole authority</span><span><i className="key support" />Supports / proposes</span><span><i className="key denied" />Explicitly denied</span></div>
        </div>
        <div className="matrix-scroll">
          <table className="authority-table">
            <thead><tr><th>Capability</th><th>Human</th><th>Control plane</th><th>Hermes</th><th>Host agent</th><th>GitHub</th></tr></thead>
            <tbody>
              {actions.map((row) => (
                <tr key={row.action}>
                  <th scope="row">{row.action}</th>
                  {(["operator", "control", "hermes", "host", "github"] as const).map((column) => (
                    <td className={cellClass(row[column])} key={column}><span>{row[column]}</span></td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="prohibition-section">
        <div className="section-heading"><span>HARD PROHIBITIONS</span><h2>Designed out, not merely discouraged.</h2></div>
        <div className="prohibition-grid">
          <article><span>01</span><h3>No autonomous merge</h3><p>The GitHub App deliberately lacks the permission needed to merge or publish a release.</p></article>
          <article><span>02</span><h3>No self-approval</h3><p>Hermes output is a proposal. Agent confidence, prior similarity, and silence never create authority.</p></article>
          <article><span>03</span><h3>No direct host access</h3><p>Hermes has no network path or credential to the macOS host. Every request crosses the control plane.</p></article>
          <article><span>04</span><h3>No prose-based pass</h3><p>Only stored, criterion-linked evidence for the exact commit can satisfy validation and readiness.</p></article>
          <article><span>05</span><h3>No generic shell</h3><p>The host exposes named operations with validated arguments, configured roots, and path allowlists.</p></article>
          <article><span>06</span><h3>No stale proof</h3><p>A changed commit, tree, configuration, contract, PR head, CI result, or review invalidates the prior gate.</p></article>
        </div>
      </section>

      <section className="trust-statement">
        <span className="trust-label">THE CORE TRUST CONTRACT</span>
        <p><strong>Humans decide.</strong> The control plane authorizes and records. Hermes proposes. The host executes. GitHub reports. Evidence proves.</p>
      </section>

      <footer className="site-footer"><span>MATHEWS / AUTHORITY MATRIX</span><span>Least privilege by construction</span></footer>
    </main>
  );
}
