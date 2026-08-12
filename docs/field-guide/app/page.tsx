import Link from "next/link";

const pages = [
  {
    index: "01",
    eyebrow: "System map",
    title: "Architecture",
    description:
      "Explore how the operator, control plane, host, Hermes, evidence, and GitHub fit together.",
    href: "/mathews-architecture.html",
    accent: "cyan",
  },
  {
    index: "02",
    eyebrow: "State model",
    title: "Task lifecycle",
    description:
      "Follow the golden path, approval pauses, repair loops, reversals, and terminal outcomes.",
    href: "/task-lifecycle",
    accent: "lime",
  },
  {
    index: "03",
    eyebrow: "Trust boundary",
    title: "Authority matrix",
    description:
      "See who can propose, authorize, execute, verify, publish, and merge—and who explicitly cannot.",
    href: "/authority-matrix",
    accent: "amber",
  },
  {
    index: "04",
    eyebrow: "Proof model",
    title: "Evidence chain",
    description:
      "Trace how intent, authority, validation, exact-head proof, and human handoff stay cryptographically bound.",
    href: "/evidence-chain",
    accent: "violet",
  },
  {
    index: "05",
    eyebrow: "Acceptance",
    title: "MVP release gate",
    description:
      "Run the authoritative acceptance procedure, capture evidence, and compute a strict GO or NO-GO decision.",
    href: "/mvp-release-gate",
    accent: "rose",
  },
  {
    index: "06",
    eyebrow: "Resilience",
    title: "Failure & recovery",
    description:
      "Explore cancellation, outages, retries, stale results, duplicate effects, and restart reconciliation.",
    href: "/failure-recovery",
    accent: "cyan",
  },
  {
    index: "07",
    eyebrow: "Operations",
    title: "Operator runbook",
    description:
      "Configure, bootstrap, start, verify, run acceptance, clean up, and troubleshoot the local MVP.",
    href: "/operator-runbook",
    accent: "lime",
  },
  {
    index: "08",
    eyebrow: "Language",
    title: "Glossary",
    description:
      "Look up the precise meaning of the records, gates, states, and trust-boundary terms used throughout Mathews.",
    href: "/glossary",
    accent: "amber",
  },
];

export default function Home() {
  return (
    <main className="home-shell">
      <div className="home-grid" aria-hidden="true" />
      <header className="site-header home-header">
        <Link className="wordmark" href="/">
          <span className="wordmark-mark">M</span>
          <span>MATHEWS</span>
        </Link>
        <span className="header-label">System documentation / MVP</span>
      </header>

      <section className="hero">
        <div className="hero-kicker"><span /> Evidence-first iOS engineering</div>
        <h1>Know the system.<br /><em>Trust the boundary.</em></h1>
        <p>
          A field guide to the architecture, workflow, and authority model behind
          Mathews—from a natural-language request to a verified draft pull request.
        </p>
        <div className="hero-meta">
          <span>8 guides</span><span>40 / 40 MVP tasks</span><span>Human-controlled merge</span>
        </div>
      </section>

      <section className="guide-list" aria-label="Documentation guides">
        {pages.map((page) => (
          <Link className={`guide-card ${page.accent}`} href={page.href} key={page.href}>
            <div className="guide-index">{page.index}</div>
            <div className="guide-copy">
              <span className="guide-eyebrow">{page.eyebrow}</span>
              <h2>{page.title}</h2>
              <p>{page.description}</p>
            </div>
            <span className="guide-arrow" aria-hidden="true">↗</span>
          </Link>
        ))}
      </section>

      <footer className="site-footer">
        <span>MATHEWS / SYSTEM FIELD GUIDE</span>
        <span>Built for auditable autonomy</span>
      </footer>
    </main>
  );
}
