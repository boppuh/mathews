import Link from "next/link";

export function DocNav({ current }: { current: "lifecycle" | "authority" | "evidence" | "release" | "recovery" | "runbook" | "glossary" }) {
  return (
    <header className="site-header doc-header">
      <Link className="wordmark" href="/">
        <span className="wordmark-mark">M</span>
        <span>MATHEWS</span>
      </Link>
      <nav aria-label="Documentation">
        <Link href="/mathews-architecture.html">Architecture</Link>
        <Link className={current === "lifecycle" ? "active" : ""} href="/task-lifecycle">Lifecycle</Link>
        <Link className={current === "authority" ? "active" : ""} href="/authority-matrix">Authority</Link>
        <Link className={current === "evidence" ? "active" : ""} href="/evidence-chain">Evidence</Link>
        <Link className={current === "release" ? "active" : ""} href="/mvp-release-gate">Release gate</Link>
        <Link className={current === "recovery" ? "active" : ""} href="/failure-recovery">Recovery</Link>
        <Link className={current === "runbook" ? "active" : ""} href="/operator-runbook">Runbook</Link>
        <Link className={current === "glossary" ? "active" : ""} href="/glossary">Glossary</Link>
      </nav>
    </header>
  );
}
