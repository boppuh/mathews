import { TASK_STATES } from "@mathews/contracts";

import { stageLabel } from "../lib/stages";
import { AuthGate } from "./auth-gate";

const services = [
  {
    name: "Control plane",
    detail: "Authoritative workflow, policy, approvals, and evidence",
  },
  {
    name: "macOS host agent",
    detail: "Typed local Git, Xcode, Simulator, and artifact operations",
  },
  {
    name: "PostgreSQL",
    detail: "Durable task, event, approval, and execution state",
  },
];

export default function Home() {
  return (
    <AuthGate>
      <main className="workspace-main">
        <header className="hero">
          <p className="eyebrow">MVP foundation</p>
          <h1>Evidence before claims.</h1>
          <p className="lede">
            Mathews turns an iOS engineering request into a revision-bound, validated draft pull
            request while humans retain control of scope, policy, sensitive actions, and merge.
          </p>
        </header>

        <section aria-labelledby="workflow-heading">
          <div className="section-heading">
            <p className="eyebrow">Workflow contract</p>
            <h2 id="workflow-heading">Durable stages, visible evidence</h2>
          </div>
          <ol className="timeline">
            {TASK_STATES.map((stage, index) => (
              <li key={stage}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                {stageLabel(stage)}
              </li>
            ))}
          </ol>
        </section>

        <section aria-labelledby="services-heading">
          <div className="section-heading">
            <p className="eyebrow">Local workspace</p>
            <h2 id="services-heading">Service boundaries</h2>
          </div>
          <div className="service-grid">
            {services.map((service) => (
              <article key={service.name}>
                <h3>{service.name}</h3>
                <p>{service.detail}</p>
              </article>
            ))}
          </div>
        </section>
      </main>
    </AuthGate>
  );
}
