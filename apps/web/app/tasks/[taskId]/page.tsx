import Link from "next/link";
import { notFound } from "next/navigation";

import { AuthGate } from "../../auth-gate";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export default async function TaskCockpitPlaceholder({
  params,
}: {
  params: Promise<{ taskId: string }>;
}) {
  const { taskId } = await params;
  if (!UUID_PATTERN.test(taskId)) {
    notFound();
  }

  return (
    <AuthGate>
      <main className="cockpit-placeholder">
        <Link href="/" className="back-link">
          ← Work
        </Link>
        <section aria-labelledby="cockpit-heading">
          <p className="eyebrow">Task cockpit</p>
          <h1 id="cockpit-heading">Task {taskId.slice(0, 8)}</h1>
          <p className="lede">
            This task is durably linked. Its full activity, evidence, and controls arrive in the
            next cockpit slice.
          </p>
        </section>
      </main>
    </AuthGate>
  );
}
