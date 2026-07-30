import { notFound } from "next/navigation";

import { AuthGate } from "../../auth-gate";
import { TaskCockpit } from "./task-cockpit";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export default async function TaskCockpitPage({ params }: { params: Promise<{ taskId: string }> }) {
  const { taskId } = await params;
  if (!UUID_PATTERN.test(taskId)) {
    notFound();
  }

  return (
    <AuthGate>
      <TaskCockpit taskId={taskId} />
    </AuthGate>
  );
}
