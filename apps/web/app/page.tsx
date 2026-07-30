import { AuthGate } from "./auth-gate";
import { TaskWorkspace } from "./task-workspace";

export default function Home() {
  return (
    <AuthGate>
      <TaskWorkspace />
    </AuthGate>
  );
}
