import { AuthGate } from "../auth-gate";
import { RepositoryWorkspace } from "./repository-workspace";

export default function RepositoryPage() {
  return (
    <AuthGate>
      <RepositoryWorkspace />
    </AuthGate>
  );
}
