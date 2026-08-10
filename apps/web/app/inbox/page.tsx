import { AuthGate } from "../auth-gate";
import { DecisionInbox } from "./decision-inbox";

export default function InboxPage() {
  return (
    <AuthGate>
      <DecisionInbox />
    </AuthGate>
  );
}
