import type { TaskState } from "@mathews/contracts";

const ACRONYMS = new Set(["API", "CI", "PR"]);

export function stageLabel(stage: TaskState): string {
  return stage
    .toLowerCase()
    .split("_")
    .map((part) => {
      const upper = part.toUpperCase();
      return ACRONYMS.has(upper) ? upper : part[0]?.toUpperCase() + part.slice(1);
    })
    .join(" ");
}
