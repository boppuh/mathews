import type { ServiceHealth } from "@mathews/contracts";

export function GET() {
  const response: ServiceHealth = {
    service: "web",
    status: "ok",
    version: "0.1.0",
  };

  return Response.json(response);
}
