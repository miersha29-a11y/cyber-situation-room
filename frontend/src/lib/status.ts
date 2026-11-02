import type { ConnectionStatus } from "../types";

export const CONNECTION_LABELS: Record<ConnectionStatus, string> = {
  connecting: "CONNECTING",
  online: "API ONLINE",
  empty: "NO DATA LOADED",
  degraded: "API ERROR",
  offline: "API OFFLINE",
};
