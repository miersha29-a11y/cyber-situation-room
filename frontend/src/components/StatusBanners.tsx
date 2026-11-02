import { API_BASE_URL } from "../api";
import type { Dashboard } from "../hooks/useDashboard";

type StatusBannersProps = Pick<
  Dashboard,
  | "apiError"
  | "connectionStatus"
>;

export function StatusBanners({
  apiError,
  connectionStatus,
}: StatusBannersProps) {
  if (connectionStatus === "offline") {
    return (
      <div className="api-status-banner api-status-error" role="alert">
        Cannot reach the API at {API_BASE_URL}. Check the backend is
        running; the dashboard reconnects automatically when it is back.
        {apiError && <> ({apiError.message})</>}
      </div>
    );
  }

  if (connectionStatus === "degraded") {
    return (
      <div className="api-status-banner api-status-error" role="alert">
        The API is reachable but some data failed to load.
        {apiError && <> ({apiError.message})</>}
      </div>
    );
  }

  if (connectionStatus === "empty") {
    return (
      <div className="api-status-banner api-status-warning" role="status">
        The API is running but the database is empty. Run the ingest
        scripts listed in the README, then reload.
      </div>
    );
  }

  return null;
}
