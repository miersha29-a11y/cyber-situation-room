import { API_BASE_URL } from "../api";
import type { Dashboard } from "../hooks/useDashboard";

type StatusBannersProps = Pick<
  Dashboard,
  | "apiError"
  | "databaseEmpty"
>;

export function StatusBanners({
  apiError,
  databaseEmpty,
}: StatusBannersProps) {
  if (apiError) {
    return (
      <div className="api-status-banner api-status-error" role="alert">
        Cannot load data from the API at {API_BASE_URL}. Check the backend
        is running. ({apiError.message})
      </div>
    );
  }

  if (databaseEmpty) {
    return (
      <div className="api-status-banner api-status-warning" role="status">
        The API is running but the database is empty. Run the ingest
        scripts listed in the README, then reload.
      </div>
    );
  }

  return null;
}
