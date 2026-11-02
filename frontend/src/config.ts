// Base URL for the FastAPI backend. Override it with VITE_API_BASE_URL in
// frontend/.env (see .env.example); defaults to the local dev server.
export const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");
