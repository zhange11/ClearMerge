export type ReviewStatus =
  | "queued"
  | "running"
  | "waiting_for_approval"
  | "approved"
  | "rejected"
  | "completed"
  | "blocked"
  | "failed"
  | "superseded";

export type StageStatus = "pending" | "running" | "completed";

export interface PipelineStage {
  name: string;
  status: StageStatus;
}

export interface Review {
  review_id: string;
  status: ReviewStatus;
  current_stage?: string;
  commit_sha?: string;
  repository?: { owner?: string; name?: string; pull_request?: number };
  pr_title?: string;
  risk_assessment?: { score?: number; risk_level?: string; rationale?: string };
  merge_decision?: { decision?: "allow" | "require_approval" | "block" };
  policy_decision?: "allow" | "require_approval" | "block";
  errors: Array<{ code?: string; message?: string; retryable?: boolean }>;
  pipeline_stages: PipelineStage[];
  updated_at?: string;
}

export interface ReviewListResponse {
  items: Review[];
  limit: number;
  offset: number;
  total: number;
}

export interface ReviewStats {
  total_reviews: number;
  by_decision: { allow: number; require_approval: number; block: number; pending: number };
  average_risk_score: number | null;
  reviews_over_time: Array<{ date: string; count: number }>;
}

export interface HealthStatus {
  status: string;
  worker_mode?: string;
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.detail ?? `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export function listReviews(params: { limit: number; offset: number; decision?: string; repo?: string }): Promise<ReviewListResponse> {
  const query = new URLSearchParams({ limit: String(params.limit), offset: String(params.offset) });
  if (params.decision) query.set("decision", params.decision);
  if (params.repo) query.set("repo", params.repo);
  return request<ReviewListResponse>(`/api/reviews?${query}`);
}

export function createReview(payload: {
  repo: string;
  pull_request: number;
}): Promise<Review> {
  return request<Review>("/api/reviews", { method: "POST", body: JSON.stringify(payload) });
}

export function getStats(): Promise<ReviewStats> {
  return request<ReviewStats>("/api/stats");
}

export function getHealth(): Promise<HealthStatus> {
  return request<HealthStatus>("/healthz");
}

export function getReadiness(): Promise<HealthStatus> {
  return request<HealthStatus>("/readyz");
}

export function getReview(reviewId: string): Promise<Review> {
  return request<Review>(`/api/reviews/${encodeURIComponent(reviewId)}`);
}

export function retryReview(reviewId: string): Promise<Review> {
  return request<Review>(`/api/reviews/${encodeURIComponent(reviewId)}/retry`, { method: "POST" });
}

export function submitApproval(
  reviewId: string,
  approval: { decision: "approve" | "reject"; reviewer_id: number; comment: string; commit_sha: string },
): Promise<Review> {
  return request<Review>(`/api/reviews/${encodeURIComponent(reviewId)}/approval`, {
    method: "POST",
    body: JSON.stringify(approval),
  });
}
