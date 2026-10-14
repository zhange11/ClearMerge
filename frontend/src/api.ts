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

interface ReviewListResponse {
  items: Review[];
  total: number;
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

export function listReviews(): Promise<ReviewListResponse> {
  return request<ReviewListResponse>("/api/reviews?limit=100");
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
