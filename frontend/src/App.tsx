import { useCallback, useEffect, useMemo, useState } from "react";
import {
  createReview, getHealth, getReadiness, getReview, getStats, listReviews, retryReview, submitApproval,
  type HealthStatus, type Review, type ReviewStats, type ReviewStatus,
} from "./api";

const pageSize = 10;
const terminalStatuses = new Set<ReviewStatus>(["completed", "blocked", "failed", "superseded", "approved", "rejected"]);
const statusCopy: Record<ReviewStatus, string> = {
  queued: "Waiting for a worker", running: "Review in progress", waiting_for_approval: "Your approval is required",
  approved: "Approved", rejected: "Rejected", completed: "Completed", blocked: "Blocked by policy",
  failed: "Review failed", superseded: "Superseded by a newer commit",
};

export function App() {
  const [reviews, setReviews] = useState<Review[]>([]);
  const [selectedId, setSelectedId] = useState<string>();
  const [statusFilter, setStatusFilter] = useState<"all" | ReviewStatus>("all");
  const [decision, setDecision] = useState("");
  const [repo, setRepo] = useState("");
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState<ReviewStats>();
  const [health, setHealth] = useState<HealthStatus>();
  const [readiness, setReadiness] = useState<HealthStatus>();
  const [error, setError] = useState<string>();
  const [showTrigger, setShowTrigger] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [result, summary] = await Promise.all([
        listReviews({ limit: pageSize, offset, decision: decision || undefined, repo: repo || undefined }),
        getStats(),
      ]);
      setReviews(result.items); setTotal(result.total); setStats(summary); setError(undefined);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to load reviews"); }
  }, [decision, offset, repo]);

  const refreshHealth = useCallback(async () => {
    try { setHealth(await getHealth()); setReadiness(await getReadiness()); }
    catch { setHealth(undefined); setReadiness(undefined); }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => { void refreshHealth(); const timer = window.setInterval(() => void refreshHealth(), 10_000); return () => window.clearInterval(timer); }, [refreshHealth]);
  const visibleReviews = useMemo(() => statusFilter === "all" ? reviews : reviews.filter((review) => review.status === statusFilter), [reviews, statusFilter]);
  const selected = reviews.find((review) => review.review_id === selectedId) ?? visibleReviews[0];
  const changeFilter = (callback: () => void) => { setOffset(0); callback(); };

  return <main className="shell">
    <header className="topbar">
      <div><p className="eyebrow">CLEARMERGE / REVIEW CONTROL</p><h1>Pull request reviews</h1></div>
      <div className="topbar-actions"><HealthIndicator health={health} readiness={readiness} /><button className="primary-button" onClick={() => setShowTrigger(true)}>Trigger review</button><button className="secondary-button" onClick={() => void refresh()}>Refresh</button></div>
    </header>
    {error && <div className="alert error">{error}</div>}
    {stats && <StatsCards stats={stats} />}
    <section className="layout">
      <aside className="panel review-list">
        <div className="panel-heading"><div><span className="eyebrow">INBOX</span><h2>{total} reviews</h2></div><select value={statusFilter} onChange={(event) => changeFilter(() => setStatusFilter(event.target.value as "all" | ReviewStatus))}><option value="all">All statuses</option><option value="queued">Queued</option><option value="running">Running</option><option value="waiting_for_approval">Needs approval</option><option value="completed">Completed</option><option value="blocked">Blocked</option><option value="failed">Failed</option></select></div>
        <div className="filter-row"><input value={repo} placeholder="Filter repository (owner/name)" onChange={(event) => changeFilter(() => setRepo(event.target.value))} /><select value={decision} onChange={(event) => changeFilter(() => setDecision(event.target.value))}><option value="">All decisions</option><option value="allow">Allow</option><option value="require_approval">Needs approval</option><option value="block">Block</option></select></div>
        {visibleReviews.length === 0 && <p className="muted empty">No reviews match these filters.</p>}
        {visibleReviews.map((review) => <button className={`review-row ${selected?.review_id === review.review_id ? "selected" : ""}`} key={review.review_id} onClick={() => setSelectedId(review.review_id)}><div className="row-title"><strong>{repositoryName(review)}</strong><StatusBadge status={review.status} /></div><span className="muted">{review.pr_title || `Pull request #${review.repository?.pull_request ?? "—"}`}</span><span className="row-meta">Updated {formatDate(review.updated_at)}</span></button>)}
        <div className="pagination"><button className="secondary-button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - pageSize))}>Previous</button><span className="muted">{total === 0 ? 0 : offset + 1}–{Math.min(offset + pageSize, total)} of {total}</span><button className="secondary-button" disabled={offset + pageSize >= total} onClick={() => setOffset(offset + pageSize)}>Next</button></div>
      </aside>
      <ReviewDetail review={selected} onUpdate={(review) => setReviews((current) => current.map((item) => item.review_id === review.review_id ? review : item))} />
    </section>
    {showTrigger && <TriggerReview onCreated={(review) => { setShowTrigger(false); setSelectedId(review.review_id); void refresh(); }} onCancel={() => setShowTrigger(false)} />}
  </main>;
}

function StatsCards({ stats }: { stats: ReviewStats }) { return <section className="stats-grid">{[["Total reviews", stats.total_reviews], ["Allowed", stats.by_decision.allow], ["Needs approval", stats.by_decision.require_approval], ["Blocked", stats.by_decision.block], ["Avg. risk", stats.average_risk_score ?? "—"]].map(([label, value]) => <div className="stat-card" key={String(label)}><span className="label">{label}</span><strong>{value}</strong></div>)}</section>; }
function HealthIndicator({ health, readiness }: { health?: HealthStatus; readiness?: HealthStatus }) { const healthy = health?.status === "ok" && readiness?.status === "ready"; return <span className={`health ${healthy ? "healthy" : "unhealthy"}`} title={`API: ${health?.status ?? "unavailable"} / Worker: ${readiness?.status ?? "unavailable"}`}><span className="health-dot" />{healthy ? "API ready" : "API unavailable"}</span>; }

function TriggerReview({ onCreated, onCancel }: { onCreated: (review: Review) => void; onCancel: () => void }) {
  const [repo, setRepo] = useState(""); const [pullRequest, setPullRequest] = useState(""); const [installationId, setInstallationId] = useState(""); const [reviewers, setReviewers] = useState(""); const [error, setError] = useState<string>(); const [busy, setBusy] = useState(false);
  const submit = async (event: React.FormEvent) => { event.preventDefault(); setBusy(true); setError(undefined); try { onCreated(await createReview({ repo, pull_request: Number(pullRequest), installation_id: Number(installationId), authorized_reviewer_ids: reviewers.split(",").map((id) => Number(id.trim())).filter((id) => Number.isInteger(id) && id > 0) })); } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to trigger review"); } finally { setBusy(false); } };
  return <div className="modal-backdrop"><form className="modal panel" onSubmit={(event) => void submit(event)}><div className="detail-header"><div><p className="eyebrow">MANUAL REVIEW</p><h2>Trigger a review</h2></div><button type="button" className="secondary-button" onClick={onCancel}>Close</button></div><p className="muted">Fetch a pull request from GitHub and place it into the review pipeline.</p>{error && <div className="alert error">{error}</div>}<label>Repository<input required pattern="^[^/\s]+/[^/\s]+$" placeholder="owner/repository" value={repo} onChange={(event) => setRepo(event.target.value)} /></label><div className="form-row"><label>Pull request<input required min="1" type="number" value={pullRequest} onChange={(event) => setPullRequest(event.target.value)} /></label><label>Installation ID<input required min="1" type="number" value={installationId} onChange={(event) => setInstallationId(event.target.value)} /></label></div><label>Authorized reviewer IDs <span className="muted">(comma-separated)</span><input placeholder="12345, 67890" value={reviewers} onChange={(event) => setReviewers(event.target.value)} /></label><div className="actions"><button type="button" className="secondary-button" onClick={onCancel}>Cancel</button><button className="primary-button" disabled={busy}>{busy ? "Creating…" : "Create review"}</button></div></form></div>;
}

function ReviewDetail({ review, onUpdate }: { review?: Review; onUpdate: (review: Review) => void }) {
  const [actionError, setActionError] = useState<string>(); const [busy, setBusy] = useState(false);
  useEffect(() => { if (!review || terminalStatuses.has(review.status) || review.status === "waiting_for_approval") return; const timer = window.setInterval(async () => { try { onUpdate(await getReview(review.review_id)); } catch (reason) { setActionError(reason instanceof Error ? reason.message : "Unable to refresh review"); } }, 3000); return () => window.clearInterval(timer); }, [onUpdate, review]);
  if (!review) return <section className="panel empty-detail"><p className="muted">Select a review to see its progress.</p></section>;
  const runAction = async (action: () => Promise<Review>) => { setBusy(true); setActionError(undefined); try { onUpdate(await action()); } catch (reason) { setActionError(reason instanceof Error ? reason.message : "Action failed"); } finally { setBusy(false); } };
  return <section className="panel detail"><div className="detail-header"><div><p className="eyebrow">REVIEW {review.review_id.slice(0, 8)}</p><h2>{repositoryName(review)}</h2><p className="muted">{review.pr_title || "Pull request review"}</p></div><StatusBadge status={review.status} /></div>{actionError && <div className="alert error">{actionError}</div>}<div className="status-banner"><span className="pulse" /><div><strong>{statusCopy[review.status]}</strong><p>{statusDescription(review.status)}</p></div></div><div className="detail-grid"><div><span className="label">Risk score</span><strong>{review.risk_assessment?.score ?? "Pending"}</strong></div><div><span className="label">Policy</span><strong>{review.merge_decision?.decision ?? review.policy_decision ?? "Pending"}</strong></div><div><span className="label">Commit</span><strong className="mono">{review.commit_sha?.slice(0, 10) ?? "Pending"}</strong></div></div><h3>Review pipeline</h3><ol className="pipeline">{review.pipeline_stages.map((stage) => <li className={stage.status} key={stage.name}><span className="stage-dot">{stage.status === "completed" ? "✓" : stage.status === "running" ? "•" : ""}</span><span>{formatStage(stage.name)}</span>{stage.status === "running" && <span className="stage-current">Current</span>}</li>)}</ol>{review.status === "waiting_for_approval" && <ApprovalActions review={review} busy={busy} onSubmit={(decision, reviewerId, comment) => void runAction(() => submitApproval(review.review_id, { decision, reviewer_id: reviewerId, comment, commit_sha: review.commit_sha ?? "" }))} />}{review.status === "failed" && <button className="primary-button" disabled={busy} onClick={() => void runAction(() => retryReview(review.review_id))}>Retry review</button>}{review.errors.length > 0 && <div className="alert error"><strong>Review errors</strong>{review.errors.map((item, index) => <p key={index}>{item.message ?? item.code}</p>)}</div>}</section>;
}

function ApprovalActions({ review, busy, onSubmit }: { review: Review; busy: boolean; onSubmit: (decision: "approve" | "reject", reviewerId: number, comment: string) => void }) { const [reviewerId, setReviewerId] = useState(""); const [comment, setComment] = useState(""); return <div className="approval-box"><h3>Human approval</h3><p className="muted">Automated checks require an authorized reviewer before this commit can merge.</p><div className="form-row"><input placeholder="Reviewer ID" value={reviewerId} onChange={(event) => setReviewerId(event.target.value)} inputMode="numeric" /><input placeholder="Optional comment" value={comment} onChange={(event) => setComment(event.target.value)} /></div><div className="actions"><button className="secondary-button" disabled={busy || !reviewerId} onClick={() => onSubmit("reject", Number(reviewerId), comment)}>Reject</button><button className="primary-button" disabled={busy || !reviewerId || !review.commit_sha} onClick={() => onSubmit("approve", Number(reviewerId), comment)}>Approve commit</button></div></div>; }
function StatusBadge({ status }: { status: ReviewStatus }) { return <span className={`badge ${status}`}>{status.replaceAll("_", " ")}</span>; }
function repositoryName(review: Review) { return `${review.repository?.owner ?? "unknown"}/${review.repository?.name ?? "repository"}`; }
function formatDate(value?: string) { return value ? new Date(value).toLocaleString([], { dateStyle: "short", timeStyle: "short" }) : "—"; }
function formatStage(value: string) { return value.replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase()); }
function statusDescription(status: ReviewStatus) { if (status === "queued") return "The review was accepted and is waiting for a worker to claim it."; if (status === "running") return "Scanner, security, and policy checks are running. This view refreshes automatically."; if (status === "waiting_for_approval") return "The automated policy requires an authorized human decision."; if (status === "failed") return "The worker could not complete this review. You can retry when it is safe to do so."; return "This review has reached a final state."; }
