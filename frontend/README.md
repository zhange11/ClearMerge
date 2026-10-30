# ClearMerge frontend

The frontend is a TypeScript/React/Vite dashboard for the FastAPI review API.

The dashboard includes:

- Manual review triggering through `POST /api/reviews`.
- Repository and policy-decision filters.
- Server-side pagination using `limit`, `offset`, and `total`.
- Aggregate review statistics from `/api/stats`.
- API liveness/readiness status from `/healthz` and `/readyz`.

While a worker is processing a review, the detail view:

- Shows `queued` as waiting for a worker.
- Shows `running` with the current pipeline stage.
- Polls the review every three seconds until it reaches an approval or terminal state.
- Shows `waiting_for_approval` as an actionable pause, not a loading state.
- Shows retry controls for failed reviews.

Run it from this directory with `npm install` and `npm run dev`. Vite proxies `/api` requests to `http://localhost:8000`.
