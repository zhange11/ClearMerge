from __future__ import annotations

import logging

from .config import Settings
from .github.adapter import GitHubRepositoryAdapter
from .github.client import GitHubAppClient
from .services.queue import InMemoryReviewQueue, RedisReviewQueue
from .services.reviews import ReviewService
from .services.worker import ReviewWorker


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    settings = Settings.from_env()
    if settings.redis_url:
        queue = RedisReviewQueue(settings.redis_url)
    else:
        logging.warning("REDIS_URL is not configured; worker will use an in-memory queue")
        queue = InMemoryReviewQueue()
    github = None
    if settings.github_app_id and settings.private_key():
        github = GitHubRepositoryAdapter(GitHubAppClient(settings))
    service = ReviewService(settings, github=github, queue=queue)
    logging.info("ClearMerge review worker started")
    ReviewWorker(queue, service).run_forever()


if __name__ == "__main__":
    main()