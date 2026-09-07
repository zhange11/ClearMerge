"""LangGraph orchestration for ClearMerge pull-request reviews."""

from .state import ReviewState, ReviewStatus, StageName, new_review_state


def build_review_graph(*args, **kwargs):
	"""Load the optional LangGraph runtime only when graph execution is requested."""
	from .graph import build_review_graph as _build_review_graph

	return _build_review_graph(*args, **kwargs)


__all__ = ["ReviewState", "ReviewStatus", "StageName", "build_review_graph", "new_review_state"]
