from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import urlparse


class ConfigurationError(ValueError):
	"""Raised for invalid ClearMerge configuration."""


@dataclass(frozen=True, repr=False)
class Settings:
	github_app_id: int | None
	github_app_private_key: str | None
	github_app_private_key_path: Path | None
	github_webhook_secret: str | None
	github_api_url: str
	public_base_url: str | None
	max_webhook_body_bytes: int
	review_worker_mode: str
	redis_url: str | None = None
	postgres_url: str | None = None
	cors_origins: tuple[str, ...] = ("http://localhost:3000",)
	github_installation_id: int | None = None
	authorized_reviewer_ids: tuple[int, ...] = ()

	@classmethod
	def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
		values = os.environ if environ is None else environ
		settings = cls(
			github_app_id=_optional_int(values.get("GITHUB_APP_ID"), "GITHUB_APP_ID"),
			github_app_private_key=_optional_text(values.get("GITHUB_APP_PRIVATE_KEY")),
			github_app_private_key_path=_optional_path(values.get("GITHUB_APP_PRIVATE_KEY_PATH")),
			github_webhook_secret=_optional_text(values.get("GITHUB_WEBHOOK_SECRET")),
			github_api_url=_text(values.get("GITHUB_API_URL"), "https://api.github.com").rstrip("/"),
			public_base_url=_optional_text(values.get("PUBLIC_BASE_URL")),
			max_webhook_body_bytes=_int(values.get("MAX_WEBHOOK_BODY_BYTES"), 1_048_576, "MAX_WEBHOOK_BODY_BYTES"),
			review_worker_mode=_text(values.get("REVIEW_WORKER_MODE"), "inline").lower(),
			redis_url=_optional_text(values.get("REDIS_URL")),
			postgres_url=_optional_text(values.get("POSTGRES_URL") or values.get("DATABASE_URL")),
			cors_origins=_origins(values.get("CORS_ORIGINS")),
			github_installation_id=_optional_int(values.get("GITHUB_INSTALLATION_ID"), "GITHUB_INSTALLATION_ID"),
			authorized_reviewer_ids=_int_list(values.get("AUTHORIZED_REVIEWER_IDS")),
		)
		settings.validate()
		return settings

	def validate(self, require_github_app: bool = False) -> None:
		if self.review_worker_mode not in {"inline", "queue"}:
			raise ConfigurationError("REVIEW_WORKER_MODE must be 'inline' or 'queue'")
		if self.max_webhook_body_bytes <= 0:
			raise ConfigurationError("MAX_WEBHOOK_BODY_BYTES must be greater than zero")
		_validate_url(self.github_api_url, "GITHUB_API_URL")
		if self.public_base_url:
			_validate_url(self.public_base_url, "PUBLIC_BASE_URL")
		if self.postgres_url and not self.postgres_url.startswith(("postgresql://", "postgres://")):
			raise ConfigurationError("POSTGRES_URL must be a PostgreSQL connection URL")
		for origin in self.cors_origins:
			if origin != "*":
				_validate_url(origin, "CORS_ORIGINS")
		if self.github_app_private_key and self.github_app_private_key_path:
			raise ConfigurationError("Set only one GitHub private-key source")
		if require_github_app:
			if self.github_app_id is None or not self.github_webhook_secret:
				raise ConfigurationError("GitHub App ID and webhook secret are required")
			if not self.github_app_private_key and not self.github_app_private_key_path:
				raise ConfigurationError("A GitHub App private key is required")

	def private_key(self) -> str | None:
		if self.github_app_private_key:
			return self.github_app_private_key
		if self.github_app_private_key_path:
			return self.github_app_private_key_path.read_text(encoding="utf-8")
		return None

	def __repr__(self) -> str:
		return f"Settings(github_app_id={self.github_app_id!r}, github_api_url={self.github_api_url!r}, review_worker_mode={self.review_worker_mode!r})"


def _optional_text(value: str | None) -> str | None:
	text = value.strip() if value else ""
	return text or None


def _text(value: str | None, default: str) -> str:
	return _optional_text(value) or default


def _optional_int(value: str | None, name: str) -> int | None:
	if not _optional_text(value):
		return None
	try:
		result = int(value)  # type: ignore[arg-type]
	except ValueError as error:
		raise ConfigurationError(f"{name} must be an integer") from error
	if result <= 0:
		raise ConfigurationError(f"{name} must be greater than zero")
	return result


def _int(value: str | None, default: int, name: str) -> int:
	parsed = _optional_int(value, name)
	return default if parsed is None else parsed


def _int_list(value: str | None) -> tuple[int, ...]:
	text = _optional_text(value)
	if not text:
		return ()
	identifiers = tuple(
		_optional_int(item.strip(), "AUTHORIZED_REVIEWER_IDS")
		for item in text.split(",")
		if item.strip()
	)
	return tuple(identifier for identifier in identifiers if identifier is not None)


def _optional_path(value: str | None) -> Path | None:
	text = _optional_text(value)
	return Path(text).expanduser() if text else None


def _origins(value: str | None) -> tuple[str, ...]:
	text = _optional_text(value)
	if not text:
		return ("http://localhost:3000",)
	origins = tuple(origin.strip().rstrip("/") for origin in text.split(",") if origin.strip())
	if not origins:
		raise ConfigurationError("CORS_ORIGINS must contain at least one origin")
	return origins


def _validate_url(value: str, name: str) -> None:
	parsed = urlparse(value)
	if parsed.scheme not in {"http", "https"} or not parsed.netloc:
		raise ConfigurationError(f"{name} must be an absolute HTTP(S) URL")
