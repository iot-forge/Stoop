"""Ring account linking: OAuth 2.0 tokens, refresh, PKCE, and the one-way nonce handshake.

Ring supports two linking flows (see https://developer.amazon.com/docs/ring/api-documentation.html):

* **One-Way (Ring-driven)**, the current default. The user starts in the Ring Appstore. Ring
  sends an authorization code to the partner's *Token Exchange URL*, the partner exchanges
  it for tokens and looks up the Ring account id, then Ring redirects the user's browser to
  the partner's *Account Link URL* with ``nonce`` and ``time``. The partner proves which
  freshly exchanged token belongs to this browser by recomputing
  ``base64url(HMAC-SHA256(hmac_key, f"{time}:{account_id}"))`` for each unclaimed token.
* **Partner-Initiated**, invite-only. Classic authorization-code flow with mandatory PKCE.

This module implements the token client, PKCE helpers, nonce matching and a small
:class:`RingLinker` that ties them to a :class:`TokenStore`. Web routes live in the app.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import logging
import secrets
import time as _time
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlencode

import httpx
from pydantic import BaseModel, ConfigDict, Field

log = logging.getLogger(__name__)

DEFAULT_TOKEN_URL = "https://oauth.ring.com/oauth/token"
DEFAULT_AUTHORIZE_URL = "https://account.ring.com/account/integrations/partner-link/authorize"
DEFAULT_API_BASE = "https://api.amazonvision.com"
DEFAULT_SCOPE = "ava.v1:read"
NONCE_MAX_AGE_S = 600


class RingOAuthError(Exception):
    """Token endpoint or integration API failure. ``code`` is Ring's ``error`` field when present."""

    def __init__(self, status: int, code: str | None, description: str | None = None) -> None:
        super().__init__(f"{status} {code or 'error'}: {description or ''}".strip())
        self.status = status
        self.code = code
        self.description = description


class TokenSet(BaseModel):
    """What a successful exchange or refresh returns, plus what we learned about the account."""

    model_config = ConfigDict(extra="ignore")

    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"
    scope: str | None = None
    expires_at: datetime
    obtained_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    account_id: str | None = None
    account_identifier: str | None = None  # masked email from /v1/users/me

    @classmethod
    def from_response(cls, body: dict[str, Any], *, now: datetime | None = None, previous: TokenSet | None = None) -> TokenSet:
        now = now or datetime.now(tz=UTC)
        expires_in = body.get("expires_in")
        ttl = int(expires_in) if isinstance(expires_in, (int, float, str)) and str(expires_in).isdigit() else 14400
        return cls(
            access_token=body["access_token"],
            refresh_token=body.get("refresh_token") or (previous.refresh_token if previous else None),
            token_type=body.get("token_type") or "Bearer",
            scope=body.get("scope") or (previous.scope if previous else None),
            expires_at=now + timedelta(seconds=ttl),
            obtained_at=now,
            account_id=previous.account_id if previous else None,
            account_identifier=previous.account_identifier if previous else None,
        )

    def expires_within(self, seconds: float, *, now: datetime | None = None) -> bool:
        now = now or datetime.now(tz=UTC)
        return self.expires_at <= now + timedelta(seconds=seconds)

    @property
    def expired(self) -> bool:
        return self.expires_within(0)


class RingOAuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_id: str
    client_secret: str
    hmac_key: str | None = None  # signs webhooks and one-way nonces
    token_url: str = DEFAULT_TOKEN_URL
    authorize_url: str = DEFAULT_AUTHORIZE_URL
    api_base: str = DEFAULT_API_BASE
    scope: str = DEFAULT_SCOPE


# ------------------------------------------------------------------------- PKCE
def pkce_pair() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge)`` for S256, the only method Ring accepts."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode("ascii")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


def new_state() -> str:
    return secrets.token_urlsafe(24)


# ------------------------------------------------------------------------ nonce
def compute_nonce(hmac_key: str, time_value: str | int, account_id: str) -> str:
    """One-way linking nonce: URL-safe base64, no padding, of HMAC-SHA256 over ``"<time>:<account_id>"``."""
    digest = hmac.new(hmac_key.encode(), f"{time_value}:{account_id}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def nonce_is_fresh(time_value: str | int, *, now: float | None = None, max_age_s: int = NONCE_MAX_AGE_S) -> bool:
    """``time`` from Ring is a Unix timestamp (seconds or milliseconds); accept both."""
    try:
        t = float(time_value)
    except (TypeError, ValueError):
        return False
    if t > 1e11:  # milliseconds
        t /= 1000.0
    now = _time.time() if now is None else now
    return abs(now - t) <= max_age_s


def match_nonce(
    hmac_key: str,
    nonce: str,
    time_value: str | int,
    candidates: Iterable[tuple[str, str]],
    *,
    now: float | None = None,
    max_age_s: int = NONCE_MAX_AGE_S,
) -> str | None:
    """Find which ``(key, account_id)`` candidate produced ``nonce``. Constant-time per candidate.

    Returns the candidate key, or ``None`` when the timestamp is stale or nothing matches.
    """
    if not nonce or not nonce_is_fresh(time_value, now=now, max_age_s=max_age_s):
        return None
    wanted = nonce.strip().rstrip("=").encode("ascii", "ignore")
    for key, account_id in candidates:
        if hmac.compare_digest(compute_nonce(hmac_key, time_value, account_id).encode("ascii"), wanted):
            return key
    return None


# ------------------------------------------------------------------- client
class RingOAuth:
    """Token endpoint and app-integration calls. Synchronous, ``httpx`` only."""

    def __init__(self, config: RingOAuthConfig, *, timeout: float = 15.0, transport: httpx.BaseTransport | None = None) -> None:
        self.config = config
        self._http = httpx.Client(timeout=timeout, transport=transport)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> RingOAuth:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------ partner-initiated
    def authorize_url(self, *, redirect_uri: str, state: str, code_challenge: str, scope: str | None = None) -> str:
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope or self.config.scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{self.config.authorize_url}?{urlencode(params)}"

    # ---------------------------------------------------------------- tokens
    def exchange_code(self, code: str, *, code_verifier: str | None = None) -> TokenSet:
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        if code_verifier:
            form["code_verifier"] = code_verifier
        return TokenSet.from_response(self._token_request(form))

    def refresh(self, tokens: TokenSet) -> TokenSet:
        if not tokens.refresh_token:
            raise RingOAuthError(400, "invalid_request", "no refresh token; the user must link again")
        form = {
            "grant_type": "refresh_token",
            "refresh_token": tokens.refresh_token,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        return TokenSet.from_response(self._token_request(form), previous=tokens)

    def ensure_fresh(self, tokens: TokenSet, *, leeway_s: int = 300) -> TokenSet:
        """Return ``tokens`` unchanged when still valid for ``leeway_s``, else a refreshed set."""
        return self.refresh(tokens) if tokens.expires_within(leeway_s) else tokens

    def _token_request(self, form: dict[str, str]) -> dict[str, Any]:
        resp = self._http.post(self.config.token_url, data=form, headers={"Accept": "application/json"})
        if resp.status_code >= 400:
            code, desc = _oauth_error(resp)
            raise RingOAuthError(resp.status_code, code, desc)
        body = resp.json()
        if not isinstance(body, dict) or not isinstance(body.get("access_token"), str):
            raise RingOAuthError(resp.status_code, "invalid_response", "token response missing access_token")
        return body

    # ------------------------------------------------------------ account API
    def whoami(self, access_token: str) -> tuple[str, str | None]:
        """Ring account id and masked identifier from ``/v1/users/me``."""
        resp = self._http.get(f"{self.config.api_base}/v1/users/me", headers=_bearer(access_token))
        if resp.status_code >= 400:
            raise RingOAuthError(resp.status_code, "users_me_failed", resp.text[:200])
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {}) or {}
        return str(data.get("id")), attrs.get("email") or attrs.get("account_identifier")

    def enrich(self, tokens: TokenSet) -> TokenSet:
        account_id, ident = self.whoami(tokens.access_token)
        return tokens.model_copy(update={"account_id": account_id, "account_identifier": ident})

    def complete_integration(self, access_token: str, *, account_identifier: str | None, nonce: str | None = None) -> None:
        """Tell Ring the link is done. One-way flow passes the nonce (POST then PATCH); partner-initiated only PATCHes."""
        url = f"{self.config.api_base}/v1/accounts/me/app-integrations"
        headers = {**_bearer(access_token), "Content-Type": "application/json"}
        if nonce is not None:
            resp = self._http.post(url, json={"account_identifier": account_identifier, "nonce": nonce}, headers=headers)
            if resp.status_code >= 400:
                raise RingOAuthError(resp.status_code, "integration_post_failed", resp.text[:200])
            body: dict[str, Any] = {"status": "completed"}
        else:
            body = {"status": "completed", "account_identifier": account_identifier}
        resp = self._http.patch(url, json=body, headers=headers)
        if resp.status_code >= 400:
            raise RingOAuthError(resp.status_code, "integration_patch_failed", resp.text[:200])

    def unlink(self, access_token: str) -> bool:
        resp = self._http.delete(f"{self.config.api_base}/v1/accounts/me/app-integrations", headers=_bearer(access_token))
        return resp.status_code < 400


# -------------------------------------------------------------------- storage
@runtime_checkable
class TokenCipher(Protocol):
    def encrypt(self, data: bytes) -> bytes: ...

    def decrypt(self, token: bytes) -> bytes: ...


class NoCipher:
    """Plaintext storage. Only for tests and local development."""

    def encrypt(self, data: bytes) -> bytes:
        return data

    def decrypt(self, token: bytes) -> bytes:
        return token


@runtime_checkable
class TokenStore(Protocol):
    """Where linked-account tokens live. Keys are the app's own link ids."""

    def get(self, link_id: str) -> TokenSet | None: ...

    def put(self, link_id: str, tokens: TokenSet, *, owner: str | None = None) -> None: ...

    def delete(self, link_id: str) -> None: ...

    def owner_of(self, link_id: str) -> str | None: ...

    def claim(self, link_id: str, owner: str) -> None: ...

    def unclaimed(self, *, max_age_s: int = NONCE_MAX_AGE_S) -> list[tuple[str, TokenSet]]: ...

    def for_owner(self, owner: str) -> list[tuple[str, TokenSet]]: ...

    def by_account(self, account_id: str) -> tuple[str, TokenSet] | None: ...


class SqliteTokenStore:
    """Token store on top of :class:`stoop.memory.store.Store`'s SQLite connection.

    Token JSON is encrypted with ``cipher`` (pass a ``cryptography.fernet.Fernet``); the
    indexed columns hold only the link id, owner, Ring account id and timestamps.
    """

    def __init__(self, store: Any, *, cipher: TokenCipher | None = None) -> None:
        self._store = store
        self._cipher = cipher or NoCipher()
        self._store.execute(
            "CREATE TABLE IF NOT EXISTS ring_links ("
            " link_id TEXT PRIMARY KEY, owner TEXT, account_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, blob BLOB NOT NULL)"
        )
        self._store.execute("CREATE INDEX IF NOT EXISTS ix_ring_links_owner ON ring_links(owner)")

    def _decode(self, blob: bytes) -> TokenSet:
        return TokenSet.model_validate_json(self._cipher.decrypt(bytes(blob)))

    def get(self, link_id: str) -> TokenSet | None:
        rows = self._store.query("SELECT blob FROM ring_links WHERE link_id=?", (link_id,))
        return self._decode(rows[0]["blob"]) if rows else None

    def put(self, link_id: str, tokens: TokenSet, *, owner: str | None = None) -> None:
        now = datetime.now(tz=UTC).isoformat()
        existing = self._store.query("SELECT owner, created_at FROM ring_links WHERE link_id=?", (link_id,))
        created = existing[0]["created_at"] if existing else now
        owner = owner if owner is not None else (existing[0]["owner"] if existing else None)
        blob = self._cipher.encrypt(tokens.model_dump_json().encode())
        self._store.execute(
            "INSERT OR REPLACE INTO ring_links(link_id, owner, account_id, created_at, updated_at, blob) VALUES (?,?,?,?,?,?)",
            (link_id, owner, tokens.account_id, created, now, blob),
        )

    def delete(self, link_id: str) -> None:
        self._store.execute("DELETE FROM ring_links WHERE link_id=?", (link_id,))

    def owner_of(self, link_id: str) -> str | None:
        rows = self._store.query("SELECT owner FROM ring_links WHERE link_id=?", (link_id,))
        return rows[0]["owner"] if rows else None

    def claim(self, link_id: str, owner: str) -> None:
        self._store.execute(
            "UPDATE ring_links SET owner=?, updated_at=? WHERE link_id=?", (owner, datetime.now(tz=UTC).isoformat(), link_id)
        )

    def unclaimed(self, *, max_age_s: int = NONCE_MAX_AGE_S) -> list[tuple[str, TokenSet]]:
        cutoff = (datetime.now(tz=UTC) - timedelta(seconds=max_age_s)).isoformat()
        rows = self._store.query(
            "SELECT link_id, blob FROM ring_links WHERE owner IS NULL AND created_at>=? ORDER BY created_at DESC", (cutoff,)
        )
        return [(r["link_id"], self._decode(r["blob"])) for r in rows]

    def for_owner(self, owner: str) -> list[tuple[str, TokenSet]]:
        rows = self._store.query("SELECT link_id, blob FROM ring_links WHERE owner=? ORDER BY created_at", (owner,))
        return [(r["link_id"], self._decode(r["blob"])) for r in rows]

    def by_account(self, account_id: str) -> tuple[str, TokenSet] | None:
        rows = self._store.query(
            "SELECT link_id, blob FROM ring_links WHERE account_id=? AND owner IS NOT NULL ORDER BY updated_at DESC LIMIT 1", (account_id,)
        )
        return (rows[0]["link_id"], self._decode(rows[0]["blob"])) if rows else None

    def purge_unclaimed(self, *, older_than_s: int = NONCE_MAX_AGE_S) -> int:
        cutoff = (datetime.now(tz=UTC) - timedelta(seconds=older_than_s)).isoformat()
        cur = self._store.execute("DELETE FROM ring_links WHERE owner IS NULL AND created_at<?", (cutoff,))
        return cur.rowcount


# --------------------------------------------------------------------- linker
class RingLinker:
    """Glue between the OAuth client and a token store for both linking flows."""

    def __init__(self, oauth: RingOAuth, tokens: TokenStore) -> None:
        self.oauth = oauth
        self.tokens = tokens

    # ---------------------------------------------------------------- one-way
    def receive_code(self, code: str, *, link_id: str | None = None) -> str:
        """Token Exchange URL handler: exchange, look up the account, park as unclaimed. Returns the link id."""
        link_id = link_id or f"lnk_{secrets.token_hex(8)}"
        tokens = self.oauth.enrich(self.oauth.exchange_code(code))
        self.tokens.put(link_id, tokens, owner=None)
        return link_id

    def claim_by_nonce(self, *, nonce: str, time_value: str | int, owner: str) -> str | None:
        """Account Link URL handler: match the browser's nonce to an unclaimed token and bind it to ``owner``.

        Completes the integration on Ring's side. Returns the link id, or ``None`` if nothing matched.
        """
        key = self.oauth.config.hmac_key
        if not key:
            raise RingOAuthError(500, "misconfigured", "hmac_key is required for one-way linking")
        candidates = [(lid, t.account_id) for lid, t in self.tokens.unclaimed() if t.account_id]
        link_id = match_nonce(key, nonce, time_value, candidates)
        if link_id is None:
            return None
        tokens = self.tokens.get(link_id)
        assert tokens is not None
        self.tokens.claim(link_id, owner)
        self.oauth.complete_integration(tokens.access_token, account_identifier=tokens.account_identifier, nonce=nonce)
        return link_id

    # ------------------------------------------------------ partner-initiated
    def finish_authorization(self, *, code: str, code_verifier: str, owner: str, link_id: str | None = None) -> str:
        link_id = link_id or f"lnk_{secrets.token_hex(8)}"
        tokens = self.oauth.enrich(self.oauth.exchange_code(code, code_verifier=code_verifier))
        self.tokens.put(link_id, tokens, owner=owner)
        self.oauth.complete_integration(tokens.access_token, account_identifier=tokens.account_identifier)
        return link_id

    # ----------------------------------------------------------------- usage
    def access_token(self, link_id: str, *, leeway_s: int = 300) -> str:
        """A valid access token for ``link_id``, refreshing and persisting when needed."""
        tokens = self.tokens.get(link_id)
        if tokens is None:
            raise RingOAuthError(404, "unknown_link", link_id)
        fresh = self.oauth.ensure_fresh(tokens, leeway_s=leeway_s)
        if fresh is not tokens:
            self.tokens.put(link_id, fresh)
        return fresh.access_token

    def unlink(self, link_id: str) -> None:
        tokens = self.tokens.get(link_id)
        if tokens is not None:
            try:
                self.oauth.unlink(tokens.access_token)
            except httpx.HTTPError:  # pragma: no cover - best effort
                log.warning("Ring unlink call failed for %s", link_id)
        self.tokens.delete(link_id)


# -------------------------------------------------------------------- helpers
def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def _oauth_error(resp: httpx.Response) -> tuple[str | None, str | None]:
    try:
        body = resp.json()
    except ValueError:
        return None, resp.text[:200]
    if isinstance(body, dict):
        if "error" in body:
            return str(body.get("error")), body.get("error_description")
        errs = body.get("errors")
        if isinstance(errs, list) and errs:
            first = errs[0] or {}
            return first.get("code") or first.get("title"), first.get("detail")
    return None, resp.text[:200]


def extract_exchange_code(body: bytes, content_type: str, query: Any) -> str | None:
    """Ring does not document the token-exchange request shape; accept JSON, form or query."""
    candidates = ("code", "authorization_code", "authorizationCode", "auth_code")
    data: dict[str, Any] = {}
    if body:
        if "json" in content_type:
            with contextlib.suppress(ValueError):
                data = json.loads(body) or {}
        elif "form" in content_type:
            from urllib.parse import parse_qs

            data = {k: v[0] for k, v in parse_qs(body.decode(errors="ignore")).items()}
        else:
            with contextlib.suppress(ValueError):
                data = json.loads(body) or {}
    for key in candidates:
        if isinstance(data, dict) and data.get(key):
            return str(data[key])
        if query.get(key):
            return str(query.get(key))
    return None
