from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from ring_sandbox.emulator import create_app
from ring_sandbox.pytest_plugin import _SyncASGITransport
from ring_sandbox.world import default_world

from stoop import Store
from stoop.sources.ring_oauth import (
    NoCipher,
    RingLinker,
    RingOAuth,
    RingOAuthConfig,
    RingOAuthError,
    SqliteTokenStore,
    TokenSet,
    compute_nonce,
    match_nonce,
    pkce_pair,
)

HMAC = "shared-signing-key"


def _config(**over) -> RingOAuthConfig:
    base = {"client_id": "cid", "client_secret": "sec", "hmac_key": HMAC, "token_url": "http://ring/oauth/token", "api_base": "http://ring"}
    base.update(over)
    return RingOAuthConfig(**base)


class FakeRing:
    """Minimal Ring: token endpoint (code + refresh), /v1/users/me, app-integrations."""

    def __init__(self, account_id: str = "ava1.ring.account.ABC", email: str = "u***@example.com"):
        self.account_id = account_id
        self.email = email
        self.codes: dict[str, str | None] = {}  # code -> expected code_verifier
        self.issued: list[str] = []
        self.integration_calls: list[tuple[str, dict]] = []
        self.unlinked = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth/token":
            form = dict(httpx.QueryParams(request.content.decode()))
            if form.get("client_id") != "cid" or form.get("client_secret") != "sec":
                return httpx.Response(401, json={"error": "invalid_client"})
            if form.get("grant_type") == "authorization_code":
                if form.get("code") not in self.codes:
                    return httpx.Response(400, json={"error": "invalid_grant", "error_description": "bad code"})
                want = self.codes.pop(form["code"])
                if want is not None and form.get("code_verifier") != want:
                    return httpx.Response(400, json={"error": "invalid_grant", "error_description": "pkce mismatch"})
            elif form.get("grant_type") == "refresh_token":
                if form.get("refresh_token") == "dead":
                    return httpx.Response(400, json={"error": "invalid_grant", "error_description": "refresh expired"})
            else:
                return httpx.Response(400, json={"error": "unsupported_grant_type"})
            tok = f"at-{len(self.issued)}"
            self.issued.append(tok)
            return httpx.Response(200, json={"access_token": tok, "refresh_token": f"rt-{len(self.issued)}", "expires_in": 14400, "token_type": "Bearer", "scope": "ava.v1:read"})
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer at-"):
            return httpx.Response(401, json={"errors": [{"status": "401", "detail": "bad token"}]})
        if request.url.path == "/v1/users/me":
            return httpx.Response(200, json={"data": {"type": "users", "id": self.account_id, "attributes": {"email": self.email}}})
        if request.url.path == "/v1/accounts/me/app-integrations":
            if request.method == "DELETE":
                self.unlinked += 1
                return httpx.Response(200, json={"data": {"type": "app-integrations", "attributes": {"status": "deleted"}}})
            self.integration_calls.append((request.method, json.loads(request.content or b"{}")))
            return httpx.Response(200, json={"data": {"type": "app-integrations", "attributes": {"status": "awaiting" if request.method == "POST" else "completed"}}})
        return httpx.Response(404)


@pytest.fixture
def ring() -> FakeRing:
    return FakeRing()


@pytest.fixture
def oauth(ring: FakeRing) -> RingOAuth:
    return RingOAuth(_config(), transport=httpx.MockTransport(ring.handler))


@pytest.fixture
def tokens_store() -> SqliteTokenStore:
    return SqliteTokenStore(Store(":memory:"), cipher=NoCipher())


# ------------------------------------------------------------------ primitives
def test_pkce_pair_shape():
    verifier, challenge = pkce_pair()
    assert 43 <= len(verifier) <= 128 and "=" not in challenge and "=" not in verifier
    assert pkce_pair()[0] != verifier


def test_nonce_matches_only_fresh_and_correct():
    now = time.time()
    t = int(now)
    nonce = compute_nonce(HMAC, t, "acct-1")
    cands = [("lnk_a", "acct-0"), ("lnk_b", "acct-1")]
    assert match_nonce(HMAC, nonce, t, cands, now=now) == "lnk_b"
    assert match_nonce(HMAC, nonce, t, cands, now=now + 601) is None  # stale
    assert match_nonce(HMAC, nonce + "x", t, cands, now=now) is None  # wrong
    assert match_nonce("other-key", nonce, t, cands, now=now) is None
    # Milliseconds are accepted too.
    nonce_ms = compute_nonce(HMAC, t * 1000, "acct-1")
    assert match_nonce(HMAC, nonce_ms, t * 1000, cands, now=now) == "lnk_b"


def test_tokenset_from_response_keeps_previous_refresh_and_account():
    prev = TokenSet(access_token="a", refresh_token="r1", expires_at=datetime.now(tz=UTC), account_id="acct")
    nxt = TokenSet.from_response({"access_token": "b", "expires_in": "60"}, previous=prev)
    assert nxt.refresh_token == "r1" and nxt.account_id == "acct"
    assert nxt.expires_within(61) and not nxt.expires_within(10)


# ---------------------------------------------------------------------- client
def test_authorize_url_has_pkce_and_state(oauth: RingOAuth):
    url = oauth.authorize_url(redirect_uri="https://app/cb", state="st", code_challenge="ch")
    assert url.startswith("https://account.ring.com/account/integrations/partner-link/authorize?")
    assert "code_challenge_method=S256" in url and "state=st" in url and "response_type=code" in url


def test_exchange_refresh_and_errors(oauth: RingOAuth, ring: FakeRing):
    ring.codes["good"] = None
    t = oauth.exchange_code("good")
    assert t.access_token == "at-0" and t.refresh_token == "rt-1" and not t.expired
    with pytest.raises(RingOAuthError) as ei:
        oauth.exchange_code("good")  # single use
    assert ei.value.code == "invalid_grant"
    stale = t.model_copy(update={"expires_at": datetime.now(tz=UTC) + timedelta(seconds=30)})
    fresh = oauth.ensure_fresh(stale, leeway_s=300)
    assert fresh.access_token == "at-1" and fresh is not stale
    assert oauth.ensure_fresh(fresh) is fresh
    with pytest.raises(RingOAuthError):
        oauth.refresh(fresh.model_copy(update={"refresh_token": "dead"}))


def test_refresh_against_emulator():
    """The ring-sandbox emulator implements the refresh grant; prove we speak it."""
    world = default_world()
    transport = _SyncASGITransport(create_app(world))
    oauth = RingOAuth(_config(token_url="http://sandbox/oauth/token", api_base="http://sandbox"), transport=transport)
    old = TokenSet(access_token="sandbox-token", refresh_token="sandbox-refresh-1", expires_at=datetime.now(tz=UTC))
    new = oauth.refresh(old)
    assert new.access_token.startswith("sandbox-") and new.access_token != "sandbox-token"
    account_id, _ = oauth.whoami(new.access_token)
    assert account_id == world.account_id


# ---------------------------------------------------------------------- store
def test_sqlite_token_store_roundtrip_and_claims(tokens_store: SqliteTokenStore):
    class Rot13:
        def encrypt(self, b: bytes) -> bytes:
            return bytes((x + 1) % 256 for x in b)

        def decrypt(self, b: bytes) -> bytes:
            return bytes((x - 1) % 256 for x in b)

    st = SqliteTokenStore(Store(":memory:"), cipher=Rot13())
    t = TokenSet(access_token="secret-at", refresh_token="rt", expires_at=datetime.now(tz=UTC), account_id="acct-1")
    st.put("lnk_1", t)
    raw = st._store.query("SELECT blob FROM ring_links")[0]["blob"]
    assert b"secret-at" not in bytes(raw)
    assert st.get("lnk_1").access_token == "secret-at"
    assert st.unclaimed() and st.owner_of("lnk_1") is None
    st.claim("lnk_1", "user-7")
    assert st.unclaimed() == [] and st.for_owner("user-7")[0][0] == "lnk_1"
    assert st.by_account("acct-1")[0] == "lnk_1"
    st.delete("lnk_1")
    assert st.get("lnk_1") is None


# --------------------------------------------------------------------- linker
def test_one_way_flow_end_to_end(oauth: RingOAuth, ring: FakeRing, tokens_store: SqliteTokenStore):
    linker = RingLinker(oauth, tokens_store)
    # 1. Ring posts the code to our Token Exchange URL.
    ring.codes["c-1"] = None
    link_id = linker.receive_code("c-1")
    parked = tokens_store.get(link_id)
    assert parked.account_id == ring.account_id and tokens_store.owner_of(link_id) is None
    # 2. Ring redirects the browser to our Account Link URL with nonce + time.
    t = int(time.time())
    nonce = compute_nonce(HMAC, t, ring.account_id)
    assert linker.claim_by_nonce(nonce="nope", time_value=t, owner="user-1") is None
    assert linker.claim_by_nonce(nonce=nonce, time_value=t, owner="user-1") == link_id
    assert tokens_store.owner_of(link_id) == "user-1"
    assert [m for m, _ in ring.integration_calls] == ["POST", "PATCH"]
    assert ring.integration_calls[0][1]["nonce"] == nonce
    # 3. Using the link refreshes transparently and persists.
    tokens_store.put(link_id, parked.model_copy(update={"expires_at": datetime.now(tz=UTC)}))
    at = linker.access_token(link_id)
    assert at.startswith("at-") and tokens_store.get(link_id).access_token == at
    linker.unlink(link_id)
    assert ring.unlinked == 1 and tokens_store.get(link_id) is None


def test_partner_initiated_flow(oauth: RingOAuth, ring: FakeRing, tokens_store: SqliteTokenStore):
    linker = RingLinker(oauth, tokens_store)
    verifier, challenge = pkce_pair()
    ring.codes["c-2"] = verifier
    url = oauth.authorize_url(redirect_uri="https://app/cb", state="s", code_challenge=challenge)
    assert challenge in url
    link_id = linker.finish_authorization(code="c-2", code_verifier=verifier, owner="user-2")
    assert tokens_store.owner_of(link_id) == "user-2"
    assert ring.integration_calls == [("PATCH", {"status": "completed", "account_identifier": ring.email})]


def test_claim_requires_hmac_key(ring: FakeRing, tokens_store: SqliteTokenStore):
    oauth = RingOAuth(_config(hmac_key=None), transport=httpx.MockTransport(ring.handler))
    with pytest.raises(RingOAuthError):
        RingLinker(oauth, tokens_store).claim_by_nonce(nonce="n", time_value=1, owner="u")
