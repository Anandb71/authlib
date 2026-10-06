import time
from unittest import mock

import pytest
import requests
from flask import Flask
from joserfc import jwt
from joserfc.errors import InvalidClaimError
from joserfc.errors import MissingClaimError
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey

from authlib.integrations.flask_client import OAuth
from authlib.oidc.core.grants.util import create_half_hash

from ..util import get_bearer_token
from ..util import read_key_file

secret_key = OctKey.import_key("test-oct-secret", {"kty": "oct", "kid": "f"})


def test_fetch_userinfo():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        userinfo_endpoint="https://provider.test/userinfo",
    )

    def fake_send(sess, req, **kwargs):
        resp = mock.MagicMock()
        resp.json = lambda: {"sub": "123"}
        resp.status_code = 200
        return resp

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            user = client.userinfo()
            assert user.sub == "123"


def test_parse_id_token():
    token = get_bearer_token()
    now = int(time.time())
    claims = {
        "sub": "123",
        "iss": "https://provider.test",
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
        "nonce": "n",
        "at_hash": create_half_hash(token["access_token"], "HS256").decode("utf-8"),
    }
    id_token = jwt.encode({"alg": "HS256"}, claims, secret_key)

    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        jwks={"keys": [secret_key.as_dict()]},
        issuer="https://provider.test",
        id_token_signing_alg_values_supported=["HS256", "RS256"],
    )
    with app.test_request_context():
        assert client.parse_id_token(token, nonce="n") is None

        token["id_token"] = id_token
        user = client.parse_id_token(token, nonce="n")
        assert user.sub == "123"

        claims_options = {"iss": {"value": "https://provider.test"}}
        user = client.parse_id_token(token, nonce="n", claims_options=claims_options)
        assert user.sub == "123"

        claims_options = {"iss": {"value": "https://wrong-provider.test"}}
        with pytest.raises(InvalidClaimError):
            client.parse_id_token(token, "n", claims_options)


def test_parse_id_token_nonce_supported():
    token = get_bearer_token()

    now = int(time.time())
    claims = {
        "sub": "123",
        "nonce_supported": False,
        "iss": "https://provider.test",
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
        "at_hash": create_half_hash(token["access_token"], "HS256").decode("utf-8"),
    }
    id_token = jwt.encode({"alg": "HS256"}, claims, secret_key)

    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        jwks={"keys": [secret_key.as_dict()]},
        issuer="https://provider.test",
        id_token_signing_alg_values_supported=["HS256", "RS256"],
    )
    with app.test_request_context():
        token["id_token"] = id_token
        user = client.parse_id_token(token, nonce="n")
        assert user.sub == "123"


def test_runtime_error_fetch_jwks_uri():
    token = get_bearer_token()
    now = int(time.time())
    claims = {
        "sub": "123",
        "nonce": "n",
        "iss": "https://provider.test",
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
        "at_hash": create_half_hash(token["access_token"], "HS256").decode("utf-8"),
    }
    id_token = jwt.encode({"alg": "HS256", "kid": "not-found"}, claims, secret_key)

    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    alt_key = secret_key.as_dict()
    alt_key["kid"] = "b"
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        jwks={"keys": [alt_key]},
        issuer="https://provider.test",
        id_token_signing_alg_values_supported=["HS256"],
    )
    with app.test_request_context():
        token["id_token"] = id_token
        with pytest.raises(RuntimeError):
            client.parse_id_token(token, "n")


def test_force_fetch_jwks_uri():
    secret_keys = KeySet.import_key_set(read_key_file("jwks_private.json"))
    token = get_bearer_token()
    now = int(time.time())
    claims = {
        "sub": "123",
        "nonce": "n",
        "iss": "https://provider.test",
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
        "at_hash": create_half_hash(token["access_token"], "RS256").decode("utf-8"),
    }
    id_token = jwt.encode({"alg": "RS256"}, claims, secret_keys)

    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        jwks={"keys": [secret_key.as_dict()]},
        jwks_uri="https://provider.test/jwks",
        issuer="https://provider.test",
    )

    def fake_send(sess, req, **kwargs):
        resp = mock.MagicMock()
        resp.json = lambda: read_key_file("jwks_public.json")
        resp.status_code = 200
        return resp

    with app.test_request_context():
        assert client.parse_id_token(token, nonce="n") is None

        with mock.patch("requests.sessions.Session.send", fake_send):
            token["id_token"] = id_token
            user = client.parse_id_token(token, nonce="n")
            assert user.sub == "123"


def _openid_userinfo_client():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        userinfo_endpoint="https://provider.test/userinfo",
        jwks={"keys": [secret_key.as_dict()]},
        issuer="https://provider.test",
        userinfo_signing_alg_values_supported=["HS256", "RS256"],
    )
    return app, client


def _userinfo_claims():
    return {
        "sub": "123",
        "iss": "https://provider.test",
        "aud": "dev",
        "email": "user@example.com",
    }


def _signed_userinfo_send(claims, content_type="application/jwt"):
    token = jwt.encode({"alg": "HS256"}, claims, secret_key)

    def fake_send(sess, req, **kwargs):
        resp = requests.Response()
        resp.status_code = 200
        resp.headers["Content-Type"] = content_type
        resp._content = token.encode()
        resp.encoding = "utf-8"
        return resp

    return fake_send


@pytest.mark.parametrize(
    "content_type",
    ["application/jwt", "application/jwt; charset=utf-8", "APPLICATION/JWT"],
)
def test_fetch_userinfo_signed(content_type):
    app, client = _openid_userinfo_client()
    fake_send = _signed_userinfo_send(_userinfo_claims(), content_type)
    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            user = client.userinfo()
            assert user.sub == "123"
            assert user.email == "user@example.com"
            assert user["iss"] == "https://provider.test"
            assert user["aud"] == "dev"


def test_fetch_userinfo_signed_aud_list():
    app, client = _openid_userinfo_client()
    claims = _userinfo_claims()
    claims["aud"] = ["other", "dev"]
    fake_send = _signed_userinfo_send(claims)
    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            user = client.userinfo()
            assert user.sub == "123"
            assert user["aud"] == ["other", "dev"]


def test_fetch_userinfo_signed_bad_aud():
    app, client = _openid_userinfo_client()
    claims = _userinfo_claims()
    claims["aud"] = "other"
    fake_send = _signed_userinfo_send(claims)
    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            with pytest.raises(InvalidClaimError):
                client.userinfo()


def test_fetch_userinfo_signed_bad_iss():
    app, client = _openid_userinfo_client()
    claims = _userinfo_claims()
    claims["iss"] = "https://wrong-provider.test"
    fake_send = _signed_userinfo_send(claims)
    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            with pytest.raises(InvalidClaimError):
                client.userinfo()


@pytest.mark.parametrize("claim", ["iss", "aud"])
def test_fetch_userinfo_signed_missing_claim(claim):
    app, client = _openid_userinfo_client()
    claims = _userinfo_claims()
    del claims[claim]
    fake_send = _signed_userinfo_send(claims)
    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            with pytest.raises(MissingClaimError):
                client.userinfo()
