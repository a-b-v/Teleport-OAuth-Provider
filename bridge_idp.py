# Copyright (c) 2025 a-b-v
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os, time, uuid, base64, hashlib, json, logging, asyncio, httpx, re
from typing import Dict, Any
from fastapi import FastAPI, Header, HTTPException, Form, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.exception_handlers import http_exception_handler
import jwt
from cachetools import TTLCache
from cryptography.hazmat.primitives import serialization

ALLOWED_TP_ALGS = {"RS256", "ES256"}

# ──────────────────────────  Runtime configuration  ──────────────────────────
BRIDGE_ISS         = os.getenv("BRIDGE_ISSUER",  "https://oidc-bridge.internal")
JWKS_URI           = os.getenv("BRIDGE_JWKS_URI", f"{BRIDGE_ISS}/.well-known/jwks.json")
AUTH_ENDPOINT      = os.getenv("BRIDGE_AUTH_ENDPOINT", f"{BRIDGE_ISS}/authorize")
TOKEN_ENDPOINT     = os.getenv("BRIDGE_TOKEN_ENDPOINT", f"{BRIDGE_ISS}/token")
USERINFO_ENDPOINT  = os.getenv("BRIDGE_USERINFO_ENDPOINT", f"{BRIDGE_ISS}/userinfo")
KID                = os.getenv("BRIDGE_KID", "bridge-2025-04")

TP_JWKS_URL  = os.getenv("TELEPORT_JWKS_URL")
TP_ISS       = os.getenv("TELEPORT_ISSUER")
TP_AUD       = os.getenv("TELEPORT_AUD")
PRIV_KEY     = serialization.load_pem_private_key(
                open(os.getenv("PRIVATE_KEY_FILE", "idp-private.pem"), "rb").read(),
                password=None)

DEBUG = os.getenv("BRIDGE_DEBUG", "false").lower() == "true"
logging.basicConfig(level=logging.DEBUG if DEBUG else logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("bridge")
httpx_logger = logging.getLogger("httpx")
httpx_logger.setLevel(logging.CRITICAL)

# ───────────────────  Build in‑memory discovery & JWKS docs  ──────────────────
PUBLIC_KEY = PRIV_KEY.public_key()
nums = PUBLIC_KEY.public_numbers()

def _b64(n: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7)//8, "big"))\
           .rstrip(b"=").decode()

JWKS_DOC = {
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": KID,
        "n": _b64(nums.n),
        "e": _b64(nums.e),
    }]
}

DISCOVERY_DOC = {
    "issuer": BRIDGE_ISS,
    "jwks_uri": JWKS_URI,
    "authorization_endpoint": AUTH_ENDPOINT,
    "token_endpoint": TOKEN_ENDPOINT,
    "userinfo_endpoint": USERINFO_ENDPOINT,
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}

# ───────────────────  JWKS fetch/refresh (Teleport)  ──────────────────────────
_jwks_cache = TTLCache(maxsize=1, ttl=300)

async def get_teleport_key(kid: str):
    keys = _jwks_cache.get("keys")
    if not keys:
        if DEBUG:
            log.debug(f"Fetching Teleport JWKS from {TP_JWKS_URL}")
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(TP_JWKS_URL)
            if not DEBUG:
                log.info(f"REQUEST TO TELEPORT: GET {TP_JWKS_URL} {r.status_code}")
            if DEBUG:
                log.debug(f"Teleport JWKS response {r.status_code}: {r.text[:500]}")
                try:
                    log.debug(f"Full Teleport JWKS JSON: {json.dumps(r.json(), indent=2)}")
                except Exception:
                    pass
            r.raise_for_status()
            jwks_data = r.json()
            if "jwks_uri" in jwks_data and "keys" not in jwks_data:
                if DEBUG:
                    log.debug(f"Received OIDC discovery document; fetching JWKS from {jwks_data['jwks_uri']}")
                r = await client.get(jwks_data["jwks_uri"])
                if DEBUG:
                    log.debug(f"Teleport JWKS response from jwks_uri {r.status_code}: {r.text[:500]}")
                    try:
                        log.debug(f"Full Teleport JWKS JSON from jwks_uri: {json.dumps(r.json(), indent=2)}")
                    except Exception:
                        pass
                r.raise_for_status()
                jwks_data = r.json()
            if "keys" not in jwks_data or not isinstance(jwks_data["keys"], list):
                if DEBUG:
                    log.debug(f"Invalid JWKS response: missing or invalid 'keys' field: {jwks_data}")
                raise HTTPException(502, "Invalid JWKS response from Teleport: missing or invalid 'keys' field")
        _jwks_cache["keys"] = {k["kid"]: k for k in jwks_data["keys"]}
        keys = _jwks_cache["keys"]

    jwk = keys.get(kid)
    if not jwk:
        # nuke cache so a retry can refresh after rotation
        _jwks_cache.pop("keys", None)
        raise HTTPException(401, "unknown kid")

    kty = jwk.get("kty")
    alg = jwk.get("alg")
    try:
        if kty == "RSA":
            return jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
        elif kty == "EC":
            # Optionally sanity-check ES256 curve
            crv = jwk.get("crv")
            if alg and alg != "ES256":
                # You can allow others by removing this check
                log.warning(f"Unexpected EC alg in JWK: {alg}")
            if crv and crv != "P-256":
                log.warning(f"Unexpected EC curve in JWK: {crv}")
            return jwt.algorithms.ECAlgorithm.from_jwk(jwk)
        else:
            # Future-proofing: you can add OKP/EdDSA here if Teleport ever ships it
            raise HTTPException(502, f"Unsupported JWK kty from Teleport: {kty!r}")
    except Exception as e:
        if DEBUG:
            log.exception("Failed to construct verification key from JWK")
        raise HTTPException(502, f"Failed to build verification key from Teleport JWK: {e}")

# ─────────────────────  In‑memory authorization code store  ───────────────────
codes: TTLCache[str, Dict[str, Any]] = TTLCache(maxsize=10_000, ttl=120)

# ─────────────────────────────  FastAPI app  ──────────────────────────────────
app = FastAPI(title="Teleport‑to‑MinIO OIDC Bridge")

# Generic exception handler for unexpected errors
@app.exception_handler(Exception)
async def unexpected_exception_handler(request: Request, exc: Exception):
    if DEBUG:
        log.debug(f"Unexpected error in {request.method} {request.url}: {str(exc)}", exc_info=True)
    return await http_exception_handler(request, HTTPException(500, "Internal server error"))

# Debug request/response logging middleware
@app.middleware("http")
async def log_http(request: Request, call_next):
    body_bytes = await request.body()
    if DEBUG:
        log.debug("REQUEST %s %s\nHeaders: %s\nBody: %s", request.method, request.url,
                  dict(request.headers), body_bytes.decode(errors="ignore"))
    response: Response = await call_next(request)
    resp_body = b""  # collect response body (stream may be async)
    async for chunk in response.body_iterator:
        resp_body += chunk
    async def new_body_iterator():
        yield resp_body
    response.body_iterator = new_body_iterator()
    if DEBUG:
        log.debug("RESPONSE %s\nHeaders: %s\nBody: %s", response.status_code,
                  dict(response.headers), resp_body.decode(errors="ignore"))
    if not DEBUG:
        log.info("REQUEST: %s %s %d", request.method, request.url, response.status_code)
    return response

# OIDC discovery + JWKS
@app.get("/.well-known/openid-configuration")
async def discovery():
    return JSONResponse(DISCOVERY_DOC)

@app.get("/.well-known/jwks.json")
async def jwks():
    return JSONResponse(JWKS_DOC)

# Authorization endpoint
@app.get("/authorize")
async def authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "",
    state: str = "",
    nonce: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    authorization: str = Header(None, convert_underscores=False),
):
    # Validate basic parameters. The audience (client_id) is no longer hardcoded;
    # we simply ensure the flow is "code" and a client_id was supplied.
    if response_type != "code" or not client_id:
        raise HTTPException(400, "unsupported response_type or missing client_id")

    if not authorization or not authorization.lower().startswith("bearer "):
        if DEBUG:
            log.debug(f"No valid Bearer token: Authorization header={'missing' if authorization is None else f'invalid: {authorization}'}")
        raise HTTPException(401, "Teleport token required (Authorization: Bearer …)")

    try:
        tp_token = authorization.split(None, 1)[1]
    except IndexError:
        if DEBUG:
            log.debug(f"Invalid Authorization header format: {authorization}")
        raise HTTPException(401, "Teleport token required (Authorization: Bearer …)")

    try:
        header = jwt.get_unverified_header(tp_token)
        if DEBUG:
            log.debug(f"Received Teleport JWT: {tp_token[:50]}... (truncated)")
            log.debug(f"JWT header: {json.dumps(header, indent=2)}")
            try:
                unverified_claims = jwt.decode(tp_token, options={"verify_signature": False})
                debug_claims = {k: v for k, v in unverified_claims.items() if k not in ["jti", "sub", "email"]}
                log.debug(f"Received Teleport JWT claims (unverified): {json.dumps(debug_claims, indent=2)}")
                log.debug(f"Teleport JWT audience: expected '{TP_AUD}', got '{unverified_claims.get('aud', 'not present')}'")
            except jwt.InvalidTokenError as e:
                log.debug(f"Failed to decode Teleport JWT: {str(e)}")
        key = await get_teleport_key(header["kid"])
        try:
            claims = jwt.decode(tp_token, key=key, algorithms=list(ALLOWED_TP_ALGS), issuer=TP_ISS, audience=TP_AUD)
        except jwt.PyJWTError as e:
            if DEBUG and "Audience doesn't match" in str(e):
                unverified_claims = jwt.decode(tp_token, options={"verify_signature": False})
                actual_aud = unverified_claims.get("aud", "not present")
                log.debug(f"Audience mismatch: expected '{TP_AUD}', got '{actual_aud}'")
            raise HTTPException(401, f"Teleport token invalid: {e}")
    except jwt.InvalidTokenError as e:
        if DEBUG:
            log.debug(f"Invalid Teleport JWT format: {str(e)}")
        raise HTTPException(401, f"Teleport token invalid: {str(e)}")

    code = uuid.uuid4().hex
    codes[code] = {
        "nonce": nonce,
        "state": state,
        "cc_hash": code_challenge,
        "claims": claims,
        "client_id": client_id,  # Store dynamic audience for later verification
    }
    log.debug(f"Raw redirect_uri received: {redirect_uri}")
    redirect_uri = redirect_uri.rstrip('/')
    redirect_url = f"{redirect_uri}?code={code}&state={state}"
    log.debug(f"Final redirect_url = {redirect_url}")
    if DEBUG:
        debug_codes = codes[code].copy()
        debug_codes["claims"] = {k: v for k, v in debug_codes["claims"].items() if k not in ["jti", "sub", "email"]}
        log.debug(f"Generated authorization code: {code}, metadata: {json.dumps(debug_codes, indent=2)}")
        try:
            decoded_state = base64.urlsafe_b64decode(state.encode()).decode()
            log.debug(f"Decoded state parameter: {decoded_state}")
        except Exception as e:
            log.debug(f"Failed to decode state parameter: {str(e)}")
        log.debug(f"Sending to callback: code={code}, state={state}")
        log.debug(f"Redirecting to: {redirect_url}")
    return RedirectResponse(redirect_url)

# Token endpoint
@app.post("/token")
async def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    code_verifier: str = Form(None),
):
    if DEBUG:
        log.debug(f"Token request: grant_type='{grant_type}', code='{code}', client_id='{client_id}', redirect_uri='{redirect_uri}', code_verifier={'present' if code_verifier else 'not present'}")
    try:
        if grant_type != "authorization_code":
            raise HTTPException(400, "unsupported grant_type")

        # Retrieve and validate the stored authorization code
        data = codes.pop(code, None)
        if not data:
            raise HTTPException(400, "invalid or expired code")

        # Ensure the client_id matches what was supplied during /authorize
        if client_id != data.get("client_id"):
            raise HTTPException(400, "client_id mismatch")

        # PKCE verification (if present)
        if data["cc_hash"]:
            expected = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
            if expected != data["cc_hash"]:
                raise HTTPException(400, "PKCE check failed")

        # ──────────────  derive MinIO/STS policy/ies from Teleport roles  ──────────────
        teleport_roles: list[str] = []
        # 1️⃣  roles / role (plural & singular)
        if "roles" in data["claims"]:
            teleport_roles = data["claims"]["roles"] or []
        elif "role" in data["claims"]:
            teleport_roles = data["claims"]["role"] or []

        # 2️⃣  traits.policy (already the desired value)
        traits = data["claims"].get("traits", {})
        if isinstance(traits, dict) and "policy" in traits:
            # traits.policy may be a string or a list → normalise to list[str]
            if isinstance(traits["policy"], (list, tuple)):
                selected_policies: list[str] = list(traits["policy"])
            else:
                selected_policies = [traits["policy"]]
        else:
            # Normalise to list
            if not isinstance(teleport_roles, (list, tuple)):
                teleport_roles = [teleport_roles] if teleport_roles else []

            delimiter_pattern = r"[-_:]"
            role_regex = re.compile(
                rf"^{re.escape(client_id)}(?:{delimiter_pattern}(.+)|$)"
            )

            matching_policies: list[str] = []
            for role_name in teleport_roles:
                m = role_regex.match(role_name)
                if not m:
                    continue
                #  role == client‑id  → policy is the *whole* role name
                #  role == client‑id‑something  → policy is "something"
                matching_policies.append(m.group(1) or role_name)

            if matching_policies:
                selected_policies = matching_policies
            else:
                selected_policies = []
                log.info(
                    "No Teleport role matches client_id '%s'; issuing JWT with no "
                    "policy claim (sub=%s)",
                    client_id,
                    data["claims"].get("sub"),
                )
        # ────────────────────────────────────────────────────────────────────────────────
        now = int(time.time())

        id_token_claims = {
            "iss": BRIDGE_ISS,
            "sub": data["claims"]["sub"],
            "name": data["claims"].get("name", data["claims"]["sub"]),
            "email": data["claims"]["sub"],
            "aud": client_id,  # Dynamic audience
            "iat": now,
            "exp": now + 3600,
            "nonce": data["nonce"],
        }

        # Inject the policies claimD only if we discovered at least one
        if selected_policies:
            id_token_claims["policy"] = selected_policies

        id_token = jwt.encode(
            id_token_claims,
            PRIV_KEY,
            algorithm="RS256",
            headers={"kid": KID},
        )

        response = {
            "access_token": id_token,
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        if DEBUG:
            log.debug(f"Token response: {json.dumps(response, indent=2)}")
        return JSONResponse(response)
    except HTTPException as e:
        if DEBUG:
            log.debug(f"Token error: {e.detail}")
        raise

# Userinfo endpoint
@app.get("/userinfo")
@app.post("/userinfo")          # POST is optional but fully spec‑compliant
async def userinfo(
    request: Request,
    authorization: str | None = Header(None),  # standard Bearer header
):
    """
    OpenID Connect UserInfo endpoint.
    Returns a JSON object with user claims extracted from the access‑token.
    """
    # 1️⃣  Extract the access‑token
    token: str | None = None

    if DEBUG:
        log.debug("Raw Authorization header: %s", authorization)

    # a)  Authorization: Bearer <token>
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()

    # b)  ?access_token=…   or   POST access_token=<…>
    if not token:
        form = await request.form() if request.method == "POST" else {}
        token = request.query_params.get("access_token") or form.get("access_token")

    if not token:
        if DEBUG:
            log.debug("No access_token found in header, query or form")
        raise HTTPException(status_code=401, detail="missing access_token")

    if DEBUG:
        # Log header & unverified claims without dumping the whole JWT
        try:
            hdr = jwt.get_unverified_header(token)
            unverified = jwt.decode(token, options={"verify_signature": False})
            log.debug("JWT header: %s", hdr)
            log.debug("Unverified claims: %s", unverified)
        except Exception as exc:  # noqa: BLE001
            log.debug("Could not parse JWT before verification: %s", exc)

    # 2️⃣  Validate and decode the JWT
    try:
        claims = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=BRIDGE_ISS,        # same constant you used when issuing
            options={
                "verify_aud": False
            },
        )
        if DEBUG:
            log.debug("Verified claims: %s", claims)

    except jwt.ExpiredSignatureError as exc:
        if DEBUG:
            log.debug("Token expired: %s", exc)
        raise HTTPException(status_code=401, detail="token expired") from exc

    except jwt.InvalidAudienceError as exc:
        if DEBUG:
            log.debug("Audience check failed: %s", exc)
        raise HTTPException(status_code=401, detail="invalid audience") from exc

    except Exception as exc:  # noqa: BLE001
        # All other validation errors (signature, issuer, etc.)
        if DEBUG:
            log.exception("Token validation failed")
        raise HTTPException(status_code=401, detail=f"invalid token ({exc})") from exc

    # 3️⃣  Build the response with the standard OIDC claims you want to expose
    userinfo_payload = {
        "sub": claims["sub"],
        "name": claims.get("name"),
        "email": claims.get("sub"),
        "preferred_username": claims.get("preferred_username"),
        # Custom claim (MinIO/STS policy) if present
        "policy": claims.get("policy"),
    }
    # Remove keys whose value is None
    userinfo_payload = {k: v for k, v in userinfo_payload.items() if v is not None}

    if DEBUG:
        log.debug("UserInfo response: %s", userinfo_payload)

    return JSONResponse(userinfo_payload)

