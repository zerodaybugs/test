#!/usr/bin/env python3
"""Passive Dynamic environment/origin/OAuth boundary collection for Synthetix.

Safety:
- public Dynamic SDK settings GETs only;
- CORS GET/OPTIONS requests only;
- no OTP, login, user creation, wallet creation, signature, transaction, or mutation;
- output retains only selected configuration fields, response hashes, and CORS metadata.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

OUT = pathlib.Path("dynamic_origin_oauth")
OUT.mkdir(parents=True, exist_ok=True)

CURRENT_ENV = "d5f379e2-ec2d-4e7c-b541-8117684d3e98"
REDIRECT_ENV = "dca95954-81d8-4ef8-b20f-b1c3b6781cb6"
BASE = "https://app.dynamicauth.com/api/v0"
UA = "Mozilla/5.0 (compatible; authorized-passive-security-review/1.0)"
MAX_BODY = 3 * 1024 * 1024
ENV_RE = re.compile(r"/sdk/([0-9a-f-]{36})/", re.I)


def sha256(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def request(
    url: str,
    *,
    method: str = "GET",
    origin: str | None = None,
    preflight_method: str | None = None,
) -> dict[str, Any]:
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if origin is not None:
        headers["Origin"] = origin
    if preflight_method:
        headers["Access-Control-Request-Method"] = preflight_method
        headers["Access-Control-Request-Headers"] = "content-type"
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            body = response.read(MAX_BODY + 1)
            status = response.status
            final_url = response.url
            response_headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        status = exc.code
        final_url = exc.url
        response_headers = dict(exc.headers.items()) if exc.headers else {}
    if len(body) > MAX_BODY:
        raise RuntimeError("response too large")
    return {
        "status": status,
        "finalUrl": final_url,
        "bodyBytes": len(body),
        "bodySha256": sha256(body),
        "contentType": response_headers.get("Content-Type"),
        "accessControlAllowOrigin": response_headers.get("Access-Control-Allow-Origin"),
        "accessControlAllowCredentials": response_headers.get("Access-Control-Allow-Credentials"),
        "accessControlAllowMethods": response_headers.get("Access-Control-Allow-Methods"),
        "accessControlAllowHeaders": response_headers.get("Access-Control-Allow-Headers"),
        "vary": response_headers.get("Vary"),
        "setCookiePresent": any(key.lower() == "set-cookie" for key in response_headers),
        "body": body,
    }


def env_from_url(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = ENV_RE.search(value)
    return match.group(1).lower() if match else None


def host_from_url(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return urllib.parse.urlparse(value).hostname


def selected_settings(env_id: str) -> dict[str, Any]:
    url = f"{BASE}/sdk/{env_id}/settings"
    item = request(url)
    body = item.pop("body")
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    providers: list[dict[str, Any]] = []
    if isinstance(parsed, dict):
        for provider in parsed.get("providers", []) or []:
            if not isinstance(provider, dict):
                continue
            providers.append(
                {
                    "provider": provider.get("provider"),
                    "createNewAccounts": provider.get("createNewAccounts"),
                    "authorizationEnvironmentId": env_from_url(provider.get("authorizationUrl")),
                    "redirectEnvironmentId": env_from_url(provider.get("redirectUrl")),
                    "authorizationHost": host_from_url(provider.get("authorizationUrl")),
                    "redirectHost": host_from_url(provider.get("redirectUrl")),
                }
            )
        sdk = parsed.get("sdk") if isinstance(parsed.get("sdk"), dict) else {}
        embedded = sdk.get("embeddedWallets") if isinstance(sdk.get("embeddedWallets"), dict) else {}
        security = parsed.get("security") if isinstance(parsed.get("security"), dict) else {}
        mfa = security.get("mfa") if isinstance(security.get("mfa"), dict) else {}
        item["selected"] = {
            "environmentName": parsed.get("environmentName"),
            "environmentLocked": security.get("environmentLocked"),
            "authStorage": ((security.get("auth") or {}).get("storage") if isinstance(security.get("auth"), dict) else None),
            "mfaEnabled": mfa.get("enabled"),
            "mfaRequired": mfa.get("required"),
            "automaticEmbeddedWalletCreation": sdk.get("automaticEmbeddedWalletCreation"),
            "embeddedWalletAutomaticCreation": embedded.get("automaticEmbeddedWalletCreation"),
            "embeddedWalletVersion": embedded.get("defaultWalletVersion"),
            "emailRecoveryEnabled": embedded.get("emailRecoveryEnabled"),
            "promptForKeyExport": embedded.get("promptForKeyExport"),
            "exportDisabled": ((sdk.get("waas") or {}).get("exportDisabled") if isinstance(sdk.get("waas"), dict) else None),
            "providers": providers,
        }
    else:
        item["selected"] = None
    return item


def cors_matrix(env_id: str) -> list[dict[str, Any]]:
    origins = [
        "https://exchange.synthetix.io",
        "https://attacker.invalid",
        "null",
    ]
    endpoints = [
        ("settings", f"{BASE}/sdk/{env_id}/settings", "GET"),
        ("email_verification_create", f"{BASE}/sdk/{env_id}/emailVerifications/create", "POST"),
        ("verify", f"{BASE}/sdk/{env_id}/verify", "POST"),
        ("embedded_wallets", f"{BASE}/sdk/{env_id}/users/embeddedWallets", "POST"),
        ("passkeys_signin", f"{BASE}/sdk/{env_id}/users/passkeys/signin", "POST"),
    ]
    results: list[dict[str, Any]] = []
    for origin in origins:
        for name, url, intended_method in endpoints:
            if intended_method == "GET":
                item = request(url, origin=origin)
                item.pop("body")
                item.update({"origin": origin, "endpoint": name, "method": "GET"})
            else:
                item = request(
                    url,
                    method="OPTIONS",
                    origin=origin,
                    preflight_method=intended_method,
                )
                item.pop("body")
                item.update({"origin": origin, "endpoint": name, "method": "OPTIONS", "intendedMethod": intended_method})
            results.append(item)
    return results


def main() -> None:
    current = selected_settings(CURRENT_ENV)
    redirect = selected_settings(REDIRECT_ENV)
    current_selected = current.get("selected") or {}
    provider_mismatches = []
    for provider in current_selected.get("providers", []) or []:
        auth_env = provider.get("authorizationEnvironmentId")
        redirect_env = provider.get("redirectEnvironmentId")
        if auth_env and redirect_env and auth_env != redirect_env:
            provider_mismatches.append(provider)

    output = {
        "safety": "Public settings GET and CORS GET/OPTIONS only; no authentication or mutation.",
        "currentEnvironmentId": CURRENT_ENV,
        "redirectEnvironmentId": REDIRECT_ENV,
        "current": current,
        "redirectTarget": redirect,
        "providerEnvironmentMismatchCount": len(provider_mismatches),
        "providerEnvironmentMismatches": provider_mismatches,
        "cors": {
            CURRENT_ENV: cors_matrix(CURRENT_ENV),
            REDIRECT_ENV: cors_matrix(REDIRECT_ENV),
        },
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "currentEnvironmentName": (current.get("selected") or {}).get("environmentName"),
                "redirectEnvironmentName": (redirect.get("selected") or {}).get("environmentName"),
                "providerEnvironmentMismatchCount": len(provider_mismatches),
                "currentEnvironmentLocked": (current.get("selected") or {}).get("environmentLocked"),
                "redirectEnvironmentLocked": (redirect.get("selected") or {}).get("environmentLocked"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
