"""Standalone bounded wire adapter; parent enforces a hard wall-clock deadline."""

import http.client
import json
import sys
from typing import Any
from urllib.parse import urlsplit

MAX_INPUT = 128 * 1024
MAX_RESPONSE = 64 * 1024
MAX_CONTENT = 32 * 1024


def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def main() -> int:
    connection = None
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError("oversized request")
        options = json.loads(raw, object_pairs_hook=unique_keys)
        url = urlsplit(options["endpoint"])
        if (
            url.scheme != "http"
            or url.hostname != "127.0.0.1"
            or url.port is None
            or not 1024 <= url.port <= 65535
            or url.netloc != f"127.0.0.1:{url.port}"
            or url.path != "/v1/chat/completions"
            or url.query
            or url.fragment
        ):
            raise ValueError("unsupported target")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if options["api_key"]:
            headers["Authorization"] = "Bearer " + options["api_key"]
        body = json.dumps(
            {
                "model": options["model"],
                "stream": False,
                "temperature": 0,
                "max_tokens": 4096,
                "messages": [
                    {
                        "role": "system",
                        "content": options["instructions"]
                        + "\nAnswer JSON Schema:\n"
                        + options["answer_schema_json"],
                    },
                    {"role": "user", "content": options["context_json"]},
                ],
                "response_format": {"type": "json_object"},
            },
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
        if len(body) > MAX_INPUT:
            raise ValueError("oversized wire request")
        connection = http.client.HTTPConnection("127.0.0.1", url.port, timeout=options["timeout"])
        connection.request("POST", "/v1/chat/completions", body=body, headers=headers)
        response = connection.getresponse()
        if (
            response.status != 200
            or response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            != "application/json"
            or response.getheader("Content-Encoding") is not None
        ):
            raise ValueError("unsupported response")
        length = response.getheader("Content-Length")
        if length is not None and (not length.isdecimal() or int(length) > MAX_RESPONSE):
            raise ValueError("oversized response")
        payload = response.read(MAX_RESPONSE + 1)
        if len(payload) > MAX_RESPONSE:
            raise ValueError("oversized response")
        envelope = json.loads(payload, object_pairs_hook=unique_keys)
        choices = envelope["choices"]
        if not isinstance(choices, list) or len(choices) != 1:
            raise ValueError("ambiguous response")
        choice = choices[0]
        message = choice["message"]
        if (
            choice.get("finish_reason") != "stop"
            or message.get("role") != "assistant"
            or set(message) - {"role", "content", "refusal"}
            or message.get("refusal") not in {None, ""}
            or not isinstance(message.get("content"), str)
        ):
            raise ValueError("incomplete response or tool request")
        result = message["content"].encode("utf-8")
        if len(result) > MAX_CONTENT:
            raise ValueError("oversized answer")
        sys.stdout.buffer.write(result)
        return 0
    except Exception:
        # No provider body, headers, prompt, URL or exception is reflected.
        return 2
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
