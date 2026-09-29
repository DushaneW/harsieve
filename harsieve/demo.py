"""Synthetic fixture only. Contains conspicuous, fake canaries for tests."""

from datetime import datetime, timedelta, timezone


def capture() -> dict:
    entries = []
    for index, (path, duration, status, size) in enumerate(
        [
            ("/dashboard", 85, 200, 18432),
            ("/assets/app.css", 34, 200, 12288),
            ("/assets/app.js", 145, 200, 182400),
            ("/api/account/private-user", 760, 200, 3200),
            ("/api/activity", 1250, 503, 320),
            ("/api/activity", 940, 200, 24160),
            ("/fonts/main.woff2", 110, 200, 32768),
            ("/api/notifications", 430, 200, 850),
            ("/api/export", 1680, 504, 128),
            ("/api/session", 62, 204, 0),
            ("/telemetry", 240, 0, -1),
            ("/api/health", 28, 200, 64),
        ]
    ):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=index * 115)
        entries.append(
            {
                "startedDateTime": start.isoformat(),
                "time": duration,
                "request": {
                    "method": "POST" if index in {8, 10} else "GET",
                    "url": f"https://{'metrics' if index == 10 else 'private'}.example{path}?token=DEMO_SECRET_QUERY",
                    "httpVersion": "HTTP/2",
                    "headers": [{"name": "Authorization", "value": "Bearer DEMO_SECRET_HEADER"}],
                    "cookies": [{"name": "session", "value": "DEMO_SECRET_COOKIE"}],
                    "queryString": [{"name": "token", "value": "DEMO_SECRET_QUERY"}],
                    "postData": {
                        "mimeType": "application/json",
                        "text": '{"password":"DEMO_SECRET_BODY"}',
                    },
                    "headersSize": 320,
                    "bodySize": 64,
                },
                "response": {
                    "status": status,
                    "statusText": "",
                    "httpVersion": "HTTP/2",
                    "headers": [],
                    "cookies": [],
                    "redirectURL": "",
                    "headersSize": 210,
                    "bodySize": size,
                    "content": {
                        "size": max(0, size),
                        "mimeType": "application/json",
                        "text": "DEMO_SECRET_RESPONSE",
                    },
                },
                "cache": {},
                "timings": {"send": 1, "wait": max(0, duration - 11), "receive": 10},
                "serverIPAddress": "192.0.2.42",
                "_webSocketMessages": [{"data": "DEMO_SECRET_EXTENSION"}],
            }
        )
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "Synthetic fixture", "version": "1"},
            "entries": entries,
        }
    }
