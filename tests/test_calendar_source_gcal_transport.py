"""
test_calendar_source_gcal_transport.py — tests for GCalSyncSource._build_transport (W-19).

Verifies the Google Calendar API v3 transport wiring: credential loading (service account
and OAuth user), API call parameters, and the constructor's transport-selection logic.
All Google API deps are mocked — no network, no credentials file.

The EXISTING test_calendar_source_gcal.py covers _map/_parse_dt and the injected-transport
path; this file covers only the default-transport wiring that W-19 adds.

Run: pytest tests/test_calendar_source_gcal_transport.py -v
"""
from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, mock_open, patch

from willow_mcp.commitments.calendar_source import GCalSyncSource


def _mock_google_modules(*, mock_service, mock_cred_module, cred_attr_name):
    """Build a sys.modules dict that makes the lazy google imports resolve."""
    mock_discovery = MagicMock()
    mock_discovery.build.return_value = mock_service

    mock_google_oauth2 = MagicMock(**{cred_attr_name: mock_cred_module})

    return {
        "googleapiclient": MagicMock(),
        "googleapiclient.discovery": mock_discovery,
        "google": MagicMock(),
        "google.oauth2": mock_google_oauth2,
        f"google.oauth2.{cred_attr_name}": mock_cred_module,
    }


def _mock_calendar_service(items=None):
    mock_list = MagicMock()
    mock_list.execute.return_value = {"items": items or []}
    mock_events = MagicMock()
    mock_events.list.return_value = mock_list
    mock_service = MagicMock()
    mock_service.events.return_value = mock_events
    return mock_service, mock_events


class TestBuildTransportServiceAccount(unittest.TestCase):
    def test_service_account_credentials_used(self):
        mock_service, _ = _mock_calendar_service()
        mock_sa = MagicMock()
        mods = _mock_google_modules(
            mock_service=mock_service,
            mock_cred_module=mock_sa,
            cred_attr_name="service_account",
        )
        cred_json = json.dumps({"type": "service_account"})
        with patch("builtins.open", mock_open(read_data=cred_json)), patch.dict(sys.modules, mods):
                GCalSyncSource._build_transport("/fake/creds.json", "primary")
                mock_sa.Credentials.from_service_account_file.assert_called_once_with(
                    "/fake/creds.json",
                    scopes=["https://www.googleapis.com/auth/calendar.readonly"],
                )

    def test_transport_returns_items(self):
        items = [{"id": "e1", "summary": "Test", "status": "confirmed",
                  "start": {"dateTime": "2026-08-01T10:00:00Z"}}]
        mock_service, _ = _mock_calendar_service(items)
        mock_sa = MagicMock()
        mods = _mock_google_modules(
            mock_service=mock_service,
            mock_cred_module=mock_sa,
            cred_attr_name="service_account",
        )
        cred_json = json.dumps({"type": "service_account"})
        with patch("builtins.open", mock_open(read_data=cred_json)), patch.dict(sys.modules, mods):
                transport = GCalSyncSource._build_transport("/fake/creds.json", "primary")
                start = datetime(2026, 8, 1, tzinfo=timezone.utc)
                end = datetime(2026, 8, 15, tzinfo=timezone.utc)
                result = transport(start, end)
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["id"], "e1")


class TestBuildTransportOAuthUser(unittest.TestCase):
    def test_oauth_user_credentials_used(self):
        mock_service, _ = _mock_calendar_service()
        mock_creds_mod = MagicMock()
        mods = _mock_google_modules(
            mock_service=mock_service,
            mock_cred_module=mock_creds_mod,
            cred_attr_name="credentials",
        )
        cred_json = json.dumps({
            "token": "ya29.xxx", "refresh_token": "1//xxx",
            "client_id": "id", "client_secret": "secret",
        })
        with patch("builtins.open", mock_open(read_data=cred_json)), patch.dict(sys.modules, mods):
                GCalSyncSource._build_transport("/fake/token.json", "primary")
                mock_creds_mod.Credentials.from_authorized_user_file.assert_called_once_with(
                    "/fake/token.json",
                    scopes=["https://www.googleapis.com/auth/calendar.readonly"],
                )


class TestTransportApiCall(unittest.TestCase):
    def test_api_call_parameters(self):
        mock_service, mock_events = _mock_calendar_service()
        mock_sa = MagicMock()
        mods = _mock_google_modules(
            mock_service=mock_service,
            mock_cred_module=mock_sa,
            cred_attr_name="service_account",
        )
        cred_json = json.dumps({"type": "service_account"})
        with patch("builtins.open", mock_open(read_data=cred_json)), patch.dict(sys.modules, mods):
                transport = GCalSyncSource._build_transport("/fake/creds.json", "work")
                start = datetime(2026, 8, 1, tzinfo=timezone.utc)
                end = datetime(2026, 8, 15, tzinfo=timezone.utc)
                transport(start, end)
                mock_events.list.assert_called_once_with(
                    calendarId="work",
                    timeMin=start.isoformat(),
                    timeMax=end.isoformat(),
                    singleEvents=True,
                    orderBy="startTime",
                )


class TestConstructorTransportSelection(unittest.TestCase):
    def test_default_no_args_still_raises(self):
        with self.assertRaises(NotImplementedError):
            GCalSyncSource().fetch()

    def test_injected_list_events_takes_precedence(self):
        called = []
        src = GCalSyncSource(
            list_events=lambda s, e: (called.append(1), [])[1],
            credentials_path="/fake/creds.json",
        )
        src.fetch()
        self.assertEqual(len(called), 1)

    def test_credentials_path_builds_transport(self):
        mock_service, _ = _mock_calendar_service()
        mock_sa = MagicMock()
        mods = _mock_google_modules(
            mock_service=mock_service,
            mock_cred_module=mock_sa,
            cred_attr_name="service_account",
        )
        cred_json = json.dumps({"type": "service_account"})
        with patch("builtins.open", mock_open(read_data=cred_json)), patch.dict(sys.modules, mods):
                src = GCalSyncSource(credentials_path="/fake/creds.json")
                events = src.fetch()
                self.assertEqual(events, [])

    def test_import_error_mentions_gcal_extra(self):
        with self.assertRaises(ImportError) as ctx:
            GCalSyncSource._build_transport("/fake/creds.json", "primary")
        self.assertIn("gcal", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
