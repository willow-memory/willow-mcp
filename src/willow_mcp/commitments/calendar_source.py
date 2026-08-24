"""
calendar_source.py — real CalendarSource adapters for the Commitment Membrane (drop-in).

The pure-script core (commitment_ledger.py) owns the read-only CalendarSource contract and a
synthetic StubCalendarSource. This module holds the REAL adapters. Their dependency (`caldav`)
is imported lazily inside the constructor, so importing this module stays dependency-free —
only *constructing* an adapter pulls the dep in.

Wiring, once you pick a provider:

    from willow_mcp.commitments.commitment_ledger import CommitmentLedger, DewConfig
    from willow_mcp.commitments.calendar_source import CalDavSource
    src = CalDavSource(url="https://caldav.fastmail.com/…", username=…, password=…)
    ledger = CommitmentLedger(source=src, gate_fn=safe_gate)
    ledger.ingest()
    for s in ledger.dew_surface(now):
        ...

The contract is READ-ONLY by design (fetch only). A cancel/reschedule is a proposal routed
through CommitmentLedger.propose_action → the SAFE gate, never a direct write from here.
Google-calendar users: swap CalDavSource for a gcal-sync-backed adapter against the same
`fetch() -> list[CalendarEvent]` contract; the ledger does not change.

Design: willow/design/willow-commitment-membrane.md · mirror of wake_gate.py · ΔΣ=42
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from willow_mcp.commitments.commitment_ledger import CalendarEvent


class CalDavSource:
    """Read-only CalendarSource over any RFC-4791 server (iCloud / Nextcloud / Fastmail).

    fetch() pulls events in a window and maps each to a CalendarEvent. The event body/notes
    ARE read here (a real server returns them), but the ledger drops them at ingest — the
    membrane's receipt-not-recording rule does not depend on the adapter withholding them.
    """

    def __init__(
        self,
        url: str,
        *,
        username: str,
        password: str,
        calendar_name: Optional[str] = None,
        window_days: int = 14,
    ):
        import caldav  # lazy: only needed when actually constructed

        self._client = caldav.DAVClient(url=url, username=username, password=password)
        self._calendar_name = calendar_name
        self._window_days = window_days

    def fetch(self) -> list[CalendarEvent]:
        from datetime import timedelta

        principal = self._client.principal()
        calendars = principal.calendars()
        if self._calendar_name:
            calendars = [c for c in calendars if c.name == self._calendar_name]
        start = datetime.now(timezone.utc)
        end = start + timedelta(days=self._window_days)
        out: list[CalendarEvent] = []
        for cal in calendars:
            for ev in cal.search(start=start, end=end, event=True, expand=True):
                vobj = ev.vobject_instance.vevent
                uid = str(getattr(vobj, "uid", ev.url).value)
                title = str(getattr(vobj, "summary", "").value) if hasattr(vobj, "summary") else ""
                dtstart = vobj.dtstart.value
                dtend = vobj.dtend.value if hasattr(vobj, "dtend") else None
                status = str(getattr(vobj, "status", "").value).upper() if hasattr(vobj, "status") else ""
                attendees = tuple(
                    str(a.value) for a in getattr(vobj, "attendee_list", [])
                )
                body = str(getattr(vobj, "description", "").value) if hasattr(vobj, "description") else ""
                out.append(CalendarEvent(
                    uid=uid, title=title, start=dtstart, end=dtend,
                    attendees=attendees, body=body, cancelled=(status == "CANCELLED"),
                ))
        return out


class GCalSyncSource:
    """Read-only CalendarSource over Google Calendar (Jarvis layer 2, Step 2).

    Maps Google Calendar API v3 `events` resources -> CalendarEvent against the SAME
    read-only fetch() contract as CalDavSource; the ledger does not change. The transport
    (the call returning v3 event dicts for a window) is an injected seam: pass `list_events`
    for tests / a custom client. The default transport is deliberately UNWIRED here — it
    raises, because the real gcal-sync path needs OAuth creds + an envelope and is stood up
    at product-repo integration (Step 3), not in this skeleton.

    Read-only by contract. A cancel/reschedule is a proposal routed through
    CommitmentLedger.propose_action -> the SAFE gate, never a write from here. There is
    deliberately no create/update/delete method to call.
    """

    def __init__(
        self,
        *,
        calendar_id: str = "primary",
        window_days: int = 14,
        list_events: Optional[Callable[[datetime, datetime], list]] = None,
        credentials_path: Optional[str] = None,
    ):
        self._calendar_id = calendar_id
        self._window_days = window_days
        self._credentials_path = credentials_path
        if list_events is not None:
            self._list_events = list_events
        elif credentials_path is not None:
            self._list_events = self._build_transport(credentials_path, calendar_id)
        else:
            self._list_events = self._unwired_transport

    @staticmethod
    def _build_transport(
        credentials_path: str, calendar_id: str,
    ) -> Callable[[datetime, datetime], list]:
        import json

        try:
            from googleapiclient.discovery import build as build_service
        except ImportError:
            raise ImportError(
                "GCalSyncSource transport needs google-api-python-client and google-auth. "
                "Install: pip install 'willow-mcp[gcal]'"
            ) from None

        with open(credentials_path) as f:
            cred_data = json.load(f)

        _SCOPES = ["https://www.googleapis.com/auth/calendar.readonly"]

        if cred_data.get("type") == "service_account":
            from google.oauth2 import service_account

            credentials = service_account.Credentials.from_service_account_file(
                credentials_path, scopes=_SCOPES,
            )
        else:
            from google.oauth2.credentials import Credentials

            credentials = Credentials.from_authorized_user_file(
                credentials_path, scopes=_SCOPES,
            )

        service = build_service("calendar", "v3", credentials=credentials)

        def _transport(start: datetime, end: datetime) -> list:
            result = (
                service.events()
                .list(
                    calendarId=calendar_id,
                    timeMin=start.isoformat(),
                    timeMax=end.isoformat(),
                    singleEvents=True,
                    orderBy="startTime",
                )
                .execute()
            )
            return result.get("items", [])

        return _transport

    @staticmethod
    def _unwired_transport(start: datetime, end: datetime) -> list:
        raise NotImplementedError(
            "gcal-sync transport is wired at product-repo integration (OAuth creds + "
            "envelope). Inject list_events=<callable(start,end)->list[dict]> for the "
            "skeleton and its tests."
        )

    @staticmethod
    def _parse_dt(node: Optional[dict]) -> Optional[datetime]:
        # v3 start/end is {"dateTime": rfc3339} (timed) or {"date": "YYYY-MM-DD"} (all-day).
        if not node:
            return None
        raw = node.get("dateTime")
        if raw:
            if raw.endswith("Z"):
                raw = raw[:-1] + "+00:00"  # fromisoformat < py3.11 rejects a bare Z
            return datetime.fromisoformat(raw)
        raw = node.get("date")
        if raw:
            return datetime.fromisoformat(raw)  # naive midnight for all-day
        return None

    @classmethod
    def _map(cls, ev: dict) -> CalendarEvent:
        return CalendarEvent(
            uid=str(ev.get("id", "")),
            title=ev.get("summary", ""),
            start=cls._parse_dt(ev.get("start")),
            end=cls._parse_dt(ev.get("end")),
            attendees=tuple(a.get("email", "") for a in ev.get("attendees", []) if a.get("email")),
            body=ev.get("description", ""),
            cancelled=(str(ev.get("status", "")).lower() == "cancelled"),
        )

    def fetch(self) -> list[CalendarEvent]:
        start = datetime.now(timezone.utc)
        end = start + timedelta(days=self._window_days)
        return [self._map(ev) for ev in self._list_events(start, end)]
