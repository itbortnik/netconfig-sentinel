"""SDK call-shape tests with a fake client, not live formal verification."""

from typing import Any

import pytest
from app.verification.batfish_worker import evaluate_session


class Frame:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    def __len__(self) -> int:
        return len(self.rows)

    def to_dict(self, *, orient: str) -> list[dict[str, Any]]:
        assert orient == "records"
        return self.rows


class Question:
    def __init__(self, session: "Session", name: str, parameters: dict[str, Any]) -> None:
        self.session, self.name, self.parameters = session, name, parameters

    def answer(self, **kwargs: Any) -> "Question":
        self.session.calls.append((self.name, self.parameters, kwargs))
        return self

    def frame(self) -> Frame:
        if self.session.mode == "error":
            raise RuntimeError("private-secret")
        if self.name == "fileParseStatus":
            return Frame(
                [
                    {
                        "File_Name": "configs/device.cfg",
                        "Nodes": ["edge"],
                        "Status": "FAILED" if self.session.mode == "parse_failed" else "PASSED",
                    }
                ]
            )
        if self.name in {"initIssues", "parseWarning"}:
            return Frame([{}] if self.session.mode == self.name else [])
        if self.name == "reachability":
            return Frame([] if self.session.mode == "empty" else [{}])
        return Frame([{}] if self.session.mode == "changed" else [])


class Session:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.q = self
        self.calls: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        self.deleted: list[str] = []
        self.uploads: list[str] = []

    def __getattr__(self, name: str) -> Any:
        return lambda **parameters: Question(self, name, parameters)

    def list_networks(self) -> list[str]:
        return ["sentinel-test"] if self.mode == "collision" else []

    def set_network(self, name: str) -> None:
        assert name == "sentinel-test"

    def get_component_versions(self) -> dict[str, str]:
        return {"Batfish": "test-double"}

    def init_snapshot(self, path: str, **kwargs: Any) -> None:
        assert kwargs["overwrite"] is False
        assert kwargs["extra_args"] == {"ignoremanagementinterfaces": False}
        self.uploads.append(path)

    def delete_network(self, name: str) -> None:
        self.deleted.append(name)
        if self.mode == "cleanup_failed":
            raise RuntimeError("private-secret")


@pytest.mark.parametrize(
    "mode,status",
    [
        ("unchanged", "no_differences_in_scope"),
        ("changed", "differences_found"),
        ("empty", "inconclusive"),
        ("parse_failed", "incomplete"),
        ("initIssues", "incomplete"),
        ("parseWarning", "incomplete"),
        ("error", "error"),
        ("collision", "error"),
        ("cleanup_failed", "no_differences_in_scope"),
    ],
)
def test_sdk_contract(mode: str, status: str) -> None:
    session = Session(mode)
    request = {
        "network_name": "sentinel-test",
        "before": "private-before",
        "after": "private-after",
        "nodes": {"configs/device.cfg": "edge"},
        "scope": {"start_node": "edge", "destination": "192.0.2.0/24"},
    }
    result = evaluate_session(session, request, dict, dict)
    assert result["status"] == status
    assert "private-secret" not in str(result)
    if mode == "collision":
        assert not session.deleted and not session.uploads
    else:
        assert session.deleted == ["sentinel-test"]
        assert result["cleanup_complete"] == (mode != "cleanup_failed")
    differentials = [call for call in session.calls if call[0] == "differentialReachability"]
    if status in {"incomplete", "error"}:
        assert not differentials
    else:
        assert differentials[0][2] == {"snapshot": "after", "reference_snapshot": "before"}
        assert differentials[0][1]["headers"] == {"dstIps": "192.0.2.0/24"}
        assert differentials[0][1]["pathConstraints"] == {"startLocation": "edge"}
