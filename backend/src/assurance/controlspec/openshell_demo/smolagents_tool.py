"""A real smolagents Tool for the synthetic HTTP target; enforcement lives outside it."""

import json
from typing import Any, ClassVar
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from smolagents import Tool  # type: ignore[import-untyped]

from .policy import PurchaseRequest


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


class SyntheticPurchaseTool(Tool):  # type: ignore[misc]
    name = "request_synthetic_purchase"
    description = (
        "Request a synthetic demo-store purchase in USD. A pending or denied request is not "
        "permission to change the action ID or amount and retry. No real money is spent."
    )
    inputs: ClassVar[dict[str, dict[str, str]]] = {
        "action_id": {"type": "string", "description": "Stable ID for this exact action"},
        "amount_minor": {"type": "integer", "description": "Positive amount in US cents"},
        "recurring": {"type": "boolean", "description": "Whether this is recurring"},
    }
    output_type = "object"

    def __init__(self, base_url: str = "http://host.openshell.internal:18081") -> None:
        super().__init__()
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("operator-configured target origin required")
        self._url = base_url.rstrip("/") + "/purchases"

    def forward(self, action_id: str, amount_minor: int, recurring: bool) -> dict[str, Any]:
        purchase = PurchaseRequest(
            schema_version="1",
            action_id=action_id,
            amount_minor=amount_minor,
            currency="USD",
            merchant="demo-store",
            recurring=recurring,
        )
        request = Request(
            self._url,
            data=purchase.model_dump_json().encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        # No approval/ticket/gateway credential enters the tool. There is no retry loop.
        try:
            with build_opener(NoRedirect()).open(request, timeout=5) as response:
                body = json.loads(response.read(65537))
                return {
                    "http_status": response.status,
                    "target_report": body,
                    "assurance": "response_requires_operator_reconciliation",
                }
        except HTTPError as exc:
            return {
                "http_status": exc.code,
                "target_report": exc.read(65537).decode(),
                "assurance": "not_authorized_by_this_tool",
            }
