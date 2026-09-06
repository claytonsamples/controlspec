"""Standalone, stateless FastAPI surface for the ControlSpec reference plane."""

from __future__ import annotations

import json
from typing import Any, cast

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import Response
from pydantic import BaseModel, ValidationError
from starlette.exceptions import HTTPException as StarletteHttpException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from assurance.contracts.canonical import canonical_json
from assurance.controlspec.api_models import (
    CatalogId,
    ControlDetailResponse,
    ControlListResponse,
    ControlSpecApiErrorBody,
    ControlSpecApiErrorCode,
    ControlSpecApiErrorResponse,
    ControlSpecValidationIssue,
    DecideRequest,
    DecideResponse,
    PackDetailResponse,
    PackListResponse,
    ReceiptAssessmentRequest,
    ReceiptAssessmentResponse,
    RecheckRequest,
    RecheckResponse,
)
from assurance.controlspec.evaluator import EvaluationInputError
from assurance.controlspec.reference_catalog import (
    CatalogBindingMismatchError,
    CatalogItemNotFoundError,
    ReferenceCatalogError,
    ReferenceScenarioFixture,
    load_default_reference_catalog,
)
from assurance.controlspec.reference_service import (
    ImmutableScenarioFactProvider,
    PriorBindingError,
    ReferenceControlPlaneService,
    ReferenceFactProvider,
    ReferenceServiceError,
)

_MAX_BODY_BYTES = 1_048_576
_POST_PATHS = frozenset(
    {
        "/controlspec/v0/decide",
        "/controlspec/v0/recheck",
        "/controlspec/v0/receipts",
    }
)


class CanonicalJSONResponse(Response):
    media_type = "application/json"

    def render(self, content: Any) -> bytes:
        if isinstance(content, BaseModel):
            content = content.model_dump(mode="json", by_alias=True, exclude_none=False)
        else:
            content = jsonable_encoder(content)
        return canonical_json(content)


def _error(
    *,
    status_code: int,
    code: ControlSpecApiErrorCode,
    detail_code: str,
    message: str,
    issues: tuple[ControlSpecValidationIssue, ...] = (),
) -> CanonicalJSONResponse:
    value = ControlSpecApiErrorResponse(
        error=ControlSpecApiErrorBody(
            code=code,
            detail_code=detail_code,
            message=message,
            issues=issues,
        )
    )
    return CanonicalJSONResponse(value, status_code=status_code)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_float(_: str) -> None:
    raise ValueError("floating-point JSON values are forbidden")


def _strict_json(data: bytes) -> Any:
    text = data.decode("utf-8", errors="strict")
    return json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_float=_reject_float,
        parse_constant=_reject_float,
    )


class StrictControlSpecJsonMiddleware:
    """Reject ambiguous POST bodies before FastAPI/Pydantic parsing."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or scope.get("path") not in _POST_PATHS
        ):
            await self._app(scope, receive, send)
            return

        headers = cast(list[tuple[bytes, bytes]], scope.get("headers", []))
        content_types = [
            value.strip().lower()
            for name, value in headers
            if name.lower() == b"content-type"
        ]
        if content_types != [b"application/json"]:
            await _error(
                status_code=400,
                code=ControlSpecApiErrorCode.INVALID_JSON,
                detail_code="controlspec.api.invalid_media_type",
                message="The request must contain one strict JSON document.",
            )(scope, receive, send)
            return

        body = bytearray()
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                await _error(
                    status_code=400,
                    code=ControlSpecApiErrorCode.INVALID_JSON,
                    detail_code="controlspec.api.invalid_body_stream",
                    message="The request must contain one strict JSON document.",
                )(scope, receive, send)
                return
            body.extend(message.get("body", b""))
            if len(body) > _MAX_BODY_BYTES:
                await _error(
                    status_code=400,
                    code=ControlSpecApiErrorCode.INVALID_JSON,
                    detail_code="controlspec.api.body_too_large",
                    message="The request exceeds the reference API body limit.",
                )(scope, receive, send)
                return
            more = bool(message.get("more_body", False))
        try:
            _strict_json(bytes(body))
        except (UnicodeDecodeError, ValueError):
            await _error(
                status_code=400,
                code=ControlSpecApiErrorCode.INVALID_JSON,
                detail_code="controlspec.api.invalid_json",
                message="The request must contain one strict JSON document.",
            )(scope, receive, send)
            return

        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if delivered:
                return {"type": "http.request", "body": b"", "more_body": False}
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self._app(scope, replay, send)


def _validation_issues(exc: RequestValidationError) -> tuple[ControlSpecValidationIssue, ...]:
    return tuple(
        ControlSpecValidationIssue(
            loc=tuple(cast(str | int, item) for item in error.get("loc", ())),
            type=str(error.get("type", "value_error")),
        )
        for error in exc.errors()
    )


def _is_selection_validation(exc: RequestValidationError) -> bool:
    for error in exc.errors():
        location = tuple(error.get("loc", ()))
        if location[:1] == ("body",):
            location = location[1:]
        if location[:1] == ("selection",):
            return True
        if location[:2] == ("path", "catalog_id"):
            return True
    return False


async def _validated_body[ModelT: BaseModel](
    request: Request,
    model: type[ModelT],
) -> ModelT:
    try:
        return model.model_validate_json(await request.body(), strict=True)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


def _request_body(model: type[BaseModel]) -> dict[str, Any]:
    return {
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": model.model_json_schema(
                        mode="validation",
                        by_alias=True,
                    )
                }
            },
        }
    }


def create_controlspec_reference_app(
    *,
    service: ReferenceControlPlaneService,
) -> FastAPI:
    """Create the exact seven-route local reference app."""

    app = FastAPI(
        title="ControlSpec Reference Control Plane",
        version="0.1.0",
        description=(
            "Stateless, non-authoritative reference API for deterministic "
            "ControlSpec evaluation."
        ),
        default_response_class=CanonicalJSONResponse,
    )
    app.router.redirect_slashes = False
    app.state.controlspec_service = service
    app.add_middleware(StrictControlSpecJsonMiddleware)

    @app.exception_handler(RequestValidationError)
    async def validation_error(
        _request: Any,
        exc: RequestValidationError,
    ) -> CanonicalJSONResponse:
        if _is_selection_validation(exc):
            return _error(
                status_code=400,
                code=ControlSpecApiErrorCode.SELECTION_INVALID,
                detail_code="controlspec.api.selection_invalid",
                message="The exact reference catalog selection is invalid.",
                issues=_validation_issues(exc),
            )
        return _error(
            status_code=422,
            code=ControlSpecApiErrorCode.INPUT_INVALID,
            detail_code="controlspec.api.contract_invalid",
            message="The request is not a valid ControlSpec reference operation.",
            issues=_validation_issues(exc),
        )

    @app.exception_handler(CatalogItemNotFoundError)
    async def catalog_not_found(
        _request: Any,
        _exc: CatalogItemNotFoundError,
    ) -> CanonicalJSONResponse:
        return _error(
            status_code=404,
            code=ControlSpecApiErrorCode.CATALOG_ITEM_NOT_FOUND,
            detail_code="controlspec.api.catalog_item_not_found",
            message="The exact reference catalog item was not found.",
        )

    @app.exception_handler(CatalogBindingMismatchError)
    async def catalog_binding_mismatch(
        _request: Any,
        _exc: CatalogBindingMismatchError,
    ) -> CanonicalJSONResponse:
        return _error(
            status_code=409,
            code=ControlSpecApiErrorCode.CATALOG_BINDING_MISMATCH,
            detail_code="controlspec.reference.catalog_binding_mismatch",
            message="The selector does not bind the current exact catalog item.",
        )

    @app.exception_handler(PriorBindingError)
    async def prior_binding_invalid(
        _request: Any,
        _exc: PriorBindingError,
    ) -> CanonicalJSONResponse:
        return _error(
            status_code=422,
            code=ControlSpecApiErrorCode.PRIOR_BINDING_INVALID,
            detail_code="controlspec.api.prior_binding_invalid",
            message="The prior Decision does not bind the supplied original input.",
        )

    @app.exception_handler(ReferenceCatalogError)
    async def catalog_invalid(
        _request: Any,
        _exc: ReferenceCatalogError,
    ) -> CanonicalJSONResponse:
        return _error(
            status_code=400,
            code=ControlSpecApiErrorCode.SELECTION_INVALID,
            detail_code="controlspec.api.selection_invalid",
            message="The exact reference catalog selection is invalid.",
        )

    @app.exception_handler(ReferenceServiceError)
    @app.exception_handler(EvaluationInputError)
    async def semantic_input_invalid(
        _request: Any,
        _exc: Exception,
    ) -> CanonicalJSONResponse:
        return _error(
            status_code=422,
            code=ControlSpecApiErrorCode.INPUT_INVALID,
            detail_code="controlspec.api.semantic_input_invalid",
            message="The request cannot be safely evaluated by the reference plane.",
        )

    @app.exception_handler(StarletteHttpException)
    async def http_error(
        _request: Any,
        exc: StarletteHttpException,
    ) -> CanonicalJSONResponse:
        code = (
            ControlSpecApiErrorCode.CATALOG_ITEM_NOT_FOUND
            if exc.status_code == 404
            else ControlSpecApiErrorCode.INPUT_INVALID
        )
        return _error(
            status_code=exc.status_code,
            code=code,
            detail_code="controlspec.api.route_not_available",
            message="The requested ControlSpec reference operation is unavailable.",
        )

    @app.exception_handler(Exception)
    async def internal_failure(
        _request: Any,
        _exc: Exception,
    ) -> CanonicalJSONResponse:
        return _error(
            status_code=500,
            code=ControlSpecApiErrorCode.INTERNAL_FAILURE,
            detail_code="controlspec.api.internal_failure",
            message="The ControlSpec reference operation failed safely.",
        )

    @app.post(
        "/controlspec/v0/decide",
        response_model=DecideResponse,
        response_class=CanonicalJSONResponse,
        tags=["ControlSpec Reference"],
        openapi_extra=_request_body(DecideRequest),
    )
    async def decide(request: Request) -> DecideResponse:
        body = await _validated_body(request, DecideRequest)
        return service.decide(body)

    @app.post(
        "/controlspec/v0/recheck",
        response_model=RecheckResponse,
        response_class=CanonicalJSONResponse,
        tags=["ControlSpec Reference"],
        openapi_extra=_request_body(RecheckRequest),
    )
    async def check(request: Request) -> RecheckResponse:
        body = await _validated_body(request, RecheckRequest)
        return service.recheck(body)

    @app.post(
        "/controlspec/v0/receipts",
        response_model=ReceiptAssessmentResponse,
        response_class=CanonicalJSONResponse,
        tags=["ControlSpec Reference"],
        openapi_extra=_request_body(ReceiptAssessmentRequest),
    )
    async def receipt(request: Request) -> ReceiptAssessmentResponse:
        body = await _validated_body(request, ReceiptAssessmentRequest)
        return service.assess_receipt(body)

    @app.get(
        "/controlspec/v0/controls",
        response_model=ControlListResponse,
        response_class=CanonicalJSONResponse,
        tags=["ControlSpec Reference Catalog"],
    )
    def controls() -> ControlListResponse:
        return service.catalog.list_controls()

    @app.get(
        "/controlspec/v0/controls/{catalog_id}",
        response_model=ControlDetailResponse,
        response_class=CanonicalJSONResponse,
        tags=["ControlSpec Reference Catalog"],
    )
    def control(catalog_id: CatalogId) -> ControlDetailResponse:
        return service.catalog.get_control(str(catalog_id))

    @app.get(
        "/controlspec/v0/packs",
        response_model=PackListResponse,
        response_class=CanonicalJSONResponse,
        tags=["ControlSpec Reference Catalog"],
    )
    def packs() -> PackListResponse:
        return service.catalog.list_packs()

    @app.get(
        "/controlspec/v0/packs/{catalog_id}",
        response_model=PackDetailResponse,
        response_class=CanonicalJSONResponse,
        tags=["ControlSpec Reference Catalog"],
    )
    def pack(catalog_id: CatalogId) -> PackDetailResponse:
        return service.catalog.get_pack(str(catalog_id))

    def canonical_openapi() -> dict[str, Any]:
        if app.openapi_schema is not None:
            return app.openapi_schema
        document = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
            separate_input_output_schemas=False,
        )
        app.openapi_schema = document
        return document

    app.openapi = canonical_openapi  # type: ignore[method-assign]
    return app


def _load_default_enterprise_provider() -> ReferenceFactProvider:
    """Import the enterprise leaf only after an exact enterprise request."""

    from assurance.controlspec.profiles.reference import (
        load_default_riskspec_reference_fact_provider,
    )

    return load_default_riskspec_reference_fact_provider()


def _load_enterprise_scenario_provider(
    scenario: ReferenceScenarioFixture,
) -> ReferenceFactProvider:
    """Import the enterprise leaf only after one complete exact scenario match."""

    from assurance.controlspec.profiles.reference import (
        load_riskspec_scenario_fact_provider,
    )

    return load_riskspec_scenario_fact_provider(scenario)


def create_default_controlspec_reference_app() -> FastAPI:
    """Create the package-data-backed reference app; callers choose how to serve it."""

    catalog = load_default_reference_catalog()
    return create_controlspec_reference_app(
        service=ReferenceControlPlaneService(
            catalog=catalog,
            fact_provider=ImmutableScenarioFactProvider(
                release_id=catalog.release_id,
                catalog_digest=catalog.catalog_digest,
                scenarios=catalog.scenarios,
                enterprise_loader=_load_enterprise_scenario_provider,
            ),
        )
    )
