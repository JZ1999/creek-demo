import json
import os
from datetime import date, datetime
from typing import Collection, Dict, List, Optional, Union
from uuid import UUID, uuid4

import structlog
from fama_interfaces.actor_dal import Actors
from fama_interfaces.blueprint_dal import Blueprints
from fama_interfaces.blueprint_service import BlueprintAnnotated, DeepCopyCompany
from fama_interfaces.company_dal import SettingTypes
from fama_interfaces.company_service import CompanySubCompanyDetails
from fama_interfaces.external_interface import (
    ActorInfo,
    ActorSummaryParameters,
    BlueprintCreate,
    BlueprintInfo,
    CompanyBaseWithParentUUID,
    CompanyEdit,
    CompanyInfo,
    CreateReportRequest,
    ItemRequest,
    KeywordGroupRequest,
    KeywordGroupResponse,
    ManualPostItemRequest,
    OptimizedItemsForReviewResponse,
    OptimizedUserSummary,
    ReportLogResponse,
    ReportSummaryResponse,
    RoleInfoMinimal,
    WorkflowDashboardEntry,
)
from fama_interfaces.item_dal import Items, LogType, Reports
from fama_interfaces.item_filters import (
    FlagCountResponse,
    GroupCountResponse,
    ItemsForReviewParams,
    ItemsForReviewSortCriteria,
    RatingType,
)
from fama_interfaces.item_service import CreateRatingRequest, CreateRatingResponse
from fama_interfaces.person_service import PersonInfoBase
from fama_interfaces.workflow_dal import (
    Status,
    WorkflowReportStatus,
    WorkflowRuns,
    WorkflowRunsChangeDueDate,
    WorkflowStepNames,
    WorkflowStepRuns,
)
from fama_interfaces.workflow_service import WorkflowRunsEx
from famautils.asgi import add_default_fama_extensions
from famautils.dal import GeneralDALClient, actor_uuid_opts
from famautils.enums import Domains
from famautils.exceptions import FamaHTTPException
from fastapi import FastAPI, Header, Query
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi_pagination import Page
from httpx import HTTPStatusError
from jwt import ExpiredSignatureError
from mangum import Mangum
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse

from external_interface import domain_client, passthrough, service
from external_interface.authorizer import AuthMiddleware, VerifyToken
from external_interface.config import AUTH0_CONFIG, ENV
from external_interface.core_translator.app import attach_v1_routes
from external_interface.exceptions import (
    CreateReportException,
    HTTPPassthroughException,
    ShortCircuitException,
    WorkflowUnlockException,
)
from external_interface.passthrough import base
from external_interface.redis_client import RedisClient
from external_interface.service import (
    BlueprintUpdate,
    CompanyCreation,
    CompanySettingsCreation,
    ReportSummaryItem,
    ReportSummaryRequest,
    convert_actor_to_actorinfo,
)

logger = structlog.get_logger()


async def get_company_uuids_from_jwt(request: Request) -> List[str]:
    company_uuids: List[str] = []
    headers_list: List[tuple] = request.headers.__dict__.get("_list")  # type: ignore
    jwt: str = ""
    if headers_list:
        try:
            jwt = list(filter(lambda i: i[0] == b"authorization", headers_list))[0][1].decode()  # type: ignore
        except (IndexError, ValueError, AttributeError) as e:
            logger.warn(f"An error ocurred while trying to obtain and decode the JWT from the headers: {e}")
            return []
    if jwt:
        try:
            verify_token = VerifyToken(str(jwt))
            token_payload = await verify_token.verify()
        except ExpiredSignatureError as exc:
            raise FamaHTTPException("token is expired", status_code=401) from exc
        if token_payload.get(f"{AUTH0_CONFIG['NAMESPACE']}/companyInfo", {}).get("allCompanies"):
            return ["__all__"]
        company_uuids = token_payload.get(f"{AUTH0_CONFIG['NAMESPACE']}/companyInfo", {}).get("companyIds")
    return company_uuids


def make_app() -> FastAPI:
    app: FastAPI = FastAPI(
        debug=(ENV == "dev"),
        title="Fama External Interface",
        description="Public endpoints.",
        version=os.getenv("CI_COMMIT_SHORT_SHA", "dev"),
    )
    app = add_default_fama_extensions(app)

    attach_v1_routes(app)

    @app.exception_handler(HTTPException)
    async def validation_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        """Supports meaningful feedback on status.HTTP_422_UNPROCESSABLE_ENTITY

        Args:
            request (Request): Incoming Header and Query Param container.
            exc (HTTPException): Thrown on invalid request values.

        Returns:
            JSONResponse: Formatted response object containing Exception message and Headers.
        """
        return JSONResponse(
            status_code=exc.status_code,
            content=jsonable_encoder({"detail": exc.detail, "headers": exc.headers, "params": request.query_params._dict}),
        )

    commit_hash = os.getenv("CI_COMMIT_SHA")
    logger.info(f"Running app version: {commit_hash}")

    @app.get("/version")
    def get_version():
        return JSONResponse(commit_hash) if commit_hash else JSONResponse("No app version found.")

    @app.get("/versions")
    async def get_versions(
        request: Request,
        actor_uuid_header: Optional[str] = Header(default=None),
    ):
        full_result = {app.title: commit_hash or "Commit Hash/Version not set"}
        async with GeneralDALClient(actor_uuid_opts(request)) as dal:
            for domain in [Domains.actor, Domains.blueprint, Domains.company, Domains.item, Domains.person, Domains.workflow]:
                try:
                    response = await dal.client.get(dal.build_url(domain, "version"))
                    version = response.json()
                except Exception:
                    version = "Commit Hash/Version not known"
                full_result[domain] = version
        return JSONResponse(status_code=200, content=jsonable_encoder(full_result))

    @app.post("/reports", tags=["Report"])
    async def create_report(
        request: Request,
        report_request: CreateReportRequest,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> JSONResponse:
        blueprint: Blueprints = await domain_client.get_blueprint(request, report_request.blueprint_uuid)

        if not blueprint.is_active or blueprint.workflow_config_uuid is None:
            raise CreateReportException("Blueprint status is not active or has no workflow config", status_code=422)

        response = await service.create_report_and_trigger_workflow(
            request,
            person_info=report_request.person_info,
            workflow_config_uuid=blueprint.workflow_config_uuid,
            blueprint_uuid=report_request.blueprint_uuid,
            company_uuid=report_request.company_uuid,
            profile_urls=report_request.profile_urls,
        )
        return JSONResponse(jsonable_encoder(response))

    @app.get("/reports/summary/dispute", response_model=ReportSummaryResponse, tags=["Report"])
    async def get_report_summaries_dispute(
        request: Request,
        page_size: int = 25,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> ReportSummaryResponse:
        message = "Completed Successfully"
        summary = []

        company_uuids = await get_company_uuids_from_jwt(request)

        try:
            summary = await service.summaries_dispute(request, company_uuids, page_size)
        except ShortCircuitException as ex:
            message = ex.detail  # type: ignore

        return ReportSummaryResponse(
            report_summaries=summary,
            message=message,
            next_page=False,
        )

    @app.get("/reports/summary", response_model=ReportSummaryResponse, tags=["Report"])
    async def get_report_summaries(
        request: Request,
        person_name: Union[str, None] = None,
        company_name: Union[str, None] = None,
        workflow_status: Optional[List[Union[WorkflowReportStatus, Status]]] = Query(None),
        blueprint_uuid: Union[UUID, None] = None,
        min_due_date: Union[datetime, None] = None,
        max_due_date: Union[datetime, None] = None,
        workflow_step_name: Optional[str] = Query(None, description="List of step names separated by commas", example="ProfilesModelPredict,PersonScrape"),
        without_steps: Optional[bool] = Query(
            None, description="When workflow_step_name filter is provided this parameter allows workflows that has not been started yet to be included"
        ),
        page_size: int = 25,
        page: int = 0,
        descending: Optional[bool] = Query(False, description="change the order by due_date to descending, new ones first."),
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> ReportSummaryResponse:
        """
        Status filters on either `Status` value or In Process/Completed value.

        Args:
            session (`AsyncSession`): updated with dao
            workflow_status (`Optional[List[Union[WorkflowReportStatus, Status]]]`): Any combination of:
                `completed`, `in_process`, `TO_DO`, `DONE`, `FAILED`, `TIMEOUT`, `CANCELLED`
            max_due_date (`Optional[datetime]`): Deliverable filter
            min_due_date (`Optional[datetime]`): Deliverable filter
            company_name (`Optional[str]`): Company filter
            person_name (`Optional[str]`): Person filter
            blueprint_uuid (`Optional[UUID]`): Blueprint filter
            workflow_step_name(`Optional[str]]`): Workflow Step Name filter, List of step names separated by commas
            page_size (`int`): Pagination size
            page (`int`): Page number
            without_steps (`Optional[bool]`): When workflow_step_name filter is provided this parameter
                allows workflows that has not been started yet to be included
            descending: (`Optional[bool]`):
        Returns:
            `ReportSummaryResponse`: Contains a list of filtered ReportSummaryItem on submitted parameters,
                an informational message and next_page pagination information.

        Pagination: managed by  page_size  and page, will return next_page true if next page is available
        """
        if workflow_status is None:
            workflow_status = []
        if workflow_step_name:
            # validation type
            try:
                workflow_step_names: Optional[List[WorkflowStepNames]] = list(map(WorkflowStepNames, workflow_step_name.split(",")))
                logger.info(f"workflow_step_name_csv map to {workflow_step_names}")
            except ValueError:
                raise HTTPException(status_code=400, detail="workflow_step_name_csv could not be converted to a list of WorkflowStepNames values")
        company_uuids = await get_company_uuids_from_jwt(request)

        logger.info(f"Company UUIDS {company_uuids}")
        args: ReportSummaryRequest = ReportSummaryRequest(
            person_name=person_name,
            company_name=company_name,
            status=workflow_status,
            blueprint_uuid=blueprint_uuid,
            min_due_date=min_due_date,
            max_due_date=max_due_date,
            page_size=page_size,
            page=page,
            workflow_step_name_csv=workflow_step_name,
            without_steps=without_steps,
            descending=descending,
            company_uuids=company_uuids,
        )
        message = "Completed Successfully"
        summary: List[ReportSummaryItem] = []
        next_page = False
        try:
            summary, next_page = await service.fetch_report_summaries(request, args)
        except ShortCircuitException as ex:
            message = ex.detail  # type: ignore

        return ReportSummaryResponse(
            report_summaries=summary,
            message=message,
            next_page=next_page,
        )

    @app.get("/report/summary", response_model=ReportSummaryItem, tags=["Report"])
    async def get_report_summary(
        request: Request,
        report_uuid: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> ReportSummaryItem:
        async with GeneralDALClient(actor_uuid_opts(request)) as dal:
            report = await dal.get(Reports, report_uuid)
            workflow_run = await dal.get(WorkflowRuns, report.workflow_run_uuid)
            step_runs: List[WorkflowStepRuns] = await dal.get_all_filter_by(WorkflowStepRuns, field="workflow_run_uuid", value=str(workflow_run.external_id))
            workflow_run_ex: WorkflowRunsEx = WorkflowRunsEx(**workflow_run.dict(), step_runs=step_runs)
            return await service.augment_report_summary(request, workflow_run_ex)

    @app.post("/report/cancel/{report_uuid}", tags=["Report"])
    async def cancel_report(
        request: Request,
        report_uuid: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> JSONResponse:
        return await service.cancel_report(request, report_uuid, modified_by=actor_uuid_opts(request))

    @app.get("/reports/flag_count/{report_uuid}", response_model=FlagCountResponse, tags=["Report"])
    async def get_flag_count(
        request: Request,
        report_uuid: UUID,
        item_type_name: Optional[str] = None,
        item_source_name: Optional[str] = None,
        item_post_type: Optional[str] = None,
        min_date: Optional[date] = None,
        max_date: Optional[date] = None,
        behaviors: Optional[str] = None,
        keywords: Optional[str] = None,
        rating_type: Optional[RatingType] = None,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> FlagCountResponse:
        return await domain_client.get_flag_count(
            request, report_uuid, item_type_name, item_source_name, item_post_type, min_date, max_date, behaviors, keywords, rating_type
        )

    @app.get("/reports/keyword_count/{report_uuid}", response_model=GroupCountResponse, tags=["Report"])
    async def keyword_flag_count(
        request: Request,
        report_uuid: UUID,
        item_type_name: Optional[str] = None,
        item_source_name: Optional[str] = None,
        item_post_type: Optional[str] = None,
        min_date: Optional[date] = None,
        max_date: Optional[date] = None,
        behaviors: Optional[str] = None,
        keywords: Optional[str] = None,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> GroupCountResponse:
        return await domain_client.get_keyword_count(
            request, report_uuid, item_type_name, item_source_name, item_post_type, min_date, max_date, behaviors, keywords
        )

    @app.get("/report_logs_multifilter", response_model=List[ReportLogResponse], tags=["Report"])
    async def get_report_logs_multifilter(
        request: Request,
        report_uuid: UUID,
        log_type: Optional[LogType] = None,
        log_message: Optional[str] = None,
        start_date: Optional[datetime] = Query(None, description="Value is in yyyy-MM-dd HH:mm:ss format"),
        end_date: Optional[datetime] = Query(None, description="Value is in yyyy-MM-dd HH:mm:ss format"),
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> List[ReportLogResponse]:
        return await service.get_report_log_multifilter(request, report_uuid, log_type, log_message, start_date, end_date)  # type: ignore

    @app.post("/reports/trigger_pdf_generation")
    async def trigger_pdf_generation(
        request: Request,
        report_uuid: UUID,
        actor_uuid: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> JSONResponse:
        return await service.trigger_pdf_regeneration(request, report_uuid, actor_uuid)  # type: ignore

    @app.post("/manual_add_posts_item", response_model=Items, response_model_exclude=base.default_excludes)
    async def manual_add_posts_item(
        request: Request,
        item_request: ItemRequest,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> Items:
        return await service.manual_add_posts(request, item_request)  # type: ignore

    @app.post("/manual_create_posts_item", response_model=Items, response_model_exclude=base.default_excludes)
    async def manual_create_posts_item(
        request: Request,
        item_request: ManualPostItemRequest,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> Items:
        return await service.manual_create_posts(request, item_request, actor_uuid_header)  # type: ignore

    @app.post("/manual_scrape/item", response_model=Items, response_model_exclude=base.default_excludes)
    async def manual_scrape_posts_item(
        request: Request,
        item_request: ManualPostItemRequest,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> Items:
        return await service.manual_scrape_create_post(request, item_request, actor_uuid_header)  # type: ignore

    @app.delete("/profile/{profile_id}", tags=["Item"])
    async def delete_complete_profile(request: Request, profile_id: Union[int, UUID], actor_uuid_header: Optional[str] = Header(default=None)):
        """
        Deletes a social media profile and all post associated with it.

        Args:
            profile_id: profile internal id or external UUID
        Returns:
            `string`: message containing basic information of successful deletion or failures.
        """
        return await service.delete_profile_and_posts(request, profile_id)

    @app.delete("/remove_posts_item/{item_uuid}", response_model=Items, response_model_exclude=base.default_excludes)
    async def remove_posts_item(
        request: Request,
        item_uuid: UUID,
        modified_by: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> Items:
        return await service.remove_posts(request, item_uuid, modified_by)  # type: ignore

    @app.delete("/remove_profile_item/{item_uuid}", response_model=Items, response_model_exclude=base.default_excludes)
    async def remove_profile_item(
        request: Request,
        item_uuid: UUID,
        modified_by: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> Items:
        return await service.remove_profile(request, item_uuid, modified_by)  # type: ignore

    @app.get(
        "/blueprint/root",
        response_model=List[BlueprintAnnotated],
        tags=["Blueprint"],
        response_model_exclude=base.default_excludes_for_response_model,
    )
    async def get_root_blueprints(request: Request, actor_uuid_header: Optional[str] = Header(default=None)) -> List[BlueprintAnnotated]:
        return await service.get_all_root_blueprints_annotated(request)

    @app.get(
        "/blueprint/template",
        response_model=List[BlueprintAnnotated],
        tags=["Blueprint"],
        response_model_exclude=base.default_excludes_for_response_model,
    )
    async def get_template_blueprints(request: Request, actor_uuid_header: Optional[str] = Header(default=None)) -> List[BlueprintAnnotated]:
        "WARNING: Cached value is list of dicts, return value is List[BlueprintAnnotated]"
        cache_key = "blueprint-templates"
        redis = RedisClient()
        raw_cached = redis.get(cache_key)
        cached: List[dict] = []
        if raw_cached:
            cached = json.loads(raw_cached)
        else:
            cached = await service.get_all_template_blueprints_annotated(request)
            thirty_days = 30 * 24 * 60 * 60  # measured in seconds
            redis.set(cache_key, json.dumps(cached), ex=thirty_days)
        rehydrated: List[BlueprintAnnotated] = []
        for entry in cached:
            rehydrated.append(BlueprintAnnotated(**entry))
        return rehydrated

    @app.get(
        "/blueprint/{blueprint_uuid}",
        response_model=BlueprintAnnotated,
        tags=["Blueprint"],
        response_model_exclude=base.default_excludes_for_response_model,
    )
    async def get_blueprint_info(
        request: Request,
        blueprint_uuid: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> BlueprintAnnotated:
        return await domain_client.get_blueprint_annotated(request, blueprint_uuid)

    @app.post(
        "/blueprint/copy",
        response_model=List[BlueprintAnnotated],
        tags=["Blueprint"],
        response_model_exclude=base.default_excludes_for_response_model,
    )
    async def copy_blueprint(
        request: Request,
        params: DeepCopyCompany,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> Collection[BlueprintAnnotated]:
        """Copy a blueprint into new ones for the company and optionally its sub-companies"""
        return await service.copy_blueprint(request, params)

    @app.patch("/report/rerun/{report_uuid}", tags=["Report"])
    async def rerun_report(
        request: Request,
        report_uuid: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> JSONResponse:
        async with GeneralDALClient(actor_uuid_opts(request)) as dal:
            return await service.rerun_complete_report(dal, report_uuid)

    @app.post(
        "/blueprint/update",
        tags=["Blueprint"],
        response_model=List[BlueprintAnnotated],
        response_model_exclude=base.default_excludes_for_response_model,
    )
    async def update_blueprints(
        request: Request,
        params: BlueprintUpdate,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> Collection[BlueprintAnnotated]:
        """Updates a list of blueprints to one specific config"""
        return await service.update_blueprints(request, params)

    @app.get("/actor/summary", response_model=Page[OptimizedUserSummary], tags=["Actor"])
    async def actor_summary(
        request: Request,
        actor_uuid: UUID,
        user_email: Optional[str] = None,
        user_name: Optional[str] = None,
        page_num: Optional[int] = 1,
        page_size: Optional[int] = 10,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> Page[OptimizedUserSummary]:
        try:
            params: ActorSummaryParameters = ActorSummaryParameters(
                actor_uuid=actor_uuid, user_name=user_name, user_email=user_email, page_num=page_num, page_size=page_size
            )
        except ValidationError as ex:
            raise HTTPException(status_code=422, detail="".join(str(ex.errors())))
        return await service.get_all_users_summary(request, params)

    @app.get("/actor_info/{actor_uuid}", response_model=ActorInfo, tags=["Actor"])
    async def get_actor_info(
        request: Request,
        actor_uuid: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> ActorInfo:
        async with GeneralDALClient(actor_uuid_opts(request)) as dal:
            actor_obj = await dal.get(Actors, actor_uuid)
            return await convert_actor_to_actorinfo(dal, actor_obj)

    @app.post("/actor_info", response_model=ActorInfo, tags=["Actor"])
    async def get_or_create_actor_and_user(
        request: Request,
        actor: ActorInfo,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> ActorInfo:
        async with GeneralDALClient(actor_uuid_opts(request)) as dal:
            return await service.create_or_update_actor_and_user(dal, request, actor)

    @app.put("/actor_info", response_model=ActorInfo, tags=["Actor"])
    async def update_actor(
        request: Request,
        actor: ActorInfo,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> ActorInfo:
        async with GeneralDALClient(actor_uuid_opts(request)) as dal:
            return await service.create_or_update_actor_and_user(dal, request, actor)

    @app.delete("/actor_info", tags=["Actor"])
    async def delete_actor_and_user(
        request: Request,
        actor: ActorInfo,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> None:
        return await service.delete_actor_and_user(request, actor)

    @app.get("/actor_info_list", response_model=List[ActorInfo], tags=["Actor"])
    async def get_paged_actor_info(
        request: Request,
        name: str = "",
        email: str = "",
        page_num: int = 1,
        page_size: int = 10,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> List[ActorInfo]:
        async with GeneralDALClient(actor_uuid_opts(request)) as dal:
            return await service.get_paged_actor_info(dal, name, email, page_num, page_size)

    @app.get("/item/items_for_review", response_model=Page[OptimizedItemsForReviewResponse], tags=["Item"])
    async def get_items_for_review(
        request: Request,
        report_uuid: Optional[UUID] = None,
        item_type_name: Optional[str] = None,
        rating_type: Optional[RatingType] = None,
        page_num: int = 1,
        page_size: int = 10,
        item_source_name: Optional[str] = None,
        item_post_type: Optional[str] = None,
        min_date: Optional[date] = None,
        max_date: Optional[date] = None,
        behaviors: Optional[str] = None,
        keywords: Optional[str] = None,
        sort_criteria: Optional[ItemsForReviewSortCriteria] = None,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> Page[OptimizedItemsForReviewResponse]:
        item_source_name_list: Optional[List[str]] = None
        item_post_type_list: Optional[List[str]] = None
        item_type_name_list: Optional[List[str]] = None
        behaviors_list: Optional[List[str]] = None
        keywords_list: Optional[List[str]] = None
        if item_source_name:
            try:
                item_source_name_list = item_source_name.split(",")
                logger.info(f"item_source_name map to {item_source_name}")
            except ValueError:
                raise HTTPException(status_code=400, detail="item_source_name could not be converted to a list")
        if item_post_type:
            try:
                item_post_type_list = item_post_type.split(",")
                logger.info(f"item_post_type map to {item_post_type}")
            except ValueError:
                raise HTTPException(status_code=400, detail="item_post_type could not be converted to a list")

        if item_type_name:
            try:
                item_type_name_list = item_type_name.split(",")
                logger.info(f"item_post_type map to {item_type_name}")
            except ValueError:
                raise HTTPException(status_code=400, detail="item_post_type could not be converted to a list")
        if behaviors:
            try:
                behaviors_list = behaviors.split(",")
                logger.info(f"behaviors map to {behaviors}")
            except ValueError:
                raise HTTPException(status_code=400, detail="behaviors could not be converted to a list")
        if keywords:
            try:
                keywords_list = keywords.split(",")
                logger.info(f"keywords map to {keywords}")
            except ValueError:
                raise HTTPException(status_code=400, detail="keywords could not be converted to a list")
        items_for_review_params: ItemsForReviewParams = ItemsForReviewParams(
            report_uuid=report_uuid,
            item_type_name=item_type_name_list,
            item_source_name=item_source_name_list,
            rating_type=rating_type,
            item_post_type=item_post_type_list,
            min_date=min_date,
            max_date=max_date,
            behaviors=behaviors_list,
            keywords=keywords_list,
            sort_criteria=sort_criteria,
        )
        return await service.get_items_for_review(request, items_for_review_params, page_num, page_size)

    @app.get("/roles_info", response_model=List[RoleInfoMinimal], tags=["Actor"])
    async def get_all_roles(request: Request, actor_uuid_header: Optional[str] = Header(default=None)) -> List[RoleInfoMinimal]:
        return await service.get_all_roles(request)

    @app.post("/companies_info", response_model=List[CompanyInfo], tags=["Company"])
    async def get_companies_info(
        request: Request,
        companies_uuids: List[UUID],
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> List[CompanyInfo]:
        return await domain_client.get_companies_info(request, companies_uuids)

    @app.get("/blueprints", response_model=List[BlueprintInfo], tags=["Blueprint"])
    async def get_all_blueprints(request: Request, actor_uuid_header: Optional[str] = Header(default=None)) -> List[BlueprintInfo]:
        return await service.get_all_blueprints(request)

    @app.delete("/blueprints/{blueprint_uuid}", response_model=BlueprintInfo, tags=["Blueprint"], description="Removes the blueprint and its associated data")
    async def remove_blueprint(request: Request, blueprint_uuid: UUID, actor_uuid_header: Optional[str] = Header(default=None)) -> BlueprintInfo:
        return await service.remove_blueprint_and_associated_data(request, blueprint_uuid)

    @app.put(
        "/company_edit/{company_uuid}",
        response_model=CompanyEdit,
        tags=["Company"],
        response_model_exclude=base.default_excludes_for_response_model,
    )
    async def update_company(
        request: Request,
        company_uuid: UUID,
        company_edit: CompanyEdit,
        actor_uuid_header: Optional[str] = Header(default=None),
        x_amzn_oidc_identity: Optional[UUID] = Header(None),
    ) -> CompanyEdit:
        if company_edit.modified_by:
            modified_by = company_edit.modified_by
        elif x_amzn_oidc_identity:
            modified_by = x_amzn_oidc_identity
        else:
            raise HTTPException(
                status_code=422,
                detail="Should have x-amzn-oidc-identity header or modified_by referring to an actor uuid",
            )
        return await service.create_or_update_company(request, company_uuid, company_edit, modified_by)

    @app.post("/company_and_company_settings", tags=["Company"])
    async def create_company_with_company_settings(
        request: Request,
        company: CompanyBaseWithParentUUID,
        company_settings_creation: List[CompanySettingsCreation],
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> CompanyCreation:
        return await service.create_company_and_company_settings(request, company, company_settings_creation)

    @app.get(
        "/setting_types",
        response_model=List[SettingTypes],
        tags=["Company"],
        response_model_exclude=base.default_excludes,
    )
    async def get_all_setting_types(request: Request, actor_uuid_header: Optional[str] = Header(default=None)) -> List[SettingTypes]:
        return await service.get_setting_types(request)

    @app.post("/create_person", response_model=UUID, tags=["Person"])
    async def create_person(
        request: Request,
        person_info: PersonInfoBase,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> UUID:
        return await service.create_person(request, person_info)

    @app.get("/person_info/{person_uuid}", response_model=PersonInfoBase, tags=["Person"])
    async def get_person_info(
        request: Request,
        person_uuid: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> PersonInfoBase:
        async with GeneralDALClient(actor_uuid_opts(request)) as dal:
            return await domain_client.get_person_info(dal, person_uuid)

    @app.post("/rate_items", tags=["Item"])
    async def create_rating(
        request: Request,
        params: CreateRatingRequest,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> CreateRatingResponse:
        return await service.create_rating(request, params)

    @app.post("/profile_manual_rate_done", tags=["Workflow"])
    async def profile_manual_rate_done(
        request: Request,
        report_uuid: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ):
        return await service.profile_manual_rate_done(request, report_uuid)

    @app.post("/profile_post_scrape_done", tags=["Workflow"])
    async def profile_post_scrape_done(
        request: Request,
        report_uuid: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ):
        return await service.profile_manual_post_scrape_done(request, report_uuid)

    @app.post("/post_manual_rate_done", tags=["Workflow"])
    async def post_manual_rate_done(
        request: Request,
        report_uuid: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ):
        return await service.post_manual_rate_done(request, report_uuid)

    @app.put("/blueprint/active/{company_uuid}", tags=["Blueprint"])
    async def blueprint_change_active(
        request: Request,
        active: bool,
        blueprint_uuid: UUID,
        company_uuid: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> JSONResponse:
        async with GeneralDALClient(actor_uuid_opts(request)) as dal:
            return await service.blueprint_change_active(dal, active, blueprint_uuid, company_uuid)

    @app.get("/subcompanies_multifilter", response_model=Page[CompanySubCompanyDetails], tags=["Company"])
    async def subcompanies_multifilter(
        request: Request,
        page: int = 1,
        size: int = 50,
        company_ids: Optional[List[str]] = Query(None, description="List of companies"),
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> Page[CompanySubCompanyDetails]:
        return await service.subcompanies_multifilter(request, page, size, company_ids)  # type: ignore[arg-type]

    @app.post("/workflow/unlock/{workflow_run_uuid}", response_model=WorkflowRuns, tags=["Workflow"], response_model_exclude=base.default_excludes)
    async def unlock_workflow(
        request: Request,
        workflow_run_uuid: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> WorkflowRuns:
        try:
            response = await GeneralDALClient(actor_uuid_opts(request), raise_for_status=True).client.get(
                url=GeneralDALClient.build_url(Domains.workflow, "workflow_runs", "unlock", workflow_run_uuid)
            )
        except HTTPStatusError as exc:
            raise HTTPPassthroughException(exc) from exc

        workflow: WorkflowRuns = WorkflowRuns(**response.json())

        if workflow.is_locked():
            raise WorkflowUnlockException("Error unlocking workflow", status_code=500)

        return workflow

    @app.post("/blueprint", response_model=BlueprintInfo, tags=["Blueprint"])
    async def create_blueprint(
        request: Request,
        blueprint_details: BlueprintCreate,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> BlueprintInfo:
        result = await domain_client.create_blueprint(request, blueprint_details)
        RedisClient().delete("blueprint-templates")
        return result

    @app.patch("/dispute/start/{report_uuid}", tags=["Report"])
    async def dispute_start(
        request: Request,
        report_uuid: UUID,
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> JSONResponse:
        async with GeneralDALClient(actor_uuid_opts(request)) as dal:
            return await service.report_start_dispute(dal, report_uuid)

    @app.get("/workflow/dashboard", response_model=List[WorkflowDashboardEntry], tags=["Workflow"])
    async def get_workflow_dashboard_stats(request: Request, actor_uuid_header: Optional[str] = Header(default=None)) -> List[WorkflowDashboardEntry]:
        return await domain_client.get_workflow_dashboard_stats(request)

    @app.put("/workflowruns/change_due_date", response_model=WorkflowRunsEx, tags=["Workflow"], response_model_exclude=base.default_excludes)
    async def change_workflow_runs_due_date(
        request: Request,
        workflow_run: WorkflowRunsChangeDueDate,
        actor_uuid_header: Optional[str] = Header(default=None),
    ):
        return await domain_client.change_workflow_due_date_and_update_sla_met(request, workflow_run)

    @app.get(
        "/companydal/companies", response_model=List[domain_client.CompaniesWithIsChild], tags=["Company DAL"], response_model_exclude=base.default_excludes
    )
    async def get_companies_with_is_child(request: Request):
        company_uuids = await get_company_uuids_from_jwt(request)
        return await domain_client.get_companies_with_is_child(request, company_uuids)

    @app.post(
        "/company_subcompany",
        response_model=List[domain_client.CompaniesWithIsChild],
        tags=["Company DAL"],
        response_model_exclude=base.default_excludes,
    )
    async def get_companies_with_subcompanies(request: Request, company_uuids: List[Union[UUID, str]]):
        return await domain_client.get_companies_and_subcompanies(request, company_uuids)

    @app.get("/companydal/parent_companies", response_model=Page[CompanySubCompanyDetails], tags=["Company DAL"])
    async def get_parent_companies(
        request: Request,
        page: int = Query(default=1, description="Which page to fetch, default=1"),
        size: int = Query(default=50, description="Number of companies per page, default=50"),
    ):
        company_uuids = await get_company_uuids_from_jwt(request)
        return await domain_client.get_parent_companies(request, company_uuids, page, size)

    @app.get("/companydal/sub_companies", response_model=Page[CompanySubCompanyDetails], tags=["Company DAL"])
    async def get_sub_companies(
        request: Request,
        page: int = Query(default=1, description="Which page to fetch, default=1"),
        size: int = Query(default=50, description="Number of sub companies per page, default=50"),
        company_uuid: UUID = Query(default=uuid4(), description="Parent Company UUID"),
    ):
        company_uuids = await get_company_uuids_from_jwt(request)
        return await domain_client.get_sub_companies(request, company_uuid, company_uuids, page, size)

    @app.post("/blueprint/keyword_group", response_model=KeywordGroupResponse, tags=["Blueprint"])
    async def post_keyword_group(request: Request, keyword_group: KeywordGroupRequest) -> KeywordGroupResponse:
        return await domain_client.create_keyword_group(request, keyword_group)

    @app.get("/blueprint/keyword_group/{blueprint_uuid}", response_model=List[KeywordGroupResponse], tags=["Blueprint"])
    async def get_keyword_group(request: Request, blueprint_uuid: UUID) -> List[KeywordGroupResponse]:
        return await service.get_keyword_groups(request, blueprint_uuid)

    @app.get("/reports/keyword_options/{report_id}", response_model=List[str], tags=["Report"])
    async def get_keyword_options(
        request: Request,
        report_id: Union[UUID, int],
        actor_uuid_header: Optional[str] = Header(default=None),
    ) -> List[str]:
        return await service.get_keyword_options(request, report_id)

    passthrough.attach_all_routes(app)

    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
    app.add_middleware(AuthMiddleware)

    return app


global_app = make_app()


def handler(event, context) -> Dict[str, str]:
    mangum_handler = Mangum(global_app)
    return mangum_handler(event, context)
