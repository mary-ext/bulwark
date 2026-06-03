//! The OpenAPI document describing the Bulwark REST API.
//!
//! Emitted to JSON by the `gen-openapi` binary; the front-end client is
//! generated from that JSON (see the README / `justfile`).

use utoipa::OpenApi;

use crate::{api, dto};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Bulwark API",
        description = "REST API for the Bulwark DNS filtering resolver.",
        version = env!("CARGO_PKG_VERSION"),
        license(name = "MIT")
    ),
    paths(
        api::status,
        api::setup,
        api::login,
        api::logout,
        api::get_config,
        api::put_upstreams,
        api::put_cache,
        api::put_filtering,
        api::put_server,
        api::put_querylog,
        api::put_stats_cfg,
        api::get_filters,
        api::put_custom_rules,
        api::add_custom_rule,
        api::check_domain,
        api::add_list,
        api::update_list,
        api::delete_list,
        api::refresh_list,
        api::get_clients,
        api::put_clients,
        api::get_stats,
        api::reset_stats,
        api::get_querylog,
        api::clear_querylog,
        api::get_upstreams,
        api::test_upstream,
    ),
    components(schemas(
        // Server-owned request/response shapes.
        api::ErrorResponse,
        api::OkResponse,
        api::StatusResponse,
        api::Credentials,
        api::FilteringSettings,
        api::ServerUpdateResponse,
        api::FiltersResponse,
        api::CustomRules,
        api::AddRule,
        api::AddRuleResponse,
        api::NewList,
        api::AddListResponse,
        api::ListUpdate,
        api::CheckRequest,
        api::CheckResponse,
        api::TestUpstream,
        api::TestResult,
        // Engine/upstream read-model DTOs.
        dto::StatsResponse,
        dto::TopEntryDto,
        dto::SeriesPointDto,
        dto::LatencyPercentilesDto,
        dto::QueryLogResponse,
        dto::LogEntryView,
        dto::UpstreamStatDto,
        dto::TransportKindDto,
        // The public configuration contract.
        bulwark_config::Config,
        bulwark_config::ServerConfig,
        bulwark_config::UpstreamsConfig,
        bulwark_config::CacheConfig,
        bulwark_config::BlockingMode,
        bulwark_config::FilterListConfig,
        bulwark_config::FilteringConfig,
        bulwark_config::ClientConfig,
        bulwark_config::QueryLogConfig,
        bulwark_config::StatsConfig,
        bulwark_config::AuthConfig,
    )),
    tags(
        (name = "auth", description = "Setup, login, and session management"),
        (name = "config", description = "Read and update configuration sections"),
        (name = "filters", description = "Filter lists, custom rules, and domain checks"),
        (name = "clients", description = "Client naming, tags, and per-client filtering"),
        (name = "stats", description = "Aggregate statistics"),
        (name = "querylog", description = "Query log browsing"),
        (name = "upstreams", description = "Upstream resolver status and testing"),
    )
)]
pub struct ApiDoc;
