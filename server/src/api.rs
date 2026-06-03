//! The HTTP REST API (Axum), annotated for OpenAPI via `utoipa`.
//!
//! Handlers use concrete request/response types (rather than ad-hoc
//! `serde_json::Value`) so the generated OpenAPI spec — and the front-end client
//! generated from it — stay in lockstep with the server.

use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{middleware, Json, Router};
use bulwark_config::{
    BlockingMode, CacheConfig, ClientConfig, Config, FilterListConfig, QueryLogConfig,
    ServerConfig, StatsConfig, UpstreamsConfig,
};
use bulwark_filter::{ClientInfo, Verdict};
use bulwark_upstream::{test_spec, UpstreamSpec};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::app::{apply_config, write_list_text, AppState};
use crate::auth::{hash_password, verify_password, SESSION_COOKIE};
use crate::dto::{LogEntryView, QueryLogResponse, StatsResponse, UpstreamStatDto};

/// API error type that renders as a JSON `{ "error": ... }` body.
pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    NotFound(String),
    Internal(String),
}

/// Error body returned for any non-2xx response.
#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(ErrorResponse { error: msg })).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(e.to_string())
}

// ---------------------------------------------------------------------------
// Shared response shapes
// ---------------------------------------------------------------------------

/// Generic success acknowledgement: `{ "ok": true }`.
#[derive(Serialize, ToSchema)]
pub struct OkResponse {
    pub ok: bool,
}

impl OkResponse {
    fn ok() -> Json<Self> {
        Json(Self { ok: true })
    }
}

/// Build the full API + middleware router.
pub fn router(state: AppState) -> Router {
    let public = Router::new()
        .route("/api/status", get(status))
        .route("/api/setup", post(setup))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout));

    let protected = Router::new()
        .route("/api/config", get(get_config))
        .route("/api/config/upstreams", put(put_upstreams))
        .route("/api/config/cache", put(put_cache))
        .route("/api/config/filtering", put(put_filtering))
        .route("/api/config/server", put(put_server))
        .route("/api/config/querylog", put(put_querylog))
        .route("/api/config/stats", put(put_stats_cfg))
        .route("/api/filters", get(get_filters))
        .route("/api/filters/custom", put(put_custom_rules))
        .route("/api/filters/rule", post(add_custom_rule))
        .route("/api/filters/check", post(check_domain))
        .route("/api/filters/lists", post(add_list))
        .route(
            "/api/filters/lists/{id}",
            put(update_list).delete(delete_list),
        )
        .route("/api/filters/lists/{id}/refresh", post(refresh_list))
        .route("/api/clients", get(get_clients).put(put_clients))
        .route("/api/stats", get(get_stats))
        .route("/api/stats/reset", post(reset_stats))
        .route("/api/querylog", get(get_querylog).delete(clear_querylog))
        .route("/api/upstreams", get(get_upstreams))
        .route("/api/upstreams/test", post(test_upstream))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    public.merge(protected).with_state(state)
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == SESSION_COOKIE).then(|| v.to_string())
    })
}

/// Middleware that rejects requests without a valid session.
async fn require_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let ok = cookie_token(&headers)
        .map(|t| state.sessions.validate(&t))
        .unwrap_or(false);
    if ok {
        next.run(request).await
    } else {
        ApiError::Unauthorized.into_response()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// Setup/auth status and basic server info.
#[derive(Serialize, ToSchema)]
pub struct StatusResponse {
    /// Whether the initial admin account still needs to be created.
    pub setup_needed: bool,
    /// Whether the current request carries a valid session.
    pub authed: bool,
    pub version: String,
    /// DNS listen addresses (host:port).
    #[schema(value_type = Vec<String>)]
    pub dns_bind: Vec<std::net::SocketAddr>,
}

#[utoipa::path(
    get,
    path = "/api/status",
    tag = "auth",
    responses((status = 200, body = StatusResponse))
)]
pub async fn status(State(state): State<AppState>, headers: HeaderMap) -> Json<StatusResponse> {
    let cfg = state.config.read().await;
    let authed = cookie_token(&headers)
        .map(|t| state.sessions.validate(&t))
        .unwrap_or(false);
    Json(StatusResponse {
        setup_needed: cfg.auth.needs_setup(),
        authed,
        version: env!("CARGO_PKG_VERSION").to_string(),
        dns_bind: cfg.server.dns_bind.clone(),
    })
}

fn session_cookie(token: &str) -> String {
    format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800")
}

#[utoipa::path(
    post,
    path = "/api/setup",
    tag = "auth",
    request_body = Credentials,
    responses(
        (status = 200, body = OkResponse, description = "Admin account created; session cookie set"),
        (status = 400, body = ErrorResponse)
    )
)]
pub async fn setup(
    State(state): State<AppState>,
    Json(creds): Json<Credentials>,
) -> ApiResult<Response> {
    {
        let cfg = state.config.read().await;
        if !cfg.auth.needs_setup() {
            return Err(ApiError::BadRequest("already set up".into()));
        }
    }
    if creds.username.trim().is_empty() || creds.password.len() < 6 {
        return Err(ApiError::BadRequest(
            "username required and password must be at least 6 characters".into(),
        ));
    }
    let hash = hash_password(&creds.password).map_err(internal)?;
    let mut cfg = state.config.read().await.clone();
    cfg.auth.username = creds.username;
    cfg.auth.password_hash = Some(hash);
    apply_config(&state, cfg).await.map_err(internal)?;

    let token = state.sessions.create();
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    Ok((headers, OkResponse::ok()).into_response())
}

#[utoipa::path(
    post,
    path = "/api/login",
    tag = "auth",
    request_body = Credentials,
    responses(
        (status = 200, body = OkResponse, description = "Authenticated; session cookie set"),
        (status = 401, body = ErrorResponse)
    )
)]
pub async fn login(
    State(state): State<AppState>,
    Json(creds): Json<Credentials>,
) -> ApiResult<Response> {
    let cfg = state.config.read().await;
    let ok = cfg.auth.username == creds.username
        && cfg
            .auth
            .password_hash
            .as_ref()
            .is_some_and(|h| verify_password(&creds.password, h));
    drop(cfg);
    if !ok {
        return Err(ApiError::Unauthorized);
    }
    let token = state.sessions.create();
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, session_cookie(&token).parse().unwrap());
    Ok((headers, OkResponse::ok()).into_response())
}

#[utoipa::path(
    post,
    path = "/api/logout",
    tag = "auth",
    responses((status = 200, body = OkResponse, description = "Session cleared"))
)]
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(t) = cookie_token(&headers) {
        state.sessions.remove(&t);
    }
    let mut out = HeaderMap::new();
    out.insert(
        header::SET_COOKIE,
        format!("{SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0")
            .parse()
            .unwrap(),
    );
    (out, OkResponse::ok()).into_response()
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/config",
    tag = "config",
    responses(
        (status = 200, body = Config, description = "Full config (password hash redacted)"),
        (status = 401, body = ErrorResponse)
    )
)]
pub async fn get_config(State(state): State<AppState>) -> Json<Config> {
    let mut cfg = state.config.read().await.clone();
    cfg.auth.password_hash = None;
    Json(cfg)
}

#[utoipa::path(
    put,
    path = "/api/config/upstreams",
    tag = "config",
    request_body = UpstreamsConfig,
    responses((status = 200, body = OkResponse), (status = 400, body = ErrorResponse))
)]
pub async fn put_upstreams(
    State(state): State<AppState>,
    Json(body): Json<UpstreamsConfig>,
) -> ApiResult<Json<OkResponse>> {
    let mut cfg = state.config.read().await.clone();
    cfg.upstreams = body;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(OkResponse::ok())
}

#[utoipa::path(
    put,
    path = "/api/config/cache",
    tag = "config",
    request_body = CacheConfig,
    responses((status = 200, body = OkResponse), (status = 400, body = ErrorResponse))
)]
pub async fn put_cache(
    State(state): State<AppState>,
    Json(body): Json<CacheConfig>,
) -> ApiResult<Json<OkResponse>> {
    let mut cfg = state.config.read().await.clone();
    cfg.cache = body;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(OkResponse::ok())
}

/// The subset of filtering settings editable from the Settings page (the lists
/// and custom rules have their own endpoints).
#[derive(Deserialize, ToSchema)]
pub struct FilteringSettings {
    pub enabled: bool,
    pub blocking_mode: BlockingMode,
    #[schema(value_type = String)]
    pub custom_block_ipv4: std::net::Ipv4Addr,
    #[schema(value_type = String)]
    pub custom_block_ipv6: std::net::Ipv6Addr,
    pub blocked_ttl_secs: u32,
}

#[utoipa::path(
    put,
    path = "/api/config/filtering",
    tag = "config",
    request_body = FilteringSettings,
    responses((status = 200, body = OkResponse), (status = 400, body = ErrorResponse))
)]
pub async fn put_filtering(
    State(state): State<AppState>,
    Json(body): Json<FilteringSettings>,
) -> ApiResult<Json<OkResponse>> {
    let mut cfg = state.config.read().await.clone();
    cfg.filtering.enabled = body.enabled;
    cfg.filtering.blocking_mode = body.blocking_mode;
    cfg.filtering.custom_block_ipv4 = body.custom_block_ipv4;
    cfg.filtering.custom_block_ipv6 = body.custom_block_ipv6;
    cfg.filtering.blocked_ttl_secs = body.blocked_ttl_secs;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(OkResponse::ok())
}

/// Response for server-config updates: bind changes only take effect on restart.
#[derive(Serialize, ToSchema)]
pub struct ServerUpdateResponse {
    pub ok: bool,
    pub restart_required: bool,
}

#[utoipa::path(
    put,
    path = "/api/config/server",
    tag = "config",
    request_body = ServerConfig,
    responses((status = 200, body = ServerUpdateResponse), (status = 400, body = ErrorResponse))
)]
pub async fn put_server(
    State(state): State<AppState>,
    Json(body): Json<ServerConfig>,
) -> ApiResult<Json<ServerUpdateResponse>> {
    let mut cfg = state.config.read().await.clone();
    cfg.server = body;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    // Note: dns_bind / http_bind changes take effect on restart.
    Ok(Json(ServerUpdateResponse {
        ok: true,
        restart_required: true,
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/querylog",
    tag = "config",
    request_body = QueryLogConfig,
    responses((status = 200, body = OkResponse), (status = 400, body = ErrorResponse))
)]
pub async fn put_querylog(
    State(state): State<AppState>,
    Json(body): Json<QueryLogConfig>,
) -> ApiResult<Json<OkResponse>> {
    let mut cfg = state.config.read().await.clone();
    cfg.query_log = body;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(OkResponse::ok())
}

#[utoipa::path(
    put,
    path = "/api/config/stats",
    tag = "config",
    request_body = StatsConfig,
    responses((status = 200, body = OkResponse), (status = 400, body = ErrorResponse))
)]
pub async fn put_stats_cfg(
    State(state): State<AppState>,
    Json(body): Json<StatsConfig>,
) -> ApiResult<Json<OkResponse>> {
    let mut cfg = state.config.read().await.clone();
    cfg.stats = body;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(OkResponse::ok())
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

/// The filtering overview: lists, custom rules, and current mode.
#[derive(Serialize, ToSchema)]
pub struct FiltersResponse {
    pub lists: Vec<FilterListConfig>,
    pub custom_rules: String,
    pub enabled: bool,
    pub blocking_mode: BlockingMode,
}

#[utoipa::path(
    get,
    path = "/api/filters",
    tag = "filters",
    responses((status = 200, body = FiltersResponse), (status = 401, body = ErrorResponse))
)]
pub async fn get_filters(State(state): State<AppState>) -> Json<FiltersResponse> {
    let cfg = state.config.read().await;
    Json(FiltersResponse {
        lists: cfg.filtering.lists.clone(),
        custom_rules: cfg.filtering.custom_rules.clone(),
        enabled: cfg.filtering.enabled,
        blocking_mode: cfg.filtering.blocking_mode,
    })
}

#[derive(Deserialize, ToSchema)]
pub struct CustomRules {
    pub rules: String,
}

#[utoipa::path(
    put,
    path = "/api/filters/custom",
    tag = "filters",
    request_body = CustomRules,
    responses((status = 200, body = OkResponse), (status = 400, body = ErrorResponse))
)]
pub async fn put_custom_rules(
    State(state): State<AppState>,
    Json(body): Json<CustomRules>,
) -> ApiResult<Json<OkResponse>> {
    let mut cfg = state.config.read().await.clone();
    cfg.filtering.custom_rules = body.rules;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(OkResponse::ok())
}

#[derive(Deserialize, ToSchema)]
pub struct AddRule {
    /// A single rule line to append to the custom rules, e.g. `@@||example.com^`
    /// or `||ads.example.com^`. Used by the query-log "allow/block" actions.
    pub rule: String,
}

/// Result of appending a single custom rule.
#[derive(Serialize, ToSchema)]
pub struct AddRuleResponse {
    pub ok: bool,
    /// The (trimmed) rule that was processed.
    pub rule: String,
    /// `false` when the rule already existed (the append was a no-op).
    pub added: bool,
}

#[utoipa::path(
    post,
    path = "/api/filters/rule",
    tag = "filters",
    request_body = AddRule,
    responses((status = 200, body = AddRuleResponse), (status = 400, body = ErrorResponse))
)]
pub async fn add_custom_rule(
    State(state): State<AppState>,
    Json(body): Json<AddRule>,
) -> ApiResult<Json<AddRuleResponse>> {
    let rule = body.rule.trim().to_string();
    if rule.is_empty() {
        return Err(ApiError::BadRequest("empty rule".into()));
    }
    let mut cfg = state.config.read().await.clone();
    // Idempotent: don't append a rule that's already present as a line.
    let already = cfg.filtering.custom_rules.lines().any(|l| l.trim() == rule);
    if !already {
        if !cfg.filtering.custom_rules.is_empty() && !cfg.filtering.custom_rules.ends_with('\n') {
            cfg.filtering.custom_rules.push('\n');
        }
        cfg.filtering.custom_rules.push_str(&rule);
        cfg.filtering.custom_rules.push('\n');
        apply_config(&state, cfg)
            .await
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    Ok(Json(AddRuleResponse {
        ok: true,
        rule,
        added: !already,
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct NewList {
    pub name: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional inline content (when no URL is given).
    #[serde(default)]
    pub content: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Result of creating a filter list.
#[derive(Serialize, ToSchema)]
pub struct AddListResponse {
    pub ok: bool,
    /// The id assigned to the new list.
    pub id: u32,
}

/// Fetch a remote filter list's text.
async fn fetch_list(url: &str) -> Result<String, ApiError> {
    let client = reqwest::Client::builder()
        .user_agent("bulwark")
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(internal)?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| ApiError::BadRequest(format!("fetch failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(ApiError::BadRequest(format!(
            "fetch status {}",
            resp.status()
        )));
    }
    resp.text()
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))
}

#[utoipa::path(
    post,
    path = "/api/filters/lists",
    tag = "filters",
    request_body = NewList,
    responses((status = 200, body = AddListResponse), (status = 400, body = ErrorResponse))
)]
pub async fn add_list(
    State(state): State<AppState>,
    Json(body): Json<NewList>,
) -> ApiResult<Json<AddListResponse>> {
    let id = state.config.read().await.next_list_id();

    // Obtain the list content (remote or inline).
    let text = if let Some(url) = &body.url {
        fetch_list(url).await?
    } else {
        body.content.clone().unwrap_or_default()
    };
    write_list_text(&state.paths, id, &text).map_err(internal)?;

    let mut cfg = state.config.read().await.clone();
    cfg.filtering.lists.push(FilterListConfig {
        id,
        name: body.name,
        url: body.url,
        enabled: body.enabled,
        rule_count: 0,
        last_updated: Some(now_ms()),
    });
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(Json(AddListResponse { ok: true, id }))
}

#[derive(Deserialize, ToSchema)]
pub struct ListUpdate {
    pub name: Option<String>,
    pub url: Option<String>,
    pub enabled: Option<bool>,
}

#[utoipa::path(
    put,
    path = "/api/filters/lists/{id}",
    tag = "filters",
    params(("id" = u32, Path, description = "Filter list id")),
    request_body = ListUpdate,
    responses((status = 200, body = OkResponse), (status = 404, body = ErrorResponse))
)]
pub async fn update_list(
    State(state): State<AppState>,
    Path(id): Path<u32>,
    Json(body): Json<ListUpdate>,
) -> ApiResult<Json<OkResponse>> {
    let mut cfg = state.config.read().await.clone();
    let list = cfg
        .filtering
        .lists
        .iter_mut()
        .find(|l| l.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("list {id}")))?;
    if let Some(n) = body.name {
        list.name = n;
    }
    if let Some(u) = body.url {
        list.url = Some(u);
    }
    if let Some(e) = body.enabled {
        list.enabled = e;
    }
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(OkResponse::ok())
}

#[utoipa::path(
    delete,
    path = "/api/filters/lists/{id}",
    tag = "filters",
    params(("id" = u32, Path, description = "Filter list id")),
    responses((status = 200, body = OkResponse), (status = 404, body = ErrorResponse))
)]
pub async fn delete_list(
    State(state): State<AppState>,
    Path(id): Path<u32>,
) -> ApiResult<Json<OkResponse>> {
    let mut cfg = state.config.read().await.clone();
    let before = cfg.filtering.lists.len();
    cfg.filtering.lists.retain(|l| l.id != id);
    if cfg.filtering.lists.len() == before {
        return Err(ApiError::NotFound(format!("list {id}")));
    }
    let _ = std::fs::remove_file(state.paths.list_file(id));
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(OkResponse::ok())
}

#[utoipa::path(
    post,
    path = "/api/filters/lists/{id}/refresh",
    tag = "filters",
    params(("id" = u32, Path, description = "Filter list id")),
    responses((status = 200, body = OkResponse), (status = 400, body = ErrorResponse), (status = 404, body = ErrorResponse))
)]
pub async fn refresh_list(
    State(state): State<AppState>,
    Path(id): Path<u32>,
) -> ApiResult<Json<OkResponse>> {
    let url = {
        let cfg = state.config.read().await;
        let list = cfg
            .filtering
            .lists
            .iter()
            .find(|l| l.id == id)
            .ok_or_else(|| ApiError::NotFound(format!("list {id}")))?;
        list.url.clone()
    };
    let Some(url) = url else {
        return Err(ApiError::BadRequest("list has no URL to refresh".into()));
    };
    let text = fetch_list(&url).await?;
    write_list_text(&state.paths, id, &text).map_err(internal)?;

    let mut cfg = state.config.read().await.clone();
    if let Some(list) = cfg.filtering.lists.iter_mut().find(|l| l.id == id) {
        list.last_updated = Some(now_ms());
    }
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(OkResponse::ok())
}

#[derive(Deserialize, ToSchema)]
pub struct CheckRequest {
    pub domain: String,
    #[serde(default)]
    pub qtype: Option<String>,
}

/// The filtering verdict for a domain probe.
#[derive(Serialize, ToSchema)]
pub struct CheckResponse {
    /// One of `allow`, `block`, or `rewrite`.
    pub action: String,
    /// The matching rule text, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// The filter list responsible (absent for allow verdicts).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_id: Option<u32>,
    /// Friendly name of the responsible list (`Custom rules` for `list_id` 0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_name: Option<String>,
}

/// Build the `list_id -> friendly name` map used to attribute a match to its
/// source list. A block (or rewrite) is one winning rule from one list; id 0 is
/// the user's own custom rules.
fn list_names(cfg: &Config) -> std::collections::HashMap<u32, String> {
    let mut m: std::collections::HashMap<u32, String> = cfg
        .filtering
        .lists
        .iter()
        .map(|l| (l.id, l.name.clone()))
        .collect();
    m.insert(0, "Custom rules".to_string());
    m
}

#[utoipa::path(
    post,
    path = "/api/filters/check",
    tag = "filters",
    request_body = CheckRequest,
    responses((status = 200, body = CheckResponse), (status = 401, body = ErrorResponse))
)]
pub async fn check_domain(
    State(state): State<AppState>,
    Json(body): Json<CheckRequest>,
) -> Json<CheckResponse> {
    let filter = state.engine.filter_snapshot();
    let domain = body.domain.trim_end_matches('.').to_ascii_lowercase();
    let qtype = body
        .qtype
        .unwrap_or_else(|| "A".into())
        .to_ascii_uppercase();
    let ci = ClientInfo::default();
    let verdict = filter.check(&domain, &qtype, &ci);
    let names = list_names(&*state.config.read().await);
    let attribute = |info: bulwark_filter::MatchInfo, action: &str| CheckResponse {
        action: action.into(),
        rule: Some(info.rule),
        list_name: names.get(&info.list_id).cloned(),
        list_id: Some(info.list_id),
    };
    let resp = match verdict {
        Verdict::Allow { rule } => CheckResponse {
            action: "allow".into(),
            rule: rule.map(|r| r.rule),
            list_id: None,
            list_name: None,
        },
        Verdict::Block(info) => attribute(info, "block"),
        Verdict::Rewrite { info, .. } => attribute(info, "rewrite"),
    };
    Json(resp)
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/clients",
    tag = "clients",
    responses((status = 200, body = Vec<ClientConfig>), (status = 401, body = ErrorResponse))
)]
pub async fn get_clients(State(state): State<AppState>) -> Json<Vec<ClientConfig>> {
    let cfg = state.config.read().await;
    Json(cfg.clients.clone())
}

#[utoipa::path(
    put,
    path = "/api/clients",
    tag = "clients",
    request_body = Vec<ClientConfig>,
    responses((status = 200, body = OkResponse), (status = 400, body = ErrorResponse))
)]
pub async fn put_clients(
    State(state): State<AppState>,
    Json(clients): Json<Vec<ClientConfig>>,
) -> ApiResult<Json<OkResponse>> {
    let mut cfg = state.config.read().await.clone();
    cfg.clients = clients;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(OkResponse::ok())
}

// ---------------------------------------------------------------------------
// Stats, query log, upstreams
// ---------------------------------------------------------------------------

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TopQuery {
    /// How many entries to include in each top-N list.
    #[serde(default = "default_top")]
    pub top: usize,
}

fn default_top() -> usize {
    15
}

#[utoipa::path(
    get,
    path = "/api/stats",
    tag = "stats",
    params(TopQuery),
    responses((status = 200, body = StatsResponse), (status = 401, body = ErrorResponse))
)]
pub async fn get_stats(
    State(state): State<AppState>,
    Query(q): Query<TopQuery>,
) -> Json<StatsResponse> {
    let clients = state.engine.clients();
    let summary = state.engine.stats().snapshot(q.top, &clients);
    let cache = state.engine.cache();
    Json(StatsResponse::new(
        summary,
        cache.hit_count(),
        cache.miss_count(),
        cache.len(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/stats/reset",
    tag = "stats",
    responses((status = 200, body = OkResponse), (status = 401, body = ErrorResponse))
)]
pub async fn reset_stats(State(state): State<AppState>) -> Json<OkResponse> {
    state.engine.stats().reset();
    OkResponse::ok()
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LogQuery {
    /// Case-insensitive substring match on the question name.
    #[serde(default)]
    pub search: Option<String>,
    /// Match a specific client (IP or name).
    #[serde(default)]
    pub client: Option<String>,
    /// Only return blocked entries.
    #[serde(default)]
    pub blocked_only: bool,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

#[utoipa::path(
    get,
    path = "/api/querylog",
    tag = "querylog",
    params(LogQuery),
    responses((status = 200, body = QueryLogResponse), (status = 401, body = ErrorResponse))
)]
pub async fn get_querylog(
    State(state): State<AppState>,
    Query(q): Query<LogQuery>,
) -> Json<QueryLogResponse> {
    let filter = bulwark_engine::querylog::LogFilter {
        search: q.search,
        client: q.client,
        blocked_only: q.blocked_only,
    };
    let clients = state.engine.clients();
    let page = state
        .engine
        .log()
        .query(&filter, q.offset, q.limit.min(1000), &clients);

    // Resolve list ids to friendly names so the UI can show which list (and
    // which rule) was responsible.
    let names = list_names(&*state.config.read().await);
    let entries: Vec<LogEntryView> = page
        .entries
        .into_iter()
        .map(|entry| {
            let list_name = entry.list_id().and_then(|id| names.get(&id).cloned());
            // Resolve the client's friendly name from its IP against the current
            // config, so renames/removals show retroactively.
            let client_name = clients.name_for_str(&entry.client_ip).map(str::to_string);
            LogEntryView::new(entry, list_name, client_name)
        })
        .collect();
    Json(QueryLogResponse {
        entries,
        total: page.total,
    })
}

#[utoipa::path(
    delete,
    path = "/api/querylog",
    tag = "querylog",
    responses((status = 200, body = OkResponse), (status = 401, body = ErrorResponse))
)]
pub async fn clear_querylog(State(state): State<AppState>) -> Json<OkResponse> {
    state.engine.log().clear();
    OkResponse::ok()
}

#[utoipa::path(
    get,
    path = "/api/upstreams",
    tag = "upstreams",
    responses((status = 200, body = Vec<UpstreamStatDto>), (status = 401, body = ErrorResponse))
)]
pub async fn get_upstreams(State(state): State<AppState>) -> Json<Vec<UpstreamStatDto>> {
    Json(
        state
            .engine
            .pool()
            .stats()
            .into_iter()
            .map(Into::into)
            .collect(),
    )
}

#[derive(Deserialize, ToSchema)]
pub struct TestUpstream {
    pub spec: String,
}

/// The result of a one-off upstream connectivity test.
#[derive(Serialize, ToSchema)]
pub struct TestResult {
    pub ok: bool,
    pub rtt_ms: Option<f64>,
    pub error: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/upstreams/test",
    tag = "upstreams",
    request_body = TestUpstream,
    responses((status = 200, body = TestResult), (status = 400, body = ErrorResponse))
)]
pub async fn test_upstream(
    State(state): State<AppState>,
    Json(body): Json<TestUpstream>,
) -> ApiResult<Json<TestResult>> {
    // Validate spec first for a clear error.
    UpstreamSpec::parse(&body.spec).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let bootstrap = state.engine.pool().bootstrap().clone();
    match test_spec(&body.spec, bootstrap, Duration::from_secs(8)).await {
        Ok(rtt) => Ok(Json(TestResult {
            ok: true,
            rtt_ms: Some(rtt.as_secs_f64() * 1000.0),
            error: None,
        })),
        Err(e) => Ok(Json(TestResult {
            ok: false,
            rtt_ms: None,
            error: Some(e.to_string()),
        })),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
