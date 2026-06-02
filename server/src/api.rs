//! The HTTP REST API (Axum).

use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{middleware, Json, Router};
use bulwark_config::{ClientConfig, FilterListConfig};
use bulwark_filter::{ClientInfo, Verdict};
use bulwark_upstream::{test_spec, UpstreamSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::app::{apply_config, write_list_text, AppState};
use crate::auth::{hash_password, verify_password, SESSION_COOKIE};

/// API error type that renders as a JSON `{ "error": ... }` body.
pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    NotFound(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(e.to_string())
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

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

async fn status(State(state): State<AppState>, headers: HeaderMap) -> Json<Value> {
    let cfg = state.config.read().await;
    let authed = cookie_token(&headers)
        .map(|t| state.sessions.validate(&t))
        .unwrap_or(false);
    Json(json!({
        "setup_needed": cfg.auth.needs_setup(),
        "authed": authed,
        "version": env!("CARGO_PKG_VERSION"),
        "dns_bind": cfg.server.dns_bind,
    }))
}

fn session_cookie(token: &str) -> String {
    format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800")
}

async fn setup(
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
    Ok((headers, Json(json!({ "ok": true }))).into_response())
}

async fn login(
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
    Ok((headers, Json(json!({ "ok": true }))).into_response())
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
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
    (out, Json(json!({ "ok": true }))).into_response()
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Return the config with the password hash redacted.
async fn get_config(State(state): State<AppState>) -> Json<Value> {
    let mut cfg = state.config.read().await.clone();
    cfg.auth.password_hash = None;
    Json(serde_json::to_value(cfg).unwrap_or(Value::Null))
}

async fn put_upstreams(
    State(state): State<AppState>,
    Json(body): Json<bulwark_config::UpstreamsConfig>,
) -> ApiResult<Json<Value>> {
    let mut cfg = state.config.read().await.clone();
    cfg.upstreams = body;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

async fn put_cache(
    State(state): State<AppState>,
    Json(body): Json<bulwark_config::CacheConfig>,
) -> ApiResult<Json<Value>> {
    let mut cfg = state.config.read().await.clone();
    cfg.cache = body;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct FilteringSettings {
    enabled: bool,
    blocking_mode: bulwark_config::BlockingMode,
    custom_block_ipv4: std::net::Ipv4Addr,
    custom_block_ipv6: std::net::Ipv6Addr,
    blocked_ttl_secs: u32,
}

async fn put_filtering(
    State(state): State<AppState>,
    Json(body): Json<FilteringSettings>,
) -> ApiResult<Json<Value>> {
    let mut cfg = state.config.read().await.clone();
    cfg.filtering.enabled = body.enabled;
    cfg.filtering.blocking_mode = body.blocking_mode;
    cfg.filtering.custom_block_ipv4 = body.custom_block_ipv4;
    cfg.filtering.custom_block_ipv6 = body.custom_block_ipv6;
    cfg.filtering.blocked_ttl_secs = body.blocked_ttl_secs;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

async fn put_server(
    State(state): State<AppState>,
    Json(body): Json<bulwark_config::ServerConfig>,
) -> ApiResult<Json<Value>> {
    let mut cfg = state.config.read().await.clone();
    cfg.server = body;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    // Note: dns_bind / http_bind changes take effect on restart.
    Ok(Json(json!({ "ok": true, "restart_required": true })))
}

async fn put_querylog(
    State(state): State<AppState>,
    Json(body): Json<bulwark_config::QueryLogConfig>,
) -> ApiResult<Json<Value>> {
    let mut cfg = state.config.read().await.clone();
    cfg.query_log = body;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

async fn put_stats_cfg(
    State(state): State<AppState>,
    Json(body): Json<bulwark_config::StatsConfig>,
) -> ApiResult<Json<Value>> {
    let mut cfg = state.config.read().await.clone();
    cfg.stats = body;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

async fn get_filters(State(state): State<AppState>) -> Json<Value> {
    let cfg = state.config.read().await;
    Json(json!({
        "lists": cfg.filtering.lists,
        "custom_rules": cfg.filtering.custom_rules,
        "enabled": cfg.filtering.enabled,
        "blocking_mode": cfg.filtering.blocking_mode,
    }))
}

#[derive(Deserialize)]
struct CustomRules {
    rules: String,
}

async fn put_custom_rules(
    State(state): State<AppState>,
    Json(body): Json<CustomRules>,
) -> ApiResult<Json<Value>> {
    let mut cfg = state.config.read().await.clone();
    cfg.filtering.custom_rules = body.rules;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct NewList {
    name: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    /// Optional inline content (when no URL is given).
    #[serde(default)]
    content: Option<String>,
}

fn default_true() -> bool {
    true
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

async fn add_list(
    State(state): State<AppState>,
    Json(body): Json<NewList>,
) -> ApiResult<Json<Value>> {
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
    Ok(Json(json!({ "ok": true, "id": id })))
}

#[derive(Deserialize)]
struct ListUpdate {
    name: Option<String>,
    url: Option<String>,
    enabled: Option<bool>,
}

async fn update_list(
    State(state): State<AppState>,
    Path(id): Path<u32>,
    Json(body): Json<ListUpdate>,
) -> ApiResult<Json<Value>> {
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
    Ok(Json(json!({ "ok": true })))
}

async fn delete_list(State(state): State<AppState>, Path(id): Path<u32>) -> ApiResult<Json<Value>> {
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
    Ok(Json(json!({ "ok": true })))
}

async fn refresh_list(
    State(state): State<AppState>,
    Path(id): Path<u32>,
) -> ApiResult<Json<Value>> {
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
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct CheckRequest {
    domain: String,
    #[serde(default)]
    qtype: Option<String>,
}

async fn check_domain(
    State(state): State<AppState>,
    Json(body): Json<CheckRequest>,
) -> Json<Value> {
    let filter = state.engine.filter_snapshot();
    let domain = body.domain.trim_end_matches('.').to_ascii_lowercase();
    let qtype = body
        .qtype
        .unwrap_or_else(|| "A".into())
        .to_ascii_uppercase();
    let ci = ClientInfo::default();
    let verdict = filter.check(&domain, &qtype, &ci);
    let v = match verdict {
        Verdict::Allow { rule } => json!({
            "action": "allow",
            "rule": rule.map(|r| r.rule),
        }),
        Verdict::Block(info) => json!({
            "action": "block",
            "rule": info.rule,
            "list_id": info.list_id,
        }),
        Verdict::Rewrite { info, .. } => json!({
            "action": "rewrite",
            "rule": info.rule,
            "list_id": info.list_id,
        }),
    };
    Json(v)
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

async fn get_clients(State(state): State<AppState>) -> Json<Value> {
    let cfg = state.config.read().await;
    Json(serde_json::to_value(&cfg.clients).unwrap_or(Value::Null))
}

async fn put_clients(
    State(state): State<AppState>,
    Json(clients): Json<Vec<ClientConfig>>,
) -> ApiResult<Json<Value>> {
    let mut cfg = state.config.read().await.clone();
    cfg.clients = clients;
    apply_config(&state, cfg)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Stats, query log, upstreams
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TopQuery {
    #[serde(default = "default_top")]
    top: usize,
}

fn default_top() -> usize {
    15
}

async fn get_stats(State(state): State<AppState>, Query(q): Query<TopQuery>) -> Json<Value> {
    let summary = state.engine.stats().snapshot(q.top);
    let cache_hits = state.engine.cache().hit_count();
    let cache_misses = state.engine.cache().miss_count();
    let mut v = serde_json::to_value(summary).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut v {
        map.insert("cache_hits".into(), json!(cache_hits));
        map.insert("cache_misses".into(), json!(cache_misses));
        map.insert("cache_size".into(), json!(state.engine.cache().len()));
    }
    Json(v)
}

async fn reset_stats(State(state): State<AppState>) -> Json<Value> {
    state.engine.stats().reset();
    Json(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct LogQuery {
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    client: Option<String>,
    #[serde(default)]
    blocked_only: bool,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    100
}

async fn get_querylog(State(state): State<AppState>, Query(q): Query<LogQuery>) -> Json<Value> {
    let filter = bulwark_engine::querylog::LogFilter {
        search: q.search,
        client: q.client,
        blocked_only: q.blocked_only,
    };
    let page = state
        .engine
        .log()
        .query(&filter, q.offset, q.limit.min(1000));

    // Resolve list ids to friendly names so the UI can show which list (and
    // which rule) was responsible. A block is one winning rule from one list;
    // id 0 is the user's custom rules.
    let names: std::collections::HashMap<u32, String> = {
        let cfg = state.config.read().await;
        let mut m: std::collections::HashMap<u32, String> = cfg
            .filtering
            .lists
            .iter()
            .map(|l| (l.id, l.name.clone()))
            .collect();
        m.insert(0, "Custom rules".to_string());
        m
    };
    let entries: Vec<Value> = page
        .entries
        .iter()
        .map(|e| {
            let mut v = serde_json::to_value(e).unwrap_or(Value::Null);
            if let (Value::Object(map), Some(id)) = (&mut v, e.list_id) {
                if let Some(name) = names.get(&id) {
                    map.insert("list_name".into(), json!(name));
                }
            }
            v
        })
        .collect();
    Json(json!({ "entries": entries, "total": page.total }))
}

async fn clear_querylog(State(state): State<AppState>) -> Json<Value> {
    state.engine.log().clear();
    Json(json!({ "ok": true }))
}

async fn get_upstreams(State(state): State<AppState>) -> Json<Value> {
    let stats = state.engine.pool().stats();
    Json(serde_json::to_value(stats).unwrap_or(Value::Null))
}

#[derive(Deserialize)]
struct TestUpstream {
    spec: String,
}

#[derive(Serialize)]
struct TestResult {
    ok: bool,
    rtt_ms: Option<f64>,
    error: Option<String>,
}

async fn test_upstream(
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
