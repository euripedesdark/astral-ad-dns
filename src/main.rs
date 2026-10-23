mod auth;
mod config;
mod audit;
mod system;
mod api;

use std::sync::Arc;
use std::net::SocketAddr;
use std::path::Path;
use axum::{
    http::{header, Method, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    Router,
};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::AppConfig;
use crate::api::create_api_router;

async fn spa_fallback_handler(uri: Uri, dist_path: String) -> Response {
    let raw_path = uri.path();
    let mut path = raw_path.trim_start_matches('/');
    if path.starts_with("ad/") {
        path = &path[3..];
    } else if path == "ad" {
        path = "";
    } else if path.starts_with("dns/") {
        path = &path[4..];
    } else if path == "dns" {
        path = "";
    }

    let target = Path::new(&dist_path).join(path);
    if !path.is_empty() && target.is_file() {
        if let Ok(content) = tokio::fs::read(&target).await {
            let mime = mime_guess::from_path(&target).first_or_octet_stream();
            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime.as_ref())],
                content,
            ).into_response();
        }
    }

    let index_file = Path::new(&dist_path).join("index.html");
    if let Ok(content) = tokio::fs::read_to_string(&index_file).await {
        Html(content).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Html("<h1>Astral AD & DNS Console</h1><p>Frontend assets are compiling or not generated yet. API is available at <a href='/api/status'>/api/status</a>.</p>"),
        ).into_response()
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "astral_ad_dns=debug,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Arc::new(AppConfig::from_env());
    info!("Starting Astral AD & Hybrid DNS Management Server...");
    info!("Target Listen Address: {}", config.bind_addr);
    info!("Web Dist Directory: {}", config.web_dist_path);

    let report = system::auto_reconcile_firewall_ports(config.sudo_password.as_deref(), false);
    info!("Firewall Auto-Reconcile: {} portas inspecionadas, {} ativas, {} corrigidas, {} falhas", report.total_ports, report.open_count, report.corrected_count, report.failed_count);

    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::PUT, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT]);

    let dist_for_fallback = config.web_dist_path.clone();
    let api_router = create_api_router(config.clone());

    let app = Router::new()
        .merge(api_router.clone())
        .nest("/ad", api_router.clone())
        .nest("/dns", api_router)
        .fallback(move |uri| spa_fallback_handler(uri, dist_for_fallback.clone()))
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = config.bind_addr.parse().expect("Invalid bind address");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind to {}: {}", addr, e));

    info!("Astral AD & DNS Server is running on http://{}", addr);

    axum::serve(listener, app)
        .await
        .expect("Server failed");
}
