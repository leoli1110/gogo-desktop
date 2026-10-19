//! The web interface: static files built from `web/` and embedded in the binary.

use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::Embed)]
#[folder = "../../web/dist"]
struct Assets;

const NOT_BUILT: &str = "<!doctype html><meta charset=utf-8><title>Gogo Desktop</title>\
<p>The web interface wasn't built into this program. Run <code>npm ci &amp;&amp; npm run build</code> in <code>web/</code>, then rebuild.</p>";

/// Serves a static file, or `index.html` for app routes.
pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") {
        return (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({ "error": "not found", "code": "not_found" })))
            .into_response();
    }
    if !path.is_empty() && !path.contains("..") {
        if let Some(file) = Assets::get(path) {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            let mut resp = Response::new(Body::from(file.data.into_owned()));
            resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_str(mime.as_ref()).unwrap());
            let cache = if path.starts_with("assets/") { "public, max-age=31536000, immutable" } else { "no-cache" };
            resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
            return resp;
        }
        // Unknown file with an extension: real 404, not the app.
        if path.rsplit('/').next().map(|n| n.contains('.')).unwrap_or(false) {
            return StatusCode::NOT_FOUND.into_response();
        }
    }
    let html = Assets::get("index.html").map(|f| f.data.into_owned()).unwrap_or_else(|| NOT_BUILT.as_bytes().to_vec());
    let mut resp = Response::new(Body::from(html));
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}
