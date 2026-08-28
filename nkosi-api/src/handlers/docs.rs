use actix_web::{HttpRequest, HttpResponse};
use std::path::PathBuf;

pub async fn openapi_docs(_req: HttpRequest) -> HttpResponse {
    serve_yaml("openapi.yaml", "application/vnd.oai.openapi")
}

pub async fn grpc_openapi_docs(_req: HttpRequest) -> HttpResponse {
    serve_yaml("grpc-openapi.yaml", "application/vnd.oai.openapi")
}

fn serve_yaml(filename: &str, content_type: &str) -> HttpResponse {
    let doc_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("doc")
        .join(filename);

    match std::fs::read(&doc_dir) {
        Ok(body) => HttpResponse::Ok()
            .content_type(format!("{};version=3.0.3", content_type))
            .body(body),
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to load {}: {}", filename, e)),
    }
}
