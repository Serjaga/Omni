use axum::{body::Body, http::StatusCode, response::Response};

pub async fn start(_state: crate::SharedState) {
    // Инициализация подсистемы или запуск фоновой задачи.
}

pub async fn dispatch(ctx: crate::api::ApiCtx) -> Option<Response<Body>> {
    if ctx.endpoint == "example-module/health" && ctx.method == axum::http::Method::GET {
        return Some(Response::builder().status(StatusCode::OK)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Body::from("example module is active"))
            .unwrap_or_else(|_| Response::new(Body::empty())));
    }
    None
}
