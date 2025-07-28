use askama::Template;
use cot::request::Request;
use cot::request::extractors::StaticFiles;
use cot::response::{Response, ResponseExt};
use cot::router::Urls;
use cot::{Body, StatusCode};

#[derive(Debug, Template)]
#[template(path = "forgot_password.html")]
pub(crate) struct ForgotPasswordTemplate<'a> {
    urls: &'a Urls,
    static_files: StaticFiles,
}

pub(crate) async fn forgot_password(
    urls: Urls,
    _request: Request,
    static_files: StaticFiles,
) -> cot::Result<Response> {
    let forgot_password_template = ForgotPasswordTemplate {
        urls: &urls,
        static_files,
    };
    let rendered = forgot_password_template.render()?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::fixed(rendered))
        .unwrap();
    Ok(response)
}
