use crate::auth::authenticate;
use askama::Template;
use cot::auth::Auth;
use cot::common_types::Password;
use cot::form::{
    Form, FormContext, FormErrorTarget, FormField, FormFieldValidationError, FormResult,
};
use cot::request::Request;
use cot::request::extractors::StaticFiles;
use cot::response::{Response, ResponseExt};
use cot::router::Urls;
use cot::{Body, Method, StatusCode, reverse_redirect};

#[derive(Debug, Form, Clone)]
pub(crate) struct LoginForm {
    pub(crate) username: String,
    pub(crate) password: Password,
}

#[derive(Debug, Template)]
#[template(path = "login.html")]
pub(crate) struct LoginTemplate<'a> {
    urls: &'a Urls,
    form: <LoginForm as Form>::Context,
    static_files: StaticFiles,
}

pub(crate) async fn login(
    urls: Urls,
    auth: Auth,
    mut request: Request,
    static_files: StaticFiles,
) -> cot::Result<Response> {
    let login_form_context = if request.method() == Method::GET {
        LoginForm::build_context(&mut request).await?
    } else if request.method() == Method::POST {
        let login_form = LoginForm::from_request(&mut request).await?;

        match login_form {
            FormResult::Ok(login_form) => {
                if authenticate(&auth, &login_form).await? {
                    return Ok(reverse_redirect!(urls, "home")?);
                }
                let mut ctx = LoginForm::build_context(&mut request).await?;
                ctx.add_error(
                    FormErrorTarget::Form,
                    FormFieldValidationError::from_static("Invalid username or password"),
                );
                ctx
            }
            FormResult::ValidationError(context) => context,
        }
    } else {
        panic!("unexpected request method");
    };

    let template = LoginTemplate {
        urls: &urls,
        form: login_form_context,
        static_files,
    };

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::fixed(template.render()?))
        .unwrap();
    Ok(response)
}
