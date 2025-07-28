use crate::auth::User;
use askama::Template;
use cot::common_types::{Email, Password};
use cot::db::{Auto, LimitedString, Model};
use cot::form::{Form, FormContext, FormErrorTarget, FormFieldValidationError, FormResult};
use cot::request::Request;
use cot::request::extractors::{RequestDb, StaticFiles};
use cot::response::{Response, ResponseExt};
use cot::router::Urls;
use cot::{Body, Method, StatusCode};

#[derive(Debug, Form)]
pub(crate) struct SignupForm {
    fullname: String,
    email: Email,
    username: String,
    password1: Password,
    password2: Password,
}

#[derive(Debug, Template)]
#[template(path = "signup.html")]
pub(crate) struct SignupTemplate<'a> {
    urls: &'a Urls,
    static_files: StaticFiles,
    form: <SignupForm as Form>::Context,
}

impl SignupForm {
    fn validate_password(&self) -> Result<&Self, FormFieldValidationError> {
        if self.password1.as_str() != self.password2.as_str() {
            return Err(FormFieldValidationError::from_static(
                "passwords do not match.",
            ));
        }
        Ok(self)
    }
}

pub(crate) async fn signup(
    urls: Urls,
    mut request: Request,
    RequestDb(db): RequestDb,
    static_files: StaticFiles,
) -> cot::Result<Response> {
    let signup_context = if request.method() == Method::GET {
        SignupForm::build_context(&mut request).await?
    } else if request.method() == Method::POST {
        let signup_form = SignupForm::from_request(&mut request).await?;
        let val = match signup_form {
            FormResult::Ok(signup_form) => {
                let val = match signup_form.validate_password() {
                    Err(err) => {
                        let mut ctx = signup_form.to_context().await;
                        ctx.add_error(FormErrorTarget::Form, err);
                        ctx
                    }

                    Ok(form) => {
                        let username = LimitedString::new(form.username.clone())
                            .expect("username is too long");
                        let name =
                            LimitedString::new(form.fullname.clone()).expect("name is too long");

                        User::new(
                            Auto::auto(),
                            username,
                            &form.password1,
                            form.email.clone(),
                            name,
                        )
                        .save(&db)
                        .await?;
                        form.to_context().await
                    }
                };

                val
            }
            FormResult::ValidationError(context) => context,
        };
        val
    } else {
        panic!("unexpected request method")
    };
    let signup_template = SignupTemplate {
        urls: &urls,
        form: signup_context,
        static_files,
    };
    let rendered = signup_template.render()?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::fixed(rendered))
        .unwrap();
    Ok(response)
}
