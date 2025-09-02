use crate::auth::User;
use crate::utils::{BASE36_RADIX, Base36};
use askama::Template;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use cot::common_types::{Email, Password};
use cot::db::{Model, query};
use cot::form::{Form, FormContext, FormErrorTarget, FormFieldValidationError, FormResult};
use cot::request::extractors::{RequestDb, StaticFiles};
use cot::request::{Request, RequestExt};
use cot::response::{Response, ResponseExt};
use cot::router::Urls;
use cot::{Body, Method, StatusCode, reverse_redirect};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSHa256 = Hmac<Sha256>;

pub(crate) struct ResetToken;

impl ResetToken {
    pub fn make_token(&self, user: &User, secret: &[u8]) -> String {
        let ts = Utc::now().timestamp();
        self.make_token_with_timestamp(user, secret, ts)
    }

    pub fn make_token_with_timestamp(&self, user: &User, secret: &[u8], ts: i64) -> String {
        // the current timestamp is always going to be positive, so this cast is safe.
        let ts_b36 = Base36::encode(ts as u64);
        let data = format!("{}{:?}{}", user.id(), &user.password_hash(), ts);

        let mut mac = HmacSHa256::new_from_slice(secret).unwrap();
        mac.update(data.as_bytes());
        let full = mac.finalize().into_bytes();
        let short = hex::encode(&full)[..20].to_string();
        format!("{ts_b36}-{short}")
    }

    pub fn check_token(&self, user: &User, token: &str, secret: &[u8], timeout_secs: i64) -> bool {
        let (ts_b36, sig) = match token.split_once("-") {
            Some((x, y)) => (x, y),
            _ => return false,
        };

        // decode the b36 timestamp
        let ts = i64::from_str_radix(ts_b36, BASE36_RADIX).unwrap();

        let age = Utc::now().timestamp() - ts;
        if age < 0 || age > timeout_secs {
            return false;
        }

        let expected = self.make_token_with_timestamp(user, secret, ts);
        expected == format!("{ts_b36}-{sig}")
    }
}

fn decode_b64url_to_i64_from_decimal(
    b64: &str,
) -> Result<i64, Box<dyn std::error::Error + Sync + Send>> {
    let bytes = URL_SAFE_NO_PAD.decode(b64)?;
    let s = String::from_utf8(bytes)?;
    let id = s.parse::<i64>()?;

    Ok(id)
}

#[derive(Debug, Form)]
pub(crate) struct ForgotPasswordForm {
    email: Email,
}

#[derive(Debug, Template)]
#[template(path = "forgot_password.html")]
pub(crate) struct ForgotPasswordTemplate<'a> {
    urls: &'a Urls,
    static_files: StaticFiles,
    form: <ForgotPasswordForm as Form>::Context,
    email_sent: bool,
}

pub(crate) async fn forgot_password(
    urls: Urls,
    mut request: Request,
    RequestDb(db): RequestDb,
    static_files: StaticFiles,
) -> cot::Result<Response> {
    let mut email_sent: bool = false;

    let forgot_pass_context = if request.method() == Method::GET {
        ForgotPasswordForm::build_context(&mut request).await?
    } else if request.method() == Method::POST {
        let fg_form = ForgotPasswordForm::from_request(&mut request).await?;
        let forgot_pass_context = match fg_form {
            FormResult::Ok(fg_form) => {
                let user = query!(User, $email == fg_form.email.clone())
                    .get(&db)
                    .await?;
                if let Some(user) = user {
                    let uid_encoded = URL_SAFE_NO_PAD.encode(user.id().to_string());
                    // TODO: Need to use secret from config for this
                    let reset_token = ResetToken.make_token(&user, b"random-secret");
                    // TODO: fix once email support is merged.
                    //TODO: URI should come from cot.
                    println!(
                        r#"
                    click link to reset password:

                    http://127.0.0.1:8000/reset/{reset_token}/{uid_encoded}

                    "#
                    );
                    email_sent = true;
                }

                fg_form.to_context().await
            }

            FormResult::ValidationError(context) => context,
        };
        forgot_pass_context
    } else {
        panic!("unexpected request method")
    };

    let forgot_password_template = ForgotPasswordTemplate {
        urls: &urls,
        static_files,
        form: forgot_pass_context,
        email_sent,
    };
    let rendered = forgot_password_template.render()?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::fixed(rendered))
        .unwrap();
    Ok(response)
}

#[derive(Debug, Form)]
pub(crate) struct ResetPasswordConfirmForm {
    password1: Password,
    password2: Password,
}

impl ResetPasswordConfirmForm {
    fn validate_password(self) -> Result<ValidatedResetForm, FormFieldValidationError> {
        if self.password1.as_str() != self.password2.as_str() {
            return Err(FormFieldValidationError::from_static(
                "passwords do not match.",
            ));
        }
        Ok(ValidatedResetForm::new(self.password1))
    }
}

#[derive(Debug)]
struct ValidatedResetForm {
    password: Password,
}

impl ValidatedResetForm {
    fn new(password: Password) -> Self {
        Self { password }
    }
}

#[derive(Debug, Template)]
#[template(path = "forgot_password_confirm.html")]
pub(crate) struct ResetPasswordConfirmTemplate<'a> {
    urls: &'a Urls,
    static_files: StaticFiles,
    form: <ResetPasswordConfirmForm as Form>::Context,
}

pub(crate) async fn reset_password_confirm(
    urls: Urls,
    mut request: Request,
    RequestDb(db): RequestDb,
    static_files: StaticFiles,
) -> cot::Result<Response> {
    let reset_pass_context = if request.method() == Method::GET {
        ResetPasswordConfirmForm::build_context(&mut request).await?
    } else if request.method() == Method::POST {
        let params = request.path_params().clone();

        let form = ResetPasswordConfirmForm::from_request(&mut request).await?;
        let form_context = match form {
            FormResult::Ok(form) => {
                let mut ctx = form.to_context().await;

                if let (Some(token), Some(uid)) = (params.get("token"), params.get("uid")) {
                    let user_id = decode_b64url_to_i64_from_decimal(uid);

                    match user_id {
                        Ok(user_id) => {
                            let user = User::get_by_id(&db, user_id).await?;
                            if let Some(mut user) = user {
                                let validated_form = form.validate_password();
                                match validated_form {
                                    Ok(validated_form) => {
                                        if ResetToken.check_token(
                                            &user,
                                            token,
                                            b"random-secret",
                                            3600,
                                        ) {
                                            user.set_password(&validated_form.password).await;
                                            user.save(&db).await?;
                                            return Ok(reverse_redirect!(urls, "login")?);
                                        } else {
                                            ctx.add_error(
                                                FormErrorTarget::Form,
                                                FormFieldValidationError::from_static(
                                                    "Invalid token or uid",
                                                ),
                                            );
                                        }
                                    }
                                    Err(err) => {
                                        ctx.add_error(FormErrorTarget::Form, err);
                                    }
                                }
                            } else {
                                ctx.add_error(
                                    FormErrorTarget::Form,
                                    FormFieldValidationError::from_static("could not find user"),
                                );
                            }
                        }
                        Err(err) => {
                            ctx.add_error(
                                FormErrorTarget::Form,
                                FormFieldValidationError::from_string(err.to_string()),
                            );
                        }
                    }

                    ctx
                } else {
                    let mut ctx = form.to_context().await;
                    ctx.add_error(
                        FormErrorTarget::Form,
                        FormFieldValidationError::from_static("token or uid cannot be empty"),
                    );
                    ctx
                }
            }
            FormResult::ValidationError(context) => context,
        };
        form_context
    } else {
        panic!("unexpected request method")
    };

    let reset_template = ResetPasswordConfirmTemplate {
        urls: &urls,
        static_files: static_files,
        form: reset_pass_context,
    };
    let rendered = reset_template.render()?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::fixed(rendered))
        .unwrap();
    Ok(response)
}
