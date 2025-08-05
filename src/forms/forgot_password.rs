use crate::auth::User;
use crate::utils::{BASE36_RADIX, Base36};
use askama::Template;
use chrono::Utc;
use cot::common_types::Email;
use cot::db::{Model, query};
use cot::form::{Form, FormContext, FormErrorTarget, FormResult};
use cot::request::Request;
use cot::request::extractors::{RequestDb, StaticFiles};
use cot::response::{Response, ResponseExt};
use cot::router::Urls;
use cot::{Body, Method, StatusCode};
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
        let ts_b36 = Base36::encode(ts.to_string().as_bytes());
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
                    let reset_token = ResetToken.make_token(&user, b"random-secret");
                    // TODO: fix once email support is merged.
                    println!(
                        r#"
                    click link to reset password:

                    http://127.0.0.1:8000/reset/{reset_token}/

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
