mod auth;
mod forms;
mod migrations;

use std::any::Any;

use std::sync::Arc;

use askama::Template;
use cot::admin::{AdminModel, AdminModelManager};
use cot::auth::AuthBackend;
use cot::auth::db::DatabaseUserApp;
use cot::cli::CliMetadata;
use cot::db::migrations::SyncDynMigration;
use cot::db::{DatabaseBackend, Model};
use cot::form::{Form, FormContext, FormField};
use cot::middleware::{AuthMiddleware, LiveReloadMiddleware, SessionMiddleware};
use cot::project::{
    AuthBackendContext, MiddlewareContext, RootHandler, RootHandlerBuilder, WithConfig,
};

use crate::forms::forgot_password::forgot_password;
use auth::UserBackend;
use cot::request::Request;
use cot::response::{Response, ResponseExt};
use cot::router::{Route, Router};
use cot::static_files::{StaticFile, StaticFilesMiddleware};
use cot::{App, AppBuilder, Body, Project, ProjectContext, StatusCode, static_files};
use forms::login::login;
use forms::signup::signup;

const MAX_USERNAME_LENGTH: u32 = 255;
#[derive(Debug, Template)]
#[template(path = "index.html")]
struct IndexTemplate {}

#[derive(Debug, Template)]
#[template(path = "home.html")]
struct HomeTemplate {}

async fn index(request: Request) -> cot::Result<Response> {
    let index_template = IndexTemplate {};
    let rendered = index_template.render()?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::fixed(rendered))
        .unwrap();
    Ok(response)
}

async fn home(request: Request) -> cot::Result<Response> {
    let home_template = HomeTemplate {};
    let rendered = home_template.render()?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::fixed(rendered))
        .unwrap();
    Ok(response)
}

struct AuthApp;

impl App for AuthApp {
    fn name(&self) -> &'static str {
        env!("CARGO_CRATE_NAME")
    }

    fn migrations(&self) -> Vec<Box<SyncDynMigration>> {
        cot::db::migrations::wrap_migrations(migrations::MIGRATIONS)
    }

    fn router(&self) -> Router {
        Router::with_urls([
            Route::with_handler_and_name("/", index, "index"),
            Route::with_handler_and_name("/login", login, "login"),
            Route::with_handler_and_name("/home", home, "home"),
            Route::with_handler_and_name("/signup", signup, "signup"),
            Route::with_handler_and_name("/forgot-password", forgot_password, "forgot_password"),
        ])
    }

    fn static_files(&self) -> Vec<StaticFile> {
        static_files!("css/main.css", "css/login.css")
    }
}

struct AuthProject;

impl Project for AuthProject {
    fn cli_metadata(&self) -> CliMetadata {
        cot::cli::metadata!()
    }

    fn register_apps(&self, apps: &mut AppBuilder, _context: &ProjectContext<WithConfig>) {
        apps.register(DatabaseUserApp::new());
        apps.register_with_views(AuthApp, "");
    }

    fn middlewares(&self, handler: RootHandlerBuilder, context: &MiddlewareContext) -> RootHandler {
        handler
            .middleware(StaticFilesMiddleware::from_context(context))
            .middleware(AuthMiddleware::new())
            .middleware(SessionMiddleware::from_context(context))
            .middleware(LiveReloadMiddleware::new())
            .build()
    }

    fn auth_backend(&self, context: &AuthBackendContext) -> Arc<dyn AuthBackend> {
        let backend =
            Arc::new(UserBackend::new(context.database().clone())) as Arc<dyn AuthBackend>;
        backend
    }
}

#[cot::main]
fn main() -> impl Project {
    AuthProject
}
