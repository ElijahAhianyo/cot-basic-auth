use crate::forms::login::LoginForm;
use async_trait::async_trait;
use cot::auth::db::CreateUserError;
use cot::auth::{
    Auth, AuthBackend, AuthError, PasswordHash, PasswordVerificationResult, SessionAuthHash, UserId,
};
use cot::common_types::{Email, Password};
use cot::config::SecretKey;
use cot::db::{Auto, Database, LimitedString, Model, model, query};
use cot::form::Form;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::any::Any;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

#[derive(Debug, Clone, Form)]
#[model]
pub struct User {
    #[model(primary_key)]
    id: Auto<i64>,
    #[model(unique)]
    username: LimitedString<254>,
    name: LimitedString<254>,
    password: PasswordHash,
    email: Email,
}

impl User {
    pub fn new(
        id: Auto<i64>,
        username: LimitedString<254>,
        password: &Password,
        email: Email,
        name: LimitedString<254>,
    ) -> Self {
        Self {
            id,
            username,
            password: PasswordHash::from_password(password),
            email,
            name,
        }
    }

    pub async fn authenticate<DB: cot::db::DatabaseBackend>(
        db: &DB,
        credentials: &UserCredentials,
    ) -> cot::auth::Result<Option<Self>> {
        let username = credentials.username();
        let username_limited = LimitedString::<254>::new(username.to_string()).map_err(|_| {
            AuthError::backend_error(CreateUserError::UsernameTooLong(username.len()))
        })?;

        let user = query!(User, $username == username_limited)
            .get(db)
            .await
            .map_err(AuthError::backend_error)?;

        if let Some(mut user) = user {
            let password_hash = &user.password;
            match password_hash.verify(credentials.password()) {
                PasswordVerificationResult::Ok => Ok(Some(user)),
                PasswordVerificationResult::OkObsolete(new_hash) => {
                    user.password = new_hash;
                    user.save(db).await.map_err(AuthError::backend_error)?;
                    Ok(Some(user))
                }
                PasswordVerificationResult::Invalid => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    #[must_use]
    pub fn id(&self) -> i64 {
        match self.id {
            Auto::Fixed(id) => id,
            Auto::Auto => unreachable!("DatabaseUser constructed with an unknown ID"),
        }
    }
    #[must_use]
    pub fn password_hash(&self) -> &PasswordHash {
        &self.password
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn get_by_id<DB: cot::db::DatabaseBackend>(
        db: &DB,
        id: i64,
    ) -> cot::auth::Result<Option<Self>> {
        let user = query!(User, $id == id)
            .get(db)
            .await
            .map_err(AuthError::backend_error)?;
        Ok(user)
    }

    pub async fn set_password(&mut self, password: &Password) -> &mut Self {
        self.password = PasswordHash::from_password(password);
        self
    }
}

type SessionAuthHmac = Hmac<Sha512>;

impl cot::auth::User for User {
    fn id(&self) -> Option<UserId> {
        Some(UserId::Int(self.id()))
    }

    fn username(&self) -> Option<Cow<'_, str>> {
        Some(Cow::from(self.username.as_str()))
    }

    fn is_active(&self) -> bool {
        true
    }

    fn is_authenticated(&self) -> bool {
        true
    }

    fn session_auth_hash(&self, secret_key: &SecretKey) -> Option<SessionAuthHash> {
        let mut mac = SessionAuthHmac::new_from_slice(secret_key.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(self.password.as_str().as_bytes());
        let hmac_data = mac.finalize().into_bytes();

        Some(SessionAuthHash::new(&hmac_data))
    }
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.username)
    }
}

#[derive(Clone, Debug)]
pub struct UserCredentials {
    username: String,
    password: Password,
}

impl UserCredentials {
    pub fn new(username: String, password: Password) -> Self {
        Self { username, password }
    }
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &Password {
        &self.password
    }
}

pub struct UserBackend {
    database: Arc<Database>,
}

impl UserBackend {
    pub fn new(database: Arc<Database>) -> Self {
        Self { database }
    }
}

#[async_trait]
impl AuthBackend for UserBackend {
    async fn authenticate(
        &self,
        credentials: &(dyn Any + Send + Sync),
    ) -> cot::auth::Result<Option<Box<dyn cot::auth::User + Send + Sync>>> {
        if let Some(credentials) = credentials.downcast_ref::<UserCredentials>() {
            let user = User::authenticate(&self.database, credentials)
                .await
                .map(|user| {
                    user.map(|user| Box::new(user) as Box<dyn cot::auth::User + Send + Sync>)
                })?;
            Ok(user)
        } else {
            Err(AuthError::CredentialsTypeNotSupported)
        }
    }

    async fn get_by_id(
        &self,
        id: UserId,
    ) -> cot::auth::Result<Option<Box<dyn cot::auth::User + Send + Sync>>> {
        let UserId::Int(id) = id else {
            return Err(AuthError::UserIdTypeNotSupported);
        };

        let user = User::get_by_id(&self.database, id)
            .await?
            .map(|user| Box::new(user) as Box<dyn cot::auth::User + Send + Sync>);
        Ok(user)
    }
}

pub(crate) async fn authenticate(auth: &Auth, login_form: &LoginForm) -> cot::Result<bool> {
    let user = auth
        .authenticate(&UserCredentials::new(
            login_form.username.clone(),
            Password::new(login_form.password.clone().into_string()),
        ))
        .await?;
    if let Some(user) = user {
        auth.login(user).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}
