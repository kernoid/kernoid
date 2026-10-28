// SPDX-License-Identifier: AGPL-3.0-or-later
//! Administration of applications (by tenant administrators) and signing keys (by instance administrators), with
//! the same permission checks for REST and GraphQL – see `kernoid_identity::admin`.

use kernoid_identity::{
    IdentityError,
    consent::ConsentInfo,
    role::{Admin, Permission},
};
use uuid::Uuid;

use crate::{
    Oidc, OidcError, Result,
    application::{AppOptions, ApplicationInfo, Kind},
    keys::KeyInfo,
};

impl Oidc {
    /// An application of the administered tenant; one of another tenant is unknown.
    pub async fn admin_application(&self, admin: &Admin, application: Uuid) -> Result<ApplicationInfo> {
        admin.require(Permission::DirectoryRead)?;
        match self.application(application).await {
            Ok(info) if info.tenant == admin.tenant() => Ok(info),
            Ok(_) | Err(OidcError::InvalidClient) => Err(IdentityError::NotFound("the application").into()),
            Err(error) => Err(error),
        }
    }

    pub async fn admin_applications(&self, admin: &Admin) -> Result<Vec<ApplicationInfo>> {
        admin.require(Permission::DirectoryRead)?;
        self.applications(admin.tenant()).await
    }

    async fn managed_application(&self, admin: &Admin, application: Uuid) -> Result<ApplicationInfo> {
        admin.require(Permission::ApplicationsManage)?;
        self.admin_application(admin, application).await
    }

    /// Registers an application in a project of the tenant; returns its id and, for a confidential one, its secret.
    pub async fn admin_add_application(
        &self,
        admin: &Admin,
        project: Uuid,
        name: &str,
        kind: Kind,
        redirect_uris: &[String],
        post_logout_redirect_uris: &[String],
    ) -> Result<(Uuid, Option<String>)> {
        admin.require(Permission::ApplicationsManage)?;
        self.add_application(
            admin.tenant(),
            project,
            name,
            kind,
            redirect_uris,
            post_logout_redirect_uris,
            &admin.creator(),
        )
        .await
    }

    pub async fn admin_rename_application(&self, admin: &Admin, application: Uuid, name: &str) -> Result<()> {
        self.managed_application(admin, application).await?;
        self.rename_application(application, name, &admin.creator()).await
    }

    pub async fn admin_set_application_project(&self, admin: &Admin, application: Uuid, project: Uuid) -> Result<()> {
        self.managed_application(admin, application).await?;
        self.set_application_project(application, project, &admin.creator()).await
    }

    pub async fn admin_set_redirect_uris(&self, admin: &Admin, application: Uuid, uris: &[String]) -> Result<()> {
        self.managed_application(admin, application).await?;
        self.set_redirect_uris(application, uris, &admin.creator()).await
    }

    pub async fn admin_set_post_logout_redirect_uris(
        &self,
        admin: &Admin,
        application: Uuid,
        uris: &[String],
    ) -> Result<()> {
        self.managed_application(admin, application).await?;
        self.set_post_logout_redirect_uris(application, uris, &admin.creator()).await
    }

    pub async fn admin_set_application_options(
        &self,
        admin: &Admin,
        application: Uuid,
        options: &AppOptions,
    ) -> Result<()> {
        self.managed_application(admin, application).await?;
        self.set_application_options(application, options, &admin.creator()).await
    }

    pub async fn admin_set_application_active(&self, admin: &Admin, application: Uuid, active: bool) -> Result<()> {
        self.managed_application(admin, application).await?;
        self.set_application_active(application, active, &admin.creator()).await
    }

    /// Replaces the secret of a confidential application; returns the new one, shown this once.
    pub async fn admin_new_client_secret(&self, admin: &Admin, application: Uuid) -> Result<String> {
        self.managed_application(admin, application).await?;
        self.new_client_secret(application, &admin.creator()).await
    }

    /// Lets an application manager require a second factor for one application. The tenant's own requirement still
    /// holds, so this can only make logins stricter.
    pub async fn admin_set_application_mfa_required(
        &self,
        admin: &Admin,
        application: Uuid,
        required: bool,
    ) -> Result<()> {
        self.managed_application(admin, application).await?;
        self.set_application_mfa_required(application, required, &admin.creator()).await
    }

    // Consents of the tenant's accounts

    pub async fn admin_account_consents(&self, admin: &Admin, account: Uuid) -> Result<Vec<ConsentInfo>> {
        self.identity.managed_account(admin, account).await?;
        Ok(self.identity.consents(account).await?)
    }

    /// Withdraws an account's consent to an application and the application's tokens for it – like ending a session,
    /// it needs every permission the account holds.
    pub async fn admin_revoke_consent(&self, admin: &Admin, account: Uuid, application: Uuid) -> Result<()> {
        self.identity.weaker_account(admin, account).await?;
        self.revoke_consent(account, application, &admin.creator()).await
    }

    // Signing keys of the instance

    pub async fn admin_signing_keys(&self, admin: &Admin) -> Result<Vec<KeyInfo>> {
        admin.require(Permission::InstanceRead)?;
        self.signing_keys(admin.instance()).await
    }

    pub async fn admin_add_signing_key(&self, admin: &Admin) -> Result<String> {
        admin.require(Permission::InstanceManage)?;
        self.add_signing_key(admin.instance(), &admin.creator()).await
    }

    pub async fn admin_activate_signing_key(&self, admin: &Admin, kid: &str) -> Result<()> {
        admin.require(Permission::InstanceManage)?;
        self.activate_signing_key(admin.instance(), kid, &admin.creator()).await
    }

    pub async fn admin_remove_signing_key(&self, admin: &Admin, kid: &str) -> Result<()> {
        admin.require(Permission::InstanceManage)?;
        self.remove_signing_key(admin.instance(), kid, &admin.creator()).await
    }
}
