// SPDX-License-Identifier: AGPL-3.0-or-later
//! Groups, roles and administration by a tenant's own administrators, against PostgreSQL; set `DATABASE_URL` as for
//! the other crates' tests.

mod common;

use std::collections::BTreeSet;

use common::{WHO, identity, tenant_with};
use kernoid_identity::{
    Address, Identity, IdentityError,
    role::{Permission, Principal, Role},
    session::ClientMeta,
};
use sqlx::PgPool;
use uuid::Uuid;

const PASSWORD: &str = "correct horse battery staple";

fn role(name: &str) -> Role {
    Role::parse(name).unwrap()
}

async fn account(identity: &Identity, tenant: Uuid, address: &str) -> Uuid {
    let account = identity.add_account(tenant, &Address::parse(address).unwrap(), address, WHO).await.unwrap();
    identity.set_password(account, PASSWORD, WHO).await.unwrap();
    account
}

async fn login(identity: &Identity, instance: Uuid, address: &str) -> String {
    identity.create_session(instance, address, PASSWORD, None, &ClientMeta::default()).await.unwrap().token
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn groups_hold_accounts_of_their_tenant(pool: PgPool) {
    let identity = identity(pool);
    let (_, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = account(&identity, tenant, "alice@firma.de").await;
    let bob = account(&identity, tenant, "bob@firma.de").await;
    let group = identity.add_group(tenant, "Vertrieb", WHO).await.unwrap();
    identity.add_group_member(tenant, group, alice, WHO).await.unwrap();
    identity.add_group_member(tenant, group, bob, WHO).await.unwrap();
    identity.add_group_member(tenant, group, bob, WHO).await.unwrap();
    identity.rename_group(tenant, group, "Sales", WHO).await.unwrap();

    let groups = identity.groups(tenant).await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "Sales");
    assert_eq!(groups[0].members, BTreeSet::from([alice, bob]).into_iter().collect::<Vec<_>>());

    identity.remove_group_member(tenant, group, bob, WHO).await.unwrap();
    assert!(matches!(identity.remove_group_member(tenant, group, bob, WHO).await, Err(IdentityError::NotFound(_))));
    assert_eq!(identity.groups(tenant).await.unwrap()[0].members, [alice]);

    // Another tenant of the same instance neither sees the group nor gets its accounts in.
    let instance = identity.tenant_instance(tenant).await.unwrap();
    let other = identity.add_tenant(instance, "Other", WHO).await.unwrap();
    assert!(identity.groups(other).await.unwrap().is_empty());
    assert!(matches!(identity.rename_group(other, group, "Mine", WHO).await, Err(IdentityError::NotFound(_))));
    let theirs = identity.add_group(other, "Theirs", WHO).await.unwrap();
    assert!(matches!(identity.add_group_member(other, theirs, alice, WHO).await, Err(IdentityError::NotFound(_))));

    identity.remove_group(tenant, group, WHO).await.unwrap();
    assert!(identity.groups(tenant).await.unwrap().is_empty());
    assert!(matches!(identity.remove_group(tenant, group, WHO).await, Err(IdentityError::NotFound(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn permissions_come_from_roles_of_the_account_and_its_groups(pool: PgPool) {
    let identity = identity(pool);
    let (_, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = account(&identity, tenant, "alice@firma.de").await;
    let bob = account(&identity, tenant, "bob@firma.de").await;
    assert!(identity.permissions(tenant, alice).await.unwrap().is_empty());

    identity.grant_role(tenant, Principal::Account(alice), &role("auditor"), WHO).await.unwrap();
    identity.grant_role(tenant, Principal::Account(alice), &role("auditor"), WHO).await.unwrap();
    assert_eq!(identity.permissions(tenant, alice).await.unwrap(), BTreeSet::from([Permission::DirectoryRead]));

    let apps = identity.add_group(tenant, "Apps", WHO).await.unwrap();
    identity.grant_role(tenant, Principal::Group(apps), &role("application_manager"), WHO).await.unwrap();
    identity.add_group_member(tenant, apps, alice, WHO).await.unwrap();
    assert_eq!(
        identity.permissions(tenant, alice).await.unwrap(),
        BTreeSet::from([Permission::DirectoryRead, Permission::ProjectsManage, Permission::ApplicationsManage])
    );
    assert_eq!(
        identity.permissions(tenant, bob).await.unwrap(),
        BTreeSet::new(),
        "bob is in no group and holds no role"
    );

    // A group with roles stays until its roles are revoked.
    assert!(matches!(identity.remove_group(tenant, apps, WHO).await, Err(IdentityError::Refused(_))));
    identity.revoke_role(tenant, Principal::Group(apps), &role("application_manager"), WHO).await.unwrap();
    assert_eq!(identity.permissions(tenant, alice).await.unwrap(), BTreeSet::from([Permission::DirectoryRead]));
    identity.remove_group(tenant, apps, WHO).await.unwrap();

    assert!(matches!(
        identity.revoke_role(tenant, Principal::Account(bob), &role("auditor"), WHO).await,
        Err(IdentityError::NotFound(_))
    ));
    // Roles go only to accounts and groups of the tenant.
    let instance = identity.tenant_instance(tenant).await.unwrap();
    let other = identity.add_tenant(instance, "Other", WHO).await.unwrap();
    assert!(matches!(
        identity.grant_role(other, Principal::Account(alice), &role("tenant_admin"), WHO).await,
        Err(IdentityError::NotFound(_))
    ));
    assert!(matches!(
        identity.grant_role(tenant, Principal::Group(Uuid::now_v7()), &role("auditor"), WHO).await,
        Err(IdentityError::NotFound(_))
    ));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_last_tenant_admin_stays(pool: PgPool) {
    let identity = identity(pool);
    let (_, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = account(&identity, tenant, "alice@firma.de").await;
    let admins = identity.add_group(tenant, "Admins", WHO).await.unwrap();
    identity.grant_role(tenant, Principal::Account(alice), &role("tenant_admin"), WHO).await.unwrap();
    identity.grant_role(tenant, Principal::Group(admins), &role("tenant_admin"), WHO).await.unwrap();

    identity.revoke_role(tenant, Principal::Group(admins), &role("tenant_admin"), WHO).await.unwrap();
    assert!(matches!(
        identity.revoke_role(tenant, Principal::Account(alice), &role("tenant_admin"), WHO).await,
        Err(IdentityError::Refused(_))
    ));
    let assignments = identity.role_assignments(tenant).await.unwrap();
    assert_eq!(assignments.len(), 1);
    assert_eq!(
        (assignments[0].principal, assignments[0].role.clone()),
        (Principal::Account(alice), role("tenant_admin"))
    );
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn administrators_need_their_permissions(pool: PgPool) {
    let identity = identity(pool.clone());
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = account(&identity, tenant, "alice@firma.de").await;
    let bob = account(&identity, tenant, "bob@firma.de").await;
    let carol = account(&identity, tenant, "carol@firma.de").await;
    identity.grant_role(tenant, Principal::Account(alice), &role("tenant_admin"), WHO).await.unwrap();
    identity.grant_role(tenant, Principal::Account(bob), &role("user_manager"), WHO).await.unwrap();

    // Without a role: a valid session, but no permission.
    let carol_token = login(&identity, instance, "carol@firma.de").await;
    let nobody = identity.admin(instance, &carol_token, None).await.unwrap();
    assert!(nobody.permissions.is_empty());
    assert!(matches!(identity.admin_groups(&nobody).await, Err(IdentityError::Forbidden(Permission::DirectoryRead))));
    assert!(matches!(
        identity.authorize(instance, &carol_token, Permission::DirectoryRead).await,
        Err(IdentityError::Forbidden(_))
    ));
    assert!(matches!(identity.admin(instance, "ks1.nonsense", None).await, Err(IdentityError::InvalidSession)));

    // The user manager manages groups, but not roles – and so not the members of a group that holds roles.
    let manager = identity.admin(instance, &login(&identity, instance, "bob@firma.de").await, None).await.unwrap();
    let team = identity.admin_add_group(&manager, "Team").await.unwrap();
    identity.admin_add_group_member(&manager, team, carol).await.unwrap();
    assert!(matches!(
        identity.admin_set_mfa_required(&manager, true).await,
        Err(IdentityError::Forbidden(Permission::PoliciesManage))
    ));
    assert!(matches!(
        identity.admin_grant_role(&manager, Principal::Group(team), &role("tenant_admin")).await,
        Err(IdentityError::Forbidden(Permission::RolesManage))
    ));

    let admin = identity.admin(instance, &login(&identity, instance, "alice@firma.de").await, None).await.unwrap();
    identity.admin_grant_role(&admin, Principal::Group(team), &role("auditor")).await.unwrap();
    assert!(matches!(
        identity.admin_add_group_member(&manager, team, bob).await,
        Err(IdentityError::Forbidden(Permission::RolesManage))
    ));
    assert!(matches!(
        identity.admin_remove_group_member(&manager, team, carol).await,
        Err(IdentityError::Forbidden(Permission::RolesManage))
    ));
    identity.admin_add_group_member(&admin, team, bob).await.unwrap();

    // Events name the administrator who caused them.
    let creators = sqlx::query_scalar!(
        "SELECT DISTINCT creator FROM events WHERE event_type IN ('group.added', 'tenant.role_granted')"
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(creators.contains(&format!("account:{alice}")), "{creators:?}");
    assert!(creators.contains(&format!("account:{bob}")), "{creators:?}");

    // The tenant's policy: once a second factor is required, administration needs one too.
    identity.admin_set_mfa_required(&admin, true).await.unwrap();
    assert!(identity.admin_tenant(&admin).await.unwrap().mfa_required);
    let token = login(&identity, instance, "alice@firma.de").await;
    assert!(matches!(identity.admin(instance, &token, None).await, Err(IdentityError::MfaRequired)));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn administrators_stay_in_their_tenant(pool: PgPool) {
    let identity = identity(pool);
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = account(&identity, tenant, "alice@firma.de").await;
    identity.grant_role(tenant, Principal::Account(alice), &role("tenant_admin"), WHO).await.unwrap();

    let other = identity.add_tenant(instance, "Other", WHO).await.unwrap();
    let token = identity.add_tenant_domain(instance, other, &common::domain("other.de"), WHO).await.unwrap();
    let dns = common::FakeDns::default();
    dns.publish("other.de", &token);
    identity.verify_tenant_domain(instance, other, &common::domain("other.de"), &dns, WHO).await.unwrap();
    let dave = account(&identity, other, "dave@other.de").await;
    let theirs = identity.add_group(other, "Theirs", WHO).await.unwrap();

    let admin = identity.admin(instance, &login(&identity, instance, "alice@firma.de").await, None).await.unwrap();
    assert_eq!(admin.tenant(), tenant);
    assert!(matches!(identity.admin_rename_group(&admin, theirs, "Mine").await, Err(IdentityError::NotFound(_))));
    assert!(matches!(identity.admin_remove_group(&admin, theirs).await, Err(IdentityError::NotFound(_))));
    assert!(matches!(identity.admin_add_group_member(&admin, theirs, alice).await, Err(IdentityError::NotFound(_))));
    assert!(matches!(
        identity.admin_grant_role(&admin, Principal::Account(dave), &role("auditor")).await,
        Err(IdentityError::NotFound(_))
    ));
    let mine = identity.admin_add_group(&admin, "Mine").await.unwrap();
    assert!(matches!(identity.admin_add_group_member(&admin, mine, dave).await, Err(IdentityError::NotFound(_))));
    assert!(identity.role_assignments(other).await.unwrap().is_empty());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn instance_roles_reach_every_tenant_of_their_instance(pool: PgPool) {
    let identity = identity(pool);
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = account(&identity, tenant, "alice@firma.de").await;
    let other = identity.add_tenant(instance, "Other", WHO).await.unwrap();
    let admin = role("instance_admin");

    // Only instance roles, only for accounts and groups of the instance.
    assert!(matches!(
        identity.grant_instance_role(instance, Principal::Account(alice), &role("tenant_admin"), WHO).await,
        Err(IdentityError::NotFound(_))
    ));
    let (elsewhere, _) = tenant_with(&identity, "login.other.de", &[]).await;
    assert!(matches!(
        identity.grant_instance_role(elsewhere, Principal::Account(alice), &admin, WHO).await,
        Err(IdentityError::NotFound(_))
    ));

    assert!(identity.permissions(other, alice).await.unwrap().is_empty());
    identity.grant_instance_role(instance, Principal::Account(alice), &admin, WHO).await.unwrap();
    let in_other = identity.permissions(other, alice).await.unwrap();
    assert!(in_other.contains(&Permission::TenantsManage) && in_other.contains(&Permission::AccountsManage));
    let token = login(&identity, instance, "alice@firma.de").await;
    let acting = identity.admin(instance, &token, Some(other)).await.unwrap();
    assert_eq!(acting.tenant(), other);
    // Tenants of another instance stay out of reach.
    let foreign = identity.add_tenant(elsewhere, "Foreign", WHO).await.unwrap();
    assert!(matches!(identity.admin(instance, &token, Some(foreign)).await, Err(IdentityError::NotFound(_))));

    assert!(matches!(
        identity.revoke_instance_role(instance, Principal::Account(alice), &admin, WHO).await,
        Err(IdentityError::Refused(_))
    ));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn tenants_define_roles_of_their_own(pool: PgPool) {
    let identity = identity(pool);
    let (_, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = account(&identity, tenant, "alice@firma.de").await;
    let lead = role("project_lead");
    let permissions = BTreeSet::from([Permission::DirectoryRead, Permission::ProjectsManage]);

    assert!(matches!(
        identity.grant_role(tenant, Principal::Account(alice), &lead, WHO).await,
        Err(IdentityError::NotFound(_))
    ));
    identity.define_role(tenant, &lead, &permissions, WHO).await.unwrap();
    identity.grant_role(tenant, Principal::Account(alice), &lead, WHO).await.unwrap();
    assert_eq!(identity.permissions(tenant, alice).await.unwrap(), permissions);

    // Changing the role changes what its holders may do.
    identity.define_role(tenant, &lead, &BTreeSet::from([Permission::DirectoryRead]), WHO).await.unwrap();
    assert_eq!(identity.permissions(tenant, alice).await.unwrap(), BTreeSet::from([Permission::DirectoryRead]));

    for (name, permissions) in [
        ("auditor", BTreeSet::from([Permission::DirectoryRead])),
        ("instance_admin", BTreeSet::from([Permission::DirectoryRead])),
        ("empty", BTreeSet::new()),
        ("sneaky", BTreeSet::from([Permission::TenantsManage])),
    ] {
        let refused = identity.define_role(tenant, &role(name), &permissions, WHO).await;
        assert!(matches!(refused, Err(IdentityError::Refused(_))), "{name}");
    }
    assert!(Role::parse("Not Valid").is_err());

    assert!(matches!(identity.delete_role(tenant, &lead, WHO).await, Err(IdentityError::Refused(_))));
    identity.revoke_role(tenant, Principal::Account(alice), &lead, WHO).await.unwrap();
    identity.delete_role(tenant, &lead, WHO).await.unwrap();
    let names: Vec<_> = identity.tenant_roles(tenant).await.unwrap().into_iter().map(|info| info.role).collect();
    assert_eq!(names.len(), 4);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn only_active_accounts_count_as_the_last_administrators(pool: PgPool) {
    let identity = identity(pool);
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = account(&identity, tenant, "alice@firma.de").await;
    let bob = account(&identity, tenant, "bob@firma.de").await;
    let admins = identity.add_group(tenant, "Admins", WHO).await.unwrap();
    identity.grant_role(tenant, Principal::Account(alice), &role("tenant_admin"), WHO).await.unwrap();
    identity.grant_role(tenant, Principal::Group(admins), &role("tenant_admin"), WHO).await.unwrap();

    // The group has no members: alice alone administers – she can be neither deactivated nor revoked.
    assert!(matches!(identity.set_account_active(alice, false, WHO).await, Err(IdentityError::Refused(_))));
    assert!(matches!(
        identity.revoke_role(tenant, Principal::Account(alice), &role("tenant_admin"), WHO).await,
        Err(IdentityError::Refused(_))
    ));
    // With bob in the group, both may go – one at a time.
    identity.add_group_member(tenant, admins, bob, WHO).await.unwrap();
    identity.set_account_active(alice, false, WHO).await.unwrap();
    assert!(matches!(identity.remove_group_member(tenant, admins, bob, WHO).await, Err(IdentityError::Refused(_))));
    assert!(matches!(identity.set_account_active(bob, false, WHO).await, Err(IdentityError::Refused(_))));
    // alice's assignment counts for nothing while she is deactivated: revoking it is fine.
    identity.revoke_role(tenant, Principal::Account(alice), &role("tenant_admin"), WHO).await.unwrap();
    identity.set_account_active(alice, true, WHO).await.unwrap();

    // The instance: its only instance_admin is not deactivated, nor is the tenant around them.
    identity.grant_instance_role(instance, Principal::Account(bob), &role("instance_admin"), WHO).await.unwrap();
    let other = identity.add_tenant(instance, "Other", WHO).await.unwrap();
    identity.set_tenant_active(instance, other, false, WHO).await.unwrap();
    assert!(matches!(identity.set_tenant_active(instance, tenant, false, WHO).await, Err(IdentityError::Refused(_))));
    identity.grant_role(tenant, Principal::Account(alice), &role("tenant_admin"), WHO).await.unwrap();
    assert!(matches!(identity.set_account_active(bob, false, WHO).await, Err(IdentityError::Refused(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn instances_define_roles_of_their_own(pool: PgPool) {
    let identity = identity(pool);
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let other = identity.add_tenant(instance, "Other", WHO).await.unwrap();
    let carol = account(&identity, tenant, "carol@firma.de").await;
    let helpdesk: BTreeSet<Permission> =
        [Permission::InstanceRead, Permission::DirectoryRead, Permission::AccountsManage].into();

    assert!(identity.define_instance_role(instance, &role("instance_admin"), &helpdesk, WHO).await.is_err());
    assert!(identity.define_instance_role(instance, &role("helpdesk"), &BTreeSet::new(), WHO).await.is_err());
    assert!(matches!(
        identity.grant_instance_role(instance, Principal::Account(carol), &role("helpdesk"), WHO).await,
        Err(IdentityError::NotFound(_))
    ));
    identity.define_instance_role(instance, &role("helpdesk"), &helpdesk, WHO).await.unwrap();
    identity.grant_instance_role(instance, Principal::Account(carol), &role("helpdesk"), WHO).await.unwrap();

    // Instance permissions at the instance, tenant permissions in every tenant.
    let elsewhere = identity.permissions(other, carol).await.unwrap();
    assert_eq!(elsewhere, helpdesk);
    let roles = identity.instance_roles(instance).await.unwrap();
    let own = roles.iter().find(|info| info.role == role("helpdesk")).unwrap();
    assert!(!own.builtin);
    assert_eq!(own.permissions, [Permission::InstanceRead].into());
    assert_eq!(own.tenant_permissions, [Permission::DirectoryRead, Permission::AccountsManage].into());

    assert!(matches!(
        identity.delete_instance_role(instance, &role("helpdesk"), WHO).await,
        Err(IdentityError::Refused(_))
    ));
    identity.revoke_instance_role(instance, Principal::Account(carol), &role("helpdesk"), WHO).await.unwrap();
    identity.delete_instance_role(instance, &role("helpdesk"), WHO).await.unwrap();
    assert!(identity.permissions(other, carol).await.unwrap().is_empty());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_audit_log_shows_the_tenants_events_to_auditors(pool: PgPool) {
    use kernoid_identity::audit::{AuditQuery, AuditScope};

    let identity = identity(pool);
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = account(&identity, tenant, "alice@firma.de").await;
    account(&identity, tenant, "carol@firma.de").await;
    identity.grant_role(tenant, Principal::Account(alice), &role("auditor"), WHO).await.unwrap();
    // Logging in is an event too (session.created); it comes before the changes here.
    let auditor = identity.admin(instance, &login(&identity, instance, "alice@firma.de").await, None).await.unwrap();
    let group = identity.add_group(tenant, "Vertrieb", WHO).await.unwrap();
    identity.add_group_member(tenant, group, alice, WHO).await.unwrap();

    let all = AuditQuery::default();
    let log = identity.admin_audit_log(&auditor, AuditScope::Tenant, &all).await.unwrap();
    assert_eq!(log[0].event_type, "group.member_added", "newest first");
    assert!(log.iter().any(|entry| entry.event_type == "account.added"));
    assert!(log.windows(2).all(|pair| pair[0].position > pair[1].position));

    // One object, and the next page.
    let group_only = AuditQuery {
        aggregate_type: Some("group".into()),
        aggregate_id: Some(group.to_string()),
        ..AuditQuery::default()
    };
    let events = identity.admin_audit_log(&auditor, AuditScope::Tenant, &group_only).await.unwrap();
    assert_eq!(
        events.iter().map(|entry| entry.event_type.as_str()).collect::<Vec<_>>(),
        ["group.member_added", "group.added"]
    );
    let page = AuditQuery { before: Some(log[0].position), limit: Some(1), ..AuditQuery::default() };
    let next = identity.admin_audit_log(&auditor, AuditScope::Tenant, &page).await.unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].position, log[1].position);

    // No permission, no log; the instance's own events need instance.read.
    let carol = identity.admin(instance, &login(&identity, instance, "carol@firma.de").await, None).await.unwrap();
    assert!(matches!(
        identity.admin_audit_log(&carol, AuditScope::Tenant, &all).await,
        Err(IdentityError::Forbidden(Permission::DirectoryRead))
    ));
    assert!(matches!(
        identity.admin_audit_log(&auditor, AuditScope::Instance, &all).await,
        Err(IdentityError::Forbidden(Permission::InstanceRead))
    ));
}
