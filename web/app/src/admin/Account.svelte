<!-- SPDX-License-Identifier: MIT -->
<!-- One account in detail: name, state, addresses, logins, password and second factors, services, quotas, who may use
     its mail and files, sessions, applications and linked providers. -->
<script lang="ts" module>
  import { t } from "../i18n.js";
  import type { AccountDetails } from "./api.svelte.js";

  export function kindOf(account: AccountDetails): string {
    if (account.shared) return t("Shared mailbox");
    return account.native ? t("Person") : t("External");
  }
</script>

<script lang="ts">
  import { emptyText, loaded } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import {
    type ConsentView,
    type FilesOverviewView,
    type MailOverviewView,
    type Schema,
    type ServiceView,
    type SessionSummaryView,
    admin,
    need,
  } from "./api.svelte.js";
  import Grants, { FILE_LEVELS, MAIL_LEVELS } from "./Grants.svelte";
  import KeyRecovery from "./KeyRecovery.svelte";
  import MailTransfer from "./MailTransfer.svelte";
  import Sieve from "./Sieve.svelte";
  import Buttons from "./ui/Buttons.svelte";
  import Check from "./ui/Check.svelte";
  import Dialog from "./ui/Dialog.svelte";
  import Field from "./ui/Field.svelte";
  import Form from "./ui/Form.svelte";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";
  import PrincipalSelect from "./ui/PrincipalSelect.svelte";
  import Select from "./ui/Select.svelte";
  import { Action, bytes, go, parseBytes, principal, useDirectory, when } from "./ui.svelte.js";

  type MailGrant = Schema<"MailGrantView">;
  type IdpLink = Schema<"IdpLinkView">;

  // The parent keys this component by the account, so the id is read once.
  let { id }: { id: string } = $props();

  const directory = useDirectory();
  const action = new Action();
  // svelte-ignore state_referenced_locally
  const path = { path: { id } };
  const account = loaded(() => need(admin.GET("/v1/accounts/{id}", { params: path })));
  const services = loaded(() => need(admin.GET("/v1/accounts/{id}/services", { params: path })).catch((): ServiceView[] => []));
  const mail = loaded(() => need(admin.GET("/v1/accounts/{id}/mail", { params: path })).catch((): MailOverviewView | undefined => undefined));
  const files = loaded(() => need(admin.GET("/v1/accounts/{id}/files", { params: path })).catch((): FilesOverviewView | undefined => undefined));
  const mailAccess = loaded(() =>
    need(admin.GET("/v1/accounts/{id}/mail/access", { params: path })).catch((): MailGrant[] => []),
  );
  const fileAccess = loaded(() => need(admin.GET("/v1/accounts/{id}/files/access", { params: path })).catch((): Schema<"FileGrantView">[] => []));
  const sessions = loaded(() => need(admin.GET("/v1/accounts/{id}/sessions", { params: path })).catch((): SessionSummaryView[] => []));
  const consents = loaded(() => need(admin.GET("/v1/accounts/{id}/consents", { params: path })).catch((): ConsentView[] => []));
  const links = loaded(() =>
    need(admin.GET("/v1/accounts/{id}/links", { params: path })).catch((): IdpLink[] => []),
  );
  const addresses = loaded(() => need(admin.GET("/v1/accounts/{id}/addresses", { params: path })).catch((): Schema<"AddressView">[] => []));
  let dialog = $state<"mail-grant" | "file-grant" | "password">();

  /** A resource's value unless it failed. */
  const ok = <T,>(resource: { value: T | undefined; error: unknown }): T | undefined => (resource.error ? undefined : resource.value);
  const me = $derived(ok(account));
  const mailView = $derived(ok(mail));
  const filesView = $derived(ok(files));

  const change = async (work: () => Promise<unknown>, done: string, after: () => unknown) => {
    if (await action.run(work, done)) await after();
  };
  const patch = (body: Schema<"AccountChange">) => need(admin.PATCH("/v1/accounts/{id}", { params: path, body }));
</script>

{#if me}
  <p>
    <button type="button" class="quiet" onclick={() => go("accounts")}>← {t("Accounts")}</button>
  </p>
  <Head title={me.display_name} description={`${me.address} · ${kindOf(me)} · ${me.id}`}>
    <button type="button" onclick={() => go("audit", `account:${me.id}`)}>{t("History")}</button>
    <button
      type="button"
      class:danger={me.active}
      disabled={action.busy}
      onclick={() =>
        void change(
          () => patch({ active: !me.active }),
          me.active ? t("The account is deactivated.") : t("The account is active again."),
          () => {
            void account.refetch();
            directory.reload();
          },
        )}
    >
      {me.active ? t("Deactivate") : t("Reactivate")}
    </button>
  </Head>
  <Outcome {action} />

  <section>
    <h2>{t("Name and addresses")}</h2>
    <Form
      class="row"
      submit={(field) =>
        void change(
          () => patch({ display_name: field("name") }),
          t("Saved."),
          () => (void account.refetch(), directory.reload()),
        )}
    >
      <input name="name" required value={me.display_name} aria-label={t("Name")} />
      <button type="submit" disabled={action.busy}>{t("Rename")}</button>
    </Form>
    {#if (ok(addresses) ?? []).length > 0}
      <ul class="rows">
        {#each ok(addresses) ?? [] as entry (entry.address)}
          <li>
            <span class="grow">
              {entry.address}
              {#if entry.primary}
                <span class="muted small"> · {t("primary, the login name")}</span>
              {/if}
            </span>
            {#if !entry.primary}
              <button
                type="button"
                class="quiet"
                disabled={action.busy}
                onclick={() =>
                  void change(
                    () => patch({ primary_address: entry.address }),
                    t("Saved."),
                    () => (void account.refetch(), void addresses.refetch(), directory.reload()),
                  )}
              >
                {t("Make primary")}
              </button>
              <button
                type="button"
                class="quiet danger"
                disabled={action.busy}
                onclick={() =>
                  void change(
                    () => need(admin.DELETE("/v1/accounts/{id}/aliases/{address}", { params: { path: { id, address: entry.address } } })),
                    t("The alias is removed."),
                    () => addresses.refetch(),
                  )}
              >
                {t("Remove")}
              </button>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
    {#if me.native}
      <Form
        class="row"
        submit={(field) =>
          void change(
            () => need(admin.PUT("/v1/accounts/{id}/aliases/{address}", { params: { path: { id, address: field("alias") } } })),
            t("The alias is added."),
            () => addresses.refetch(),
          )}
      >
        <input name="alias" type="email" required placeholder={t("Alias, e.g. office@example.org")} aria-label={t("Alias")} />
        <button type="submit" disabled={action.busy}>{t("Add alias")}</button>
      </Form>
    {/if}
  </section>

  {#if !me.shared}
    <section>
      <h2>{t("Logging in")}</h2>
      <Form
        class="row"
        submit={(field) =>
          void change(
            () => need(admin.PUT("/v1/accounts/{id}/username", { params: path, body: { username: field("username") || null } })),
            t("Saved."),
            () => undefined,
          )}
      >
        <input name="username" placeholder={t("Username (empty removes it)")} aria-label={t("Username")} />
        <button type="submit" disabled={action.busy}>{t("Set username")}</button>
      </Form>
      <Form
        class="row"
        submit={(field, all) =>
          void change(
            () =>
              need(
                admin.PUT("/v1/accounts/{id}/contact", {
                  params: path,
                  body: { email: field("email") || null, verified: all("verified").length > 0 },
                }),
              ),
            t("Saved."),
            () => undefined,
          )}
      >
        <input name="email" type="email" placeholder={t("Contact address (empty removes it)")} aria-label={t("Contact address")} />
        <label class="inline">
          <input type="checkbox" name="verified" />
          <span>{t("verified")}</span>
        </label>
        <button type="submit" disabled={action.busy}>{t("Set contact address")}</button>
      </Form>
      <div class="actions">
        <button type="button" onclick={() => (dialog = "password")}>{t("Set a password")}</button>
        <button
          type="button"
          class="danger"
          disabled={action.busy}
          onclick={() =>
            window.confirm(t("Remove all second factors, recovery codes and app passwords of this account?")) &&
            void change(
              () => need(admin.DELETE("/v1/accounts/{id}/second-factors", { params: path })),
              t("The second factors are removed."),
              () => undefined,
            )}
        >
          {t("Reset second factors")}
        </button>
      </div>
    </section>
  {/if}

  <section>
    <h2>{t("Services")}</h2>
    <table class="nodes">
      <tbody>
        {#each ["mail", "files"] as service (service)}
          {@const state = ok(services)?.find((entry) => entry.service === service)?.state ?? "off"}
          <tr>
            <td class="name">{service === "mail" ? t("Mail") : t("Files")}</td>
            <td class="small">{t(state)}</td>
            <td class="end">
              {#if state === "on"}
                <button
                  type="button"
                  class="quiet danger"
                  disabled={action.busy}
                  onclick={() =>
                    void change(
                      () => need(admin.DELETE("/v1/accounts/{id}/services/{service}", { params: { path: { id, service } } })),
                      t("Saved."),
                      () => services.refetch(),
                    )}
                >
                  {t("Switch off")}
                </button>
              {:else}
                <button
                  type="button"
                  disabled={action.busy}
                  onclick={() =>
                    void change(
                      () => need(admin.PUT("/v1/accounts/{id}/services/{service}", { params: { path: { id, service } } })),
                      t("Saved."),
                      () => services.refetch(),
                    )}
                >
                  {state === "requested" ? t("Approve") : t("Switch on")}
                </button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>

  {#if me?.native && !me.shared}
    <KeyRecovery {id} name={me.display_name} />
  {/if}

  <section>
    <h2>{t("Quotas")}</h2>
    <Form
      class="stack"
      submit={(field) =>
        void change(
          async () => {
            if (mailView) await need(admin.PUT("/v1/accounts/{id}/mail/quota", { params: path, body: { bytes: parseBytes(field("mail")) } }));
            if (filesView) await need(admin.PUT("/v1/accounts/{id}/files/quota", { params: path, body: { bytes: parseBytes(field("files")) } }));
          },
          t("Saved."),
          () => (void mail.refetch(), void files.refetch()),
        )}
    >
      {#if mailView}
        <Field
          label={t("Mail – {used} used of {limit}", { used: bytes(mailView.used_bytes), limit: bytes(mailView.effective_quota) })}
          name="mail"
          placeholder={t("the tenant's default")}
          value={mailView.quota != null ? bytes(mailView.quota) : ""}
        />
      {/if}
      {#if filesView}
        <Field
          label={t("Files – {used} used of {limit}", { used: bytes(filesView.used_bytes), limit: bytes(filesView.effective_quota) })}
          name="files"
          placeholder={t("the tenant's default")}
          value={filesView.quota != null ? bytes(filesView.quota) : ""}
        />
      {/if}
      <Buttons busy={action.busy} />
    </Form>
  </section>

  {#if mailView}
    <section>
      <div class="toolbar">
        <h2 class="grow">{t("Access to the mail")}</h2>
        <button type="button" onclick={() => (dialog = "mail-grant")}>{t("Grant access")}</button>
      </div>
      <Grants
        grants={ok(mailAccess) ?? []}
        where={(grant) => (grant.mailbox ? (mailView.mailboxes.find((box) => box.id === grant.mailbox)?.name ?? grant.mailbox) : t("all mailboxes"))}
        extra={(grant) => (grant.send_as ? t("may send as") : "")}
        busy={action.busy}
        remove={(grant) =>
          void change(
            () =>
              need(
                admin.DELETE("/v1/accounts/{id}/mail/access", {
                  params: {
                    path: { id },
                    query: { grantee_kind: grant.grantee_kind, grantee_id: grant.grantee_id, mailbox: grant.mailbox ?? null },
                  },
                }),
              ),
            t("The access is removed."),
            () => mailAccess.refetch(),
          )}
      />
    </section>
  {/if}

  {#if filesView}
    <section>
      <div class="toolbar">
        <h2 class="grow">{t("Access to the files")}</h2>
        <button type="button" onclick={() => (dialog = "file-grant")}>{t("Grant access")}</button>
      </div>
      <Grants
        grants={ok(fileAccess) ?? []}
        where={(grant) => (grant.node ? t("a folder") : t("all files"))}
        busy={action.busy}
        remove={(grant) =>
          void change(
            () =>
              need(
                admin.DELETE("/v1/accounts/{id}/files/access", {
                  params: {
                    path: { id },
                    query: { grantee_kind: grant.grantee_kind, grantee_id: grant.grantee_id, node: grant.node ?? null },
                  },
                }),
              ),
            t("The access is removed."),
            () => fileAccess.refetch(),
          )}
      />
    </section>
  {/if}

  {#if mailView}
    <MailTransfer account={id} mail={mailView} onImported={() => void mail.refetch()} />
    <Sieve account={id} />
  {/if}

  {#if !me.shared}
    <section>
      <h2>{t("Sessions")}</h2>
      <ul class="rows">
        {#each ok(sessions) ?? [] as entry (entry.id)}
          <li>
            <span class="grow">
              {(entry.user_agent ?? t("Unknown device")).slice(0, 60)}
              <small class="muted">
                – {when(entry.created_at)}{entry.client_address ? `, ${entry.client_address}` : ""}
              </small>
            </span>
            <button
              type="button"
              class="quiet danger"
              disabled={action.busy}
              onclick={() =>
                void change(
                  () => need(admin.DELETE("/v1/accounts/{id}/sessions/{session}", { params: { path: { id, session: entry.id } } })),
                  t("The session has ended."),
                  () => sessions.refetch(),
                )}
            >
              {t("End")}
            </button>
          </li>
        {:else}
          <li class="muted">{emptyText(sessions, t("No sessions."))}</li>
        {/each}
      </ul>
    </section>

    <section>
      <h2>{t("Applications")}</h2>
      <ul class="rows">
        {#each ok(consents) ?? [] as consent (consent.application)}
          <li>
            <span class="grow">
              {consent.application_name} <small class="muted">– {when(consent.granted_at)}</small>
            </span>
            <button
              type="button"
              class="quiet danger"
              disabled={action.busy}
              onclick={() =>
                void change(
                  () =>
                    need(admin.DELETE("/v1/accounts/{id}/consents/{application}", { params: { path: { id, application: consent.application } } })),
                  t("Withdrawn."),
                  () => consents.refetch(),
                )}
            >
              {t("Withdraw")}
            </button>
          </li>
        {:else}
          <li class="muted">{emptyText(consents, t("None."))}</li>
        {/each}
      </ul>
    </section>

    <section>
      <h2>{t("Linked providers")}</h2>
      <ul class="rows">
        {#each ok(links) ?? [] as link (`${link.identity_provider}/${link.subject}`)}
          <li>
            <span class="grow">
              {link.identity_provider} <small class="muted">– {link.subject}</small>
            </span>
            <button
              type="button"
              class="quiet danger"
              disabled={action.busy}
              onclick={() =>
                void change(
                  () =>
                    need(
                      admin.DELETE("/v1/accounts/{id}/links/{idp}/{subject}", {
                        params: { path: { id, idp: link.identity_provider, subject: link.subject } },
                      }),
                    ),
                  t("The link is removed."),
                  () => links.refetch(),
                )}
            >
              {t("Remove")}
            </button>
          </li>
        {:else}
          <li class="muted">{emptyText(links, t("None."))}</li>
        {/each}
      </ul>
    </section>
  {/if}

  {#if dialog === "password"}
    <Dialog title={t("Set a password")} onClose={() => (dialog = undefined)}>
      <Form
        submit={(field) =>
          void change(
            () => need(admin.PUT("/v1/accounts/{id}/password", { params: path, body: { password: field("password") } })),
            t("The password is set."),
            () => (dialog = undefined),
          )}
      >
        <Field label={t("New password")} name="password" type="password" autocomplete="new-password" required minlength={12} />
        <Buttons busy={action.busy} onCancel={() => (dialog = undefined)} />
      </Form>
    </Dialog>
  {:else if dialog === "mail-grant"}
    <Dialog title={t("Grant access to the mail")} onClose={() => (dialog = undefined)}>
      <Form
        submit={(field, all) => {
          const [kind, grantee] = principal(field("who"));
          void change(
            () =>
              need(
                admin.PUT("/v1/accounts/{id}/mail/access", {
                  params: path,
                  body: {
                    grantee_kind: kind,
                    grantee_id: grantee,
                    rights: field("rights"),
                    mailbox: field("mailbox") || null,
                    send_as: all("send_as").length > 0,
                  },
                }),
              ),
            t("Access granted."),
            () => ((dialog = undefined), void mailAccess.refetch()),
          );
        }}
      >
        <PrincipalSelect name="who" label={t("Who")} />
        <Select label={t("May")} name="rights" value="lrswite" options={MAIL_LEVELS.map(([rights, label]) => [rights, t(label)])} />
        <Select
          label={t("Where")}
          name="mailbox"
          options={[["", t("all mailboxes")], ...(mailView?.mailboxes ?? []).map((box): [string, string] => [box.id, box.name])]}
        />
        <Check label={t("may send as this address")} name="send_as" hint={t("all mailboxes only")} />
        <Buttons busy={action.busy} onCancel={() => (dialog = undefined)} label={t("Grant")} />
      </Form>
    </Dialog>
  {:else if dialog === "file-grant"}
    <Dialog title={t("Grant access to the files")} onClose={() => (dialog = undefined)}>
      <p class="muted">{t("For all files of the account. Single folders are shared in Files.")}</p>
      <Form
        submit={(field) => {
          const [kind, grantee] = principal(field("who"));
          void change(
            () =>
              need(
                admin.PUT("/v1/accounts/{id}/files/access", {
                  params: path,
                  body: { grantee_kind: kind, grantee_id: grantee, rights: field("rights") },
                }),
              ),
            t("Access granted."),
            () => ((dialog = undefined), void fileAccess.refetch()),
          );
        }}
      >
        <PrincipalSelect name="who" label={t("Who")} />
        <Select label={t("May")} name="rights" value="rnadw" options={FILE_LEVELS.map(([rights, label]) => [rights, t(label)])} />
        <Buttons busy={action.busy} onCancel={() => (dialog = undefined)} label={t("Grant")} />
      </Form>
    </Dialog>
  {/if}
{:else if account.error}
  <Failure error={account.error} />
{:else}
  <p class="muted">{t("Loading")}</p>
{/if}
