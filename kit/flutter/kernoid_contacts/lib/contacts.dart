// SPDX-License-Identifier: MIT
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_ui/ui.dart';
import 'package:kernoid_shell/widgets/states.dart';
import 'package:kernoid_shell/app/format.dart';
import 'package:kernoid_mail/compose.dart';

import 'contact_form.dart';
import 'l10n/contacts_text.dart';

/// The contacts of every address book the account reaches, with search; contacts are made, changed and deleted, and a
/// contact's addresses start an email.
class ContactsPage extends StatefulWidget {
  const ContactsPage({super.key, required this.account});

  final Kernoid account;

  @override
  State<ContactsPage> createState() => _ContactsPageState();
}

class _ContactsPageState extends State<ContactsPage> {
  final _search = TextEditingController();
  Timer? _debounce;
  List<Contact>? _contacts;
  Object? _error;
  int _asked = 0;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _debounce?.cancel();
    _search.dispose();
    super.dispose();
  }

  /// Loads the contacts for what the search says; only the latest answer counts.
  Future<void> _load() async {
    final ask = ++_asked;
    setState(() => _error = null);
    try {
      final contacts = await widget.account.contacts(search: _search.text);
      if (mounted && ask == _asked) setState(() => _contacts = contacts);
    } catch (error) {
      if (mounted && ask == _asked) setState(() => _error = error);
    }
  }

  void _searchChanged(String _) {
    _debounce?.cancel();
    _debounce = Timer(const Duration(milliseconds: 300), _load);
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return KScaffold(
      topBar: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          KTopBar(title: l.contactsText.contacts),
          Container(
            color: context.k.panel,
            padding: const EdgeInsets.fromLTRB(12, 8, 12, 8),
            child: KTextField(
              key: const ValueKey('contacts-search'),
              controller: _search,
              hint: l.contactsText.searchContacts,
              icon: LucideIcons.search,
              onChanged: _searchChanged,
              fill: context.k.raised,
              borderless: true,
              textInputAction: TextInputAction.search,
            ),
          ),
        ],
      ),
      body: _body(l),
      floating: KFloatingButton(
        key: const ValueKey('new-contact'),
        tooltip: l.contactsText.newContact,
        onPressed: () => _show(ContactFormPage(account: widget.account), dialog: true),
        icon: LucideIcons.userPlus,
      ),
    );
  }

  /// Opens a page; anything saved or deleted there loads the list again.
  Future<void> _show(Widget page, {bool dialog = false}) async {
    final changed = await Navigator.of(context).push<bool>(KPageRoute(fullscreenDialog: dialog, builder: (_) => page));
    if (changed ?? false) _load();
  }

  Widget _body(AppLocalizations l) {
    if (_error != null) return ErrorView(error: _error!, onRetry: _load);
    final contacts = _contacts;
    if (contacts == null) return const Center(child: KSpinner());
    if (contacts.isEmpty) return EmptyView(l.contactsText.noContacts, icon: LucideIcons.userSearch);
    return KRefresh(
      onRefresh: _load,
      child: ListView.builder(
        itemCount: contacts.length,
        itemBuilder: (context, i) {
          final c = contacts[i];
          final details = c.organization ?? c.emails.firstOrNull?.value ?? c.phones.firstOrNull?.value;
          return KListRow(
            leading: KAvatar(name: c.name),
            title: Text(c.name),
            subtitle: details == null ? null : Text(details),
            onTap: () => _show(ContactPage(account: widget.account, contact: c)),
          );
        },
      ),
    );
  }
}

/// `Email · work`: what it is, and its labels.
String _labelled(AppLocalizations l, String kind, List<String> labels) =>
    [kind, ...labels.map((label) => labelName(l, label))].join(' · ');

/// One contact: organisation, addresses – each starts an email –, phone numbers to copy, notes. Pops `true` when it
/// was changed or deleted.
class ContactPage extends StatelessWidget {
  const ContactPage({super.key, required this.account, required this.contact});

  final Kernoid account;
  final Contact contact;

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final c = contact;
    Future<void> edit() async {
      final saved = await Navigator.of(context).push<bool>(
        KPageRoute(
          fullscreenDialog: true,
          builder: (_) => ContactFormPage(account: account, contact: c),
        ),
      );
      if ((saved ?? false) && context.mounted) Navigator.of(context).pop(true);
    }

    Future<void> delete() async {
      final messenger = KToast.of(context);
      final sure = await showKDialog<bool>(
        context,
        builder: (context) => KDialog(
          content: Text(l.contactsText.deleteContactConfirm),
          actions: [
            KButton(tone: KTone.quiet, onPressed: () => Navigator.of(context).pop(false), label: l.cancel),
            KButton(
              tone: KTone.primary,
              key: const ValueKey('confirm-delete'),
              onPressed: () => Navigator.of(context).pop(true),
              label: l.delete,
            ),
          ],
        ),
      );
      if (!(sure ?? false)) return;
      try {
        await account.deleteContact(accountId: c.accountId, contactId: c.id);
        messenger.show(l.deleted);
        if (context.mounted) Navigator.of(context).pop(true);
      } catch (error) {
        messenger.show(l.error(errorText(error)));
      }
    }

    return KScaffold(
      topBar: KTopBar(
        title: c.name,
        actions: [
          KIconButton(key: const ValueKey('edit-contact'), tooltip: l.edit, onPressed: edit, icon: LucideIcons.pencil),
          KIconButton(
            key: const ValueKey('delete-contact'),
            tooltip: l.delete,
            onPressed: delete,
            icon: LucideIcons.trash2,
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Center(child: KAvatar(name: c.name, size: 72)),
          const SizedBox(height: 8),
          Center(child: Text(c.name, style: KText.title(context.k))),
          if (c.organization != null) Center(child: Text(c.organization!)),
          const SizedBox(height: 16),
          for (final email in c.emails)
            KListRow(
              leading: const Icon(LucideIcons.mail),
              title: Text(email.value),
              subtitle: Text(_labelled(l, l.contactsText.emails, email.labels)),
              trailing: KIconButton(
                key: ValueKey('write-to-${email.value}'),
                tooltip: l.contactsText.writeEmail,
                icon: LucideIcons.send,
                onPressed: () => writeMessage(context, account, to: email.value),
              ),
            ),
          for (final phone in c.phones)
            KListRow(
              leading: const Icon(LucideIcons.phone),
              title: Text(phone.value),
              subtitle: Text(_labelled(l, l.contactsText.phones, phone.labels)),
              trailing: KIconButton(
                tooltip: l.copy,
                icon: LucideIcons.copy,
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: phone.value));
                  KToast.of(context).show(l.copied);
                },
              ),
            ),
          if (c.notes.isNotEmpty) ...[
            const SizedBox(height: 16),
            Text(l.contactsText.notes, style: KText.heading(context.k).copyWith(fontSize: 14)),
            for (final note in c.notes) Padding(padding: const EdgeInsets.only(top: 4), child: KSelectable.text(note)),
          ],
        ],
      ),
    );
  }
}
