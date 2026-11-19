// SPDX-License-Identifier: MIT

import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'package:kernoid_shell/app/format.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_ui/ui.dart';

import 'l10n/contacts_text.dart';

/// Making or changing a contact: name, organisation, addresses and numbers – each with its labels (work, private, and
/// for a number what it is) –, a note. Pops `true` once saved.
class ContactFormPage extends StatefulWidget {
  const ContactFormPage({super.key, required this.account, this.contact});

  final Kernoid account;

  /// The contact changed; none for a new one.
  final Contact? contact;

  @override
  State<ContactFormPage> createState() => _ContactFormPageState();
}

class _ContactFormPageState extends State<ContactFormPage> {
  final _form = GlobalKey<FormState>();
  late final _name = TextEditingController(text: widget.contact?.name ?? '');
  late final _organization = TextEditingController(text: widget.contact?.organization ?? '');
  late final _emails = [for (final v in widget.contact?.emails ?? const <LabelledValue>[]) _Row.of(v)];
  late final _phones = [for (final v in widget.contact?.phones ?? const <LabelledValue>[]) _Row.of(v)];
  late final _note = TextEditingController(text: widget.contact?.notes.join('\n') ?? '');
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    for (final c in [
      _name,
      _organization,
      _note,
      for (final row in [..._emails, ..._phones]) row.text,
    ]) {
      c.dispose();
    }
    super.dispose();
  }

  List<LabelledValue> _values(List<_Row> rows) => [
    for (final row in rows)
      if (row.text.text.trim().isNotEmpty) LabelledValue(value: row.text.text.trim(), labels: row.labels.toList()),
  ];

  Future<void> _save() async {
    if (!_form.currentState!.validate()) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.account.saveContact(
        accountId: widget.contact?.accountId,
        contactId: widget.contact?.id,
        draft: ContactDraft(
          name: _name.text,
          organization: _organization.text,
          emails: _values(_emails),
          phones: _values(_phones),
          note: _note.text,
        ),
      );
      if (mounted) Navigator.of(context).pop(true);
    } catch (error) {
      if (mounted) setState(() => _error = errorText(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return KScaffold(
      topBar: KTopBar(
        title: widget.contact == null ? l.contactsText.newContact : l.contactsText.editContact,
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 8),
            child: KButton(
              tone: KTone.primary,
              key: const ValueKey('save-contact'),
              onPressed: _busy ? null : _save,
              label: l.save,
            ),
          ),
        ],
      ),
      body: Form(
        key: _form,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            KTextFormField(
              key: const ValueKey('contact-name'),
              controller: _name,
              autofocus: widget.contact == null,
              label: l.name,
              validator: (v) => (v ?? '').trim().isEmpty ? l.required : null,
            ),
            const SizedBox(height: 8),
            KTextFormField(
              key: const ValueKey('contact-organization'),
              controller: _organization,
              label: l.contactsText.organization,
            ),
            const SizedBox(height: 8),
            _LabelledFields(
              kind: 'email',
              title: l.contactsText.emailsField,
              add: l.contactsText.addEmail,
              rows: _emails,
              allowed: Kernoid.emailLabels(),
              keyboard: TextInputType.emailAddress,
              icon: LucideIcons.mail,
              validator: (v) => (v ?? '').trim().isNotEmpty && !v!.contains('@') ? l.contactsText.emailsField : null,
              onChanged: () => setState(() {}),
            ),
            const SizedBox(height: 8),
            _LabelledFields(
              kind: 'phone',
              title: l.contactsText.phonesField,
              add: l.contactsText.addPhone,
              rows: _phones,
              allowed: Kernoid.phoneLabels(),
              keyboard: TextInputType.phone,
              icon: LucideIcons.phone,
              onChanged: () => setState(() {}),
            ),
            const SizedBox(height: 8),
            KTextFormField(
              key: const ValueKey('contact-note'),
              controller: _note,
              minLines: 2,
              maxLines: 6,
              label: l.contactsText.note,
            ),
            if (_error != null) ...[
              const SizedBox(height: 12),
              Text(_error!, style: TextStyle(color: context.k.error)),
            ],
          ],
        ),
      ),
    );
  }
}

/// One address or number being written, with its labels.
class _Row {
  _Row(String value, Iterable<String> labels) : text = TextEditingController(text: value), labels = {...labels};

  _Row.of(LabelledValue v) : this(v.value, v.labels);

  final TextEditingController text;
  final Set<String> labels;
}

/// What a label is called in the user's language.
String labelName(AppLocalizations l, String label) => switch (label) {
  'work' => l.contactsText.labelWork,
  'private' => l.contactsText.labelPrivate,
  'mobile' => l.contactsText.labelMobile,
  'voice' => l.contactsText.labelVoice,
  'text' => l.contactsText.labelText,
  'video' => l.contactsText.labelVideo,
  'fax' => l.contactsText.labelFax,
  'pager' => l.contactsText.labelPager,
  'textphone' => l.contactsText.labelTextphone,
  _ => label,
};

/// Addresses or numbers, one field each with a menu of its labels; rows are added and removed.
class _LabelledFields extends StatelessWidget {
  const _LabelledFields({
    required this.kind,
    required this.title,
    required this.add,
    required this.rows,
    required this.allowed,
    required this.keyboard,
    required this.icon,
    required this.onChanged,
    this.validator,
  });

  /// `email` or `phone`, for the keys of the fields.
  final String kind;
  final String title;
  final String add;
  final List<_Row> rows;
  final List<String> allowed;
  final TextInputType keyboard;
  final IconData icon;
  final VoidCallback onChanged;
  final FormFieldValidator<String>? validator;

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(title, style: KText.heading(context.k).copyWith(fontSize: 14)),
        for (final (i, row) in rows.indexed)
          Row(
            children: [
              Icon(icon, size: 20),
              const SizedBox(width: 12),
              Expanded(
                child: KTextFormField(
                  key: ValueKey('contact-$kind-$i'),
                  controller: row.text,
                  keyboardType: keyboard,
                  validator: validator,
                ),
              ),
              KMenuButton<String>(
                key: ValueKey('contact-$kind-$i-labels'),
                tooltip: l.contactsText.labels,
                onSelected: (label) {
                  if (!row.labels.remove(label)) row.labels.add(label);
                  onChanged();
                },
                items: () => [
                  for (final label in allowed)
                    KMenuItem(value: label, label: labelName(l, label), checked: row.labels.contains(label)),
                ],
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 12),
                  child: Text(
                    row.labels.isEmpty
                        ? l.contactsText.labels
                        : row.labels.map((label) => labelName(l, label)).join(', '),
                    style: TextStyle(color: context.k.accent),
                  ),
                ),
              ),
              KIconButton(
                tooltip: l.remove,
                icon: LucideIcons.x,
                onPressed: () {
                  rows.removeAt(i).text.dispose();
                  onChanged();
                },
              ),
            ],
          ),
        KButton(
          tone: KTone.quiet,
          key: ValueKey('add-$kind'),
          onPressed: () {
            rows.add(_Row('', const []));
            onChanged();
          },
          icon: LucideIcons.plus,
          label: add,
        ),
      ],
    );
  }
}
