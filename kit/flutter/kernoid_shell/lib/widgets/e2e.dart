// SPDX-License-Identifier: MIT

import 'package:flutter/services.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import '../app/format.dart';

import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_ui/ui.dart';

/// Asks for the recovery code and unlocks the key with it. True once unlocked. **OPEN**: unlocking with a passkey
/// (PRF) and a copy for this device in the system's key store (docs/plan.md, 6).
Future<bool> unlockKey(BuildContext context, Kernoid account) async {
  final unlocked = await showKDialog<bool>(context, builder: (_) => _UnlockDialog(account: account));
  return unlocked ?? false;
}

class _UnlockDialog extends StatefulWidget {
  const _UnlockDialog({required this.account});

  final Kernoid account;

  @override
  State<_UnlockDialog> createState() => _UnlockDialogState();
}

class _UnlockDialogState extends State<_UnlockDialog> {
  final _code = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _code.dispose();
    super.dispose();
  }

  Future<void> _unlock() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.account.unlockKey(code: _code.text);
      if (mounted) Navigator.of(context).pop(true);
    } catch (error) {
      setState(() => _error = errorText(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return KDialog(
      title: l.unlock,
      content: SizedBox(
        width: 380,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(l.e2eLocked),
            const SizedBox(height: 12),
            KTextField(
              key: const ValueKey('recovery-code'),
              controller: _code,
              autofocus: true,
              autocorrect: false,
              style: KText.mono(context.k).copyWith(fontSize: 15, color: context.k.text),
              label: l.recoveryCode,
              error: _error,
              onSubmitted: (_) => _unlock(),
            ),
          ],
        ),
      ),
      actions: [
        KButton(tone: KTone.quiet, onPressed: _busy ? null : () => Navigator.of(context).pop(false), label: l.cancel),
        KButton(key: const ValueKey('unlock'), tone: KTone.primary, onPressed: _unlock, busy: _busy, label: l.unlock),
      ],
    );
  }
}

/// Shows the recovery code of a new key once; closes only when the user says they kept it.
Future<void> showRecoveryCode(BuildContext context, String code) {
  return showKDialog<void>(context, dismissible: false, builder: (_) => _RecoveryDialog(code: code));
}

class _RecoveryDialog extends StatefulWidget {
  const _RecoveryDialog({required this.code});

  final String code;

  @override
  State<_RecoveryDialog> createState() => _RecoveryDialogState();
}

class _RecoveryDialogState extends State<_RecoveryDialog> {
  bool _kept = false;

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return KDialog(
      title: l.recoveryTitle,
      content: SizedBox(
        width: 420,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(l.recoveryBody),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(color: context.k.hover, borderRadius: BorderRadius.circular(8)),
              child: KSelectable.text(
                widget.code,
                key: const ValueKey('the-recovery-code'),
                style: KText.heading(context.k).copyWith(fontFamily: KFont.mono, letterSpacing: 1.2),
              ),
            ),
            Align(
              alignment: Alignment.centerRight,
              child: KButton(
                tone: KTone.quiet,
                onPressed: () async {
                  final messenger = KToast.of(context);
                  await Clipboard.setData(ClipboardData(text: widget.code));
                  messenger.show(l.copied);
                },
                icon: LucideIcons.copy,
                label: l.copy,
              ),
            ),
            KToggleRow(
              key: const ValueKey('recovery-kept'),
              value: _kept,
              onChanged: (v) => setState(() => _kept = v),
              title: Text(l.recoveryKept),
              checkbox: true,
            ),
          ],
        ),
      ),
      actions: [
        KButton(
          tone: KTone.primary,
          key: const ValueKey('recovery-done'),
          onPressed: _kept ? () => Navigator.of(context).pop() : null,
          label: l.done,
        ),
      ],
    );
  }
}

/// A fingerprint in groups of four, as people compare it.
String groupedFingerprint(String hex) {
  final upper = hex.toUpperCase();
  final groups = [for (var i = 0; i < upper.length; i += 4) upper.substring(i, (i + 4).clamp(0, upper.length))];
  return groups.join(' ');
}

/// How an end-to-end encrypted email was opened: a line under its header.
class SealBadge extends StatelessWidget {
  const SealBadge({super.key, required this.email});

  final Email email;

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final signature = !email.signed
        ? l.notSigned
        : email.verified
        ? l.signatureVerified
        : l.signatureUnverified;
    final good = email.signed && email.verified;
    return Wrap(
      spacing: 8,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        Icon(LucideIcons.lock, size: 16, color: context.k.accent),
        Text(l.e2eEncrypted, style: TextStyle(color: context.k.accent)),
        Text('·', style: TextStyle(color: context.k.muted)),
        Icon(
          good ? LucideIcons.badgeCheck : LucideIcons.circleHelp,
          size: 16,
          color: good ? context.k.accent : context.k.error,
        ),
        Text(signature, style: TextStyle(color: good ? context.k.muted : context.k.error)),
      ],
    );
  }
}
