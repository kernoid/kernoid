// SPDX-License-Identifier: MIT
import 'package:kernoid_ui/ui.dart';

import '../app/format.dart';

import 'package:kernoid_l10n/l10n/app_localizations.dart';

/// An error with the chance to try again.
class ErrorView extends StatelessWidget {
  const ErrorView({super.key, required this.error, required this.onRetry});

  final Object error;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(l.error(errorText(error)), textAlign: TextAlign.center),
            const SizedBox(height: 12),
            KButton(onPressed: onRetry, label: l.retry),
          ],
        ),
      ),
    );
  }
}

/// A quiet line where nothing is to show.
class EmptyView extends StatelessWidget {
  const EmptyView(this.text, {super.key, this.icon});

  final String text;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final color = context.k.muted;
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) Icon(icon, size: 40, color: color),
          if (icon != null) const SizedBox(height: 8),
          Text(text, style: TextStyle(color: color)),
        ],
      ),
    );
  }
}
