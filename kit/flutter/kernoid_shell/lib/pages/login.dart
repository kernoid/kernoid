// SPDX-License-Identifier: MIT
import 'dart:io';
import 'dart:math';

import 'package:flutter/services.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import '../app/format.dart';

import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_ui/ui.dart';

/// Where the browser comes back: the app's own scheme on Apple's systems and Android, a loopback address on a port of
/// our choosing on desktops (RFC 8252, 7.1 and 7.3).
(String, String) _redirect() {
  if (Platform.isIOS || Platform.isMacOS || Platform.isAndroid) {
    return ('dev.kernoid.kernoid:/oauth', 'dev.kernoid.kernoid');
  }
  final port = 49152 + Random.secure().nextInt(16000);
  return ('http://127.0.0.1:$port/oauth', 'http://127.0.0.1:$port');
}

/// A login with OpenID Connect in the system's browser – for the app, or a separate one for a shell of the system
/// (Explorer's files), which renews its own refresh token. Throws `PlatformException` with `CANCELED` when the user
/// closes the browser.
Future<Kernoid> signInWithBrowser(String server, String? address) async {
  final (redirect, scheme) = _redirect();
  final login = await Kernoid.beginLogin(server: server, redirectUri: redirect, address: address);
  final callback = await FlutterWebAuth2.authenticate(url: login.url, callbackUrlScheme: scheme);
  return Kernoid.finishLogin(login: login, callback: callback);
}

/// Signing in: with OpenID Connect in the system's browser – kernoid's login page, with a passkey, a password or a
/// second factor –, or with an address and an app password. A login with OpenID Connect is kept and resumed at start
/// (`app/kept_login.dart`); one with an app password is not.
class LoginPage extends StatefulWidget {
  const LoginPage({super.key, required this.onSignedIn, this.notice});

  final ValueChanged<Kernoid> onSignedIn;

  /// Why the kept login could not be resumed, if it could not.
  final String? notice;

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final _form = GlobalKey<FormState>();
  final _server = TextEditingController();
  final _address = TextEditingController();
  final _password = TextEditingController();
  bool _busy = false;
  late String? _error = widget.notice;

  @override
  void dispose() {
    _server.dispose();
    _address.dispose();
    _password.dispose();
    super.dispose();
  }

  Future<void> _signInWithBrowser() async {
    final l = AppLocalizations.of(context);
    if (_server.text.trim().isEmpty) {
      setState(() => _error = '${l.server}: ${l.required}');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final address = _address.text.trim();
      final account = await signInWithBrowser(_server.text, address.isEmpty ? null : address);
      widget.onSignedIn(account);
    } on PlatformException catch (error) {
      setState(() => _error = error.code == 'CANCELED' ? l.signInCancelled : error.message ?? error.code);
    } catch (error) {
      setState(() => _error = errorText(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _signIn() async {
    if (!_form.currentState!.validate()) return;
    if (_address.text.trim().isEmpty) {
      setState(() => _error = '${AppLocalizations.of(context).address}: ${AppLocalizations.of(context).required}');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final account = await Kernoid.login(server: _server.text, address: _address.text, password: _password.text);
      _password.clear();
      widget.onSignedIn(account);
    } on KernoidError catch (error) {
      // The server says only that it did not accept them – the same for a wrong address and a wrong password.
      setState(() => _error = error.unauthorized ? AppLocalizations.of(context).appPasswordWrong : errorText(error));
    } catch (error) {
      setState(() => _error = errorText(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    String? required(String? v) => (v == null || v.trim().isEmpty) ? l.required : null;
    return KScaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 380),
            child: Form(
              key: _form,
              child: AutofillGroup(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    const Align(alignment: AlignmentDirectional.centerStart, child: KWordmark(size: 26)),
                    const SizedBox(height: 8),
                    Text(l.signInTitle, style: KText.heading(context.k)),
                    const SizedBox(height: 24),
                    KTextFormField(
                      key: const ValueKey('server'),
                      controller: _server,
                      label: l.server,
                      hint: l.serverHint,
                      keyboardType: TextInputType.url,
                      autocorrect: false,
                      validator: required,
                    ),
                    const SizedBox(height: 12),
                    KTextFormField(
                      key: const ValueKey('address'),
                      controller: _address,
                      label: l.address,
                      keyboardType: TextInputType.emailAddress,
                      autocorrect: false,
                      autofillHints: const [AutofillHints.username, AutofillHints.email],
                    ),
                    const SizedBox(height: 20),
                    KButton(
                      key: const ValueKey('sign-in-browser'),
                      tone: KTone.primary,
                      expand: true,
                      onPressed: _signInWithBrowser,
                      busy: _busy,
                      icon: LucideIcons.keyRound,
                      label: l.signInBrowser,
                    ),
                    const SizedBox(height: 6),
                    Text(l.signInBrowserHint, style: KText.small(context.k)),
                    const SizedBox(height: 24),
                    Row(
                      children: [
                        const Expanded(child: KDivider()),
                        Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 8),
                          child: Text(l.orAppPassword, style: KText.small(context.k)),
                        ),
                        const Expanded(child: KDivider()),
                      ],
                    ),
                    const SizedBox(height: 12),
                    KTextFormField(
                      key: const ValueKey('password'),
                      controller: _password,
                      label: l.appPassword,
                      helper: l.appPasswordHint,
                      obscureText: true,
                      autofillHints: const [AutofillHints.password],
                      validator: required,
                      onSubmitted: (_) => _signIn(),
                    ),
                    if (_error != null) ...[
                      const SizedBox(height: 12),
                      Text(_error!, style: TextStyle(color: context.k.error)),
                    ],
                    const SizedBox(height: 24),
                    KButton(
                      key: const ValueKey('sign-in'),
                      onPressed: _busy ? null : _signIn,
                      label: l.signInAppPassword,
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
