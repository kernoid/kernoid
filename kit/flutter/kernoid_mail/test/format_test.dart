// SPDX-License-Identifier: MIT
import 'package:flutter_test/flutter_test.dart';
import 'package:kernoid_shell/app/format.dart';
import 'package:kernoid_mail/compose.dart';
import 'package:kernoid_shell/widgets/e2e.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';

void main() {
  test('people are named by name, else by address', () {
    expect(person(const Address(name: 'Alice', email: 'a@x.example')), 'Alice');
    expect(person(const Address(name: '  ', email: 'b@x.example')), 'b@x.example');
    expect(people(const [Address(email: 'a@x'), Address(name: 'Bob', email: 'b@x')]), 'a@x, Bob');
  });

  test('sizes are short', () {
    expect(bytes(512), '512 B');
    expect(bytes(1500), '1.5 KB');
    expect(bytes(25000000), '25 MB');
  });

  test('addresses are found in what was typed', () {
    expect(addresses('Bob <bob@x.example>, carol@x.example; "d@x" <d@x.example>, "Doe, J." <j@x.example>, no'), [
      'bob@x.example',
      'carol@x.example',
      'd@x.example',
      'j@x.example',
    ]);
  });

  test('fingerprints are grouped by four', () {
    expect(groupedFingerprint('abcd1234ef'), 'ABCD 1234 EF');
  });
}
