// SPDX-License-Identifier: MIT
import 'package:flutter_test/flutter_test.dart';
import 'package:kernoid_files/viewer.dart';

void main() {
  test('the viewer shows text, pictures and PDFs, and hands the rest on', () {
    expect(viewKindOf('text/plain', 'a.txt'), ViewKind.text);
    expect(viewKindOf('text/markdown; charset=utf-8', 'a.md'), ViewKind.text);
    expect(viewKindOf('application/json', 'a'), ViewKind.text);
    expect(viewKindOf(null, 'notes.md'), ViewKind.text);
    expect(viewKindOf('application/octet-stream', 'config.toml'), ViewKind.text);
    // HTML is not shown as text, nor run: it goes to another app.
    expect(viewKindOf('text/html', 'page.html'), ViewKind.other);
    expect(viewKindOf('image/png', 'a.png'), ViewKind.image);
    expect(viewKindOf(null, 'photo.JPG'), ViewKind.image);
    expect(viewKindOf('image/svg+xml', 'logo.svg'), ViewKind.other);
    expect(viewKindOf('application/pdf', 'a'), ViewKind.pdf);
    expect(viewKindOf(null, 'Handbuch.PDF'), ViewKind.pdf);
    expect(viewKindOf('video/mp4', 'a.mp4'), ViewKind.other);
    expect(viewKindOf('audio/mpeg', 'a.mp3'), ViewKind.other);
    expect(viewKindOf(null, 'archive'), ViewKind.other);
  });
}
