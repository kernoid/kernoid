// SPDX-License-Identifier: MIT
// The WebAssembly build as the web app uses it: a keyring that makes a key, protects and unlocks it, and encrypts
// mail as PGP/MIME – the same code as apps/e2e's own tests, here through its JavaScript bindings.
import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import { initSync, isEncrypted, Keyring, normalizeRecoveryCode, recoveryCode } from '../dist/kernoid_e2e.js';

beforeAll(() => {
  initSync({ module: readFileSync(new URL('../dist/kernoid_e2e_bg.wasm', import.meta.url)) });
});

const mail = new TextEncoder().encode(
  'From: ada@example.org\r\nTo: bob@example.org\r\nSubject: The plan\r\n\r\nMeet at noon.\r\n',
);

describe('@kernoid/e2e', () => {
  it('makes, protects and unlocks a post-quantum key', () => {
    const ring = new Keyring();
    const fingerprint = ring.generate('pqc', ['ada@example.org']);
    expect(ring.kind(fingerprint)).toBe('pqc');
    expect(ring.addresses(fingerprint)).toEqual(['ada@example.org']);
    const code = recoveryCode();
    const copy = ring.protect(fingerprint, code);
    const other = new Keyring();
    expect(() => other.unlock(copy, 'wrong')).toThrow();
    expect(other.unlock(copy, normalizeRecoveryCode(code.toLowerCase()))).toBe(fingerprint);
  });

  it('encrypts mail for a recipient and verifies the sender', () => {
    const ada = new Keyring();
    const bob = new Keyring();
    const adaKey = ada.generate('pqc', ['ada@example.org']);
    const bobKey = bob.generate('compatible', ['bob@example.org']);
    ada.addPublic(bob.publicKey(bobKey));
    bob.addPublic(ada.publicKey(adaKey));

    const encrypted = ada.encryptMessage(mail, [bobKey], adaKey);
    expect(isEncrypted(encrypted)).toBe(true);
    expect(new TextDecoder().decode(encrypted)).toContain('Subject: [...]');

    const opened = bob.decryptMessage(encrypted, [adaKey]);
    expect(new TextDecoder().decode(opened.data)).toContain('Subject: The plan');
    expect(opened.signed).toBe(true);
    expect(opened.verifiedBy).toBe(adaKey);

    const summary = JSON.parse(bob.decryptSummary(ada.encryptedSummary(mail, [bobKey])));
    expect(summary).toEqual({ subject: 'The plan', preview: 'Meet at noon.', hasAttachment: false });
  });
});
