<!-- SPDX-License-Identifier: MIT -->
# kernoid-sync

A folder kept in step with a file store of [kernoid](https://kernoid.dev) – the file sync of kernoid's apps, on
[`kernoid-client`](../client). Whatever shows the files – a folder, the system's file manager through a native shell –
decides nothing itself; what changed, what to download and what conflicts is decided here.

```rust
let mut folder = kernoid_sync::Folder::open("/home/alice/kernoid", &store, &data_dir.join("files.db"))?;
let report = folder.sync(&client).await?; // again after every push of `FileNode`
let report = folder.sync_with(&client, Some(&mut e2e)).await?; // vaults too, with the account's key unlocked
```

- **Changes** from the store's journal (`FileNode/changes`); the whole store when there is no state yet or it is too
  old. The folder is scanned; size and modification time tell a change.
- **Conflicts:** a file changed on both sides keeps the server's version under its name and the local one as a copy
  beside it (`notes (conflict 2026-10-30 1412).txt`), which goes up in the next round – never merged, never lost.
- **Deletions** carry over – on the server into the store's trash –, but never take a change of the other side along.
- **Moves** stay moves: a node moved on the server (its id at another path) is moved here, a file moved here (its
  inode at another path, size and time unchanged) is moved on the server – it keeps its versions and shares and is not
  sent again. Not into or out of a vault, and not on Windows yet (no file ids read there).
- **Transfers** go on after a break: a download from where it stopped (an HTTP range), a file over 8 MiB up in pieces
  joined on the server (`Blob/upload`, RFC 9404) – the pieces sent are not sent again while the file is unchanged and
  the server still keeps them (a day).
- **Vaults** (end-to-end encrypted folders, RFC 0006) with the account's key: names and contents decrypted here,
  encrypted before they go. While a vault's key is not at hand, the vault is left as it is on both sides.
- **Names** a file system cannot hold are left out (`Report::skipped`): on Windows its reserved names and characters,
  and where case does not tell names apart (Windows, macOS) a second name differing only in case.
- **State** in SQLite (built in), outside the folder.

OPEN: content hashes; vault contents in pieces (a file there is encrypted in memory); file ids on Windows.

MIT – see [LICENSE](LICENSE).
