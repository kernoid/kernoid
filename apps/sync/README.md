<!-- SPDX-License-Identifier: MIT -->
# kernoid-sync

A folder kept in step with a file store of [kernoid](https://kernoid.dev) – the file sync of kernoid's apps, on
[`kernoid-client`](../client). Whatever shows the files – a folder, the system's file manager through a native shell –
decides nothing itself; what changed, what to download and what conflicts is decided here.

```rust
let mut folder = kernoid_sync::Folder::open("/home/alice/kernoid", &store, &data_dir.join("files.db"))?;
let report = folder.sync(&client).await?; // again after every push of `FileNode`
```

- **Changes** from the store's journal (`FileNode/changes`); the whole store when there is no state yet or it is too
  old. The folder is scanned; size and modification time tell a change.
- **Conflicts:** a file changed on both sides keeps the server's version under its name and the local one as a copy
  beside it (`notes (conflict 2026-10-30 1412).txt`), which goes up in the next round – never merged, never lost.
- **Deletions** carry over – on the server into the store's trash –, but never take a change of the other side along.
- **State** in SQLite (built in), outside the folder.

OPEN: moves as moves (today a deletion and a creation), transfers resumed after an interruption (RFC 9404), content
hashes, vaults (end-to-end encrypted folders), the name rules of Windows.

MIT – see [LICENSE](LICENSE).
