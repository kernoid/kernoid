// SPDX-License-Identifier: MIT
// The pictures of the tenant's accounts (GET /v1/avatars): loaded once, again after one's own changes; Avatar.svelte
// finds a person's picture by address. Who has none shows initials.

interface AvatarEntry {
  account: string;
  version: string;
  addresses: string[];
}

const known = $state<{ byAddress: Record<string, string>; byAccount: Record<string, string> }>({ byAddress: {}, byAccount: {} });

export async function loadAvatars(): Promise<void> {
  try {
    const response = await fetch("/v1/avatars", { credentials: "same-origin", headers: { accept: "application/json" } });
    if (!response.ok) return;
    const list = (await response.json()) as AvatarEntry[];
    const byAddress: Record<string, string> = {};
    const byAccount: Record<string, string> = {};
    for (const entry of list) {
      const url = `/v1/avatars/${encodeURIComponent(entry.account)}?v=${encodeURIComponent(entry.version)}`;
      byAccount[entry.account] = url;
      for (const address of entry.addresses) byAddress[address.toLowerCase()] = url;
    }
    known.byAddress = byAddress;
    known.byAccount = byAccount;
  } catch {
    // Without the list everyone shows initials.
  }
}

export function avatarOfAddress(address: string | null | undefined): string | undefined {
  return address ? known.byAddress[address.toLowerCase()] : undefined;
}

export function avatarOfAccount(account: string | null | undefined): string | undefined {
  return account ? known.byAccount[account] : undefined;
}

/** A picture made square and small in the browser – the middle of it, 256 pixels, as JPEG – before it goes up. */
export async function squareImage(file: File, size = 256): Promise<Blob> {
  const bitmap = await createImageBitmap(file);
  const side = Math.min(bitmap.width, bitmap.height);
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const context = canvas.getContext("2d");
  if (!context) throw new Error("no canvas");
  context.drawImage(bitmap, (bitmap.width - side) / 2, (bitmap.height - side) / 2, side, side, 0, 0, size, size);
  bitmap.close();
  return new Promise((resolve, reject) =>
    canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error("the picture could not be made"))), "image/jpeg", 0.9),
  );
}

export async function setAvatar(picture: Blob): Promise<void> {
  const response = await fetch("/v1/account/avatar", {
    method: "PUT",
    credentials: "same-origin",
    headers: { "content-type": picture.type || "image/jpeg", "kernoid-csrf": "1" },
    body: picture,
  });
  if (!response.ok) {
    const problem = (await response.json().catch(() => ({}))) as { detail?: string; title?: string };
    throw new Error(problem.detail ?? problem.title ?? `${response.status}`);
  }
  await loadAvatars();
}

export async function removeAvatar(): Promise<void> {
  const response = await fetch("/v1/account/avatar", { method: "DELETE", credentials: "same-origin", headers: { "kernoid-csrf": "1" } });
  if (!response.ok) throw new Error(`${response.status}`);
  await loadAvatars();
}
