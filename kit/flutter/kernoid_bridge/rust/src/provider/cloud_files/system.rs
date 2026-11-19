// SPDX-License-Identifier: MIT
//! What calls Windows in the Cloud Files shell: sync roots, placeholders, the callbacks of the platform, the scan for
//! what changed in Explorer, and DPAPI for the shell's login. The flow is described in the module above.
//!
//! The shell runs in the app's process while the app is open (**OPEN**: a small provider started at login, plan
//! section 5). Every callback answers on a thread of its own (`CfExecute` may come later than the callback returns),
//! so that a fetch never holds up the platform's thread.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::mem::{offset_of, size_of};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{Value, json};
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, HLOCAL, LocalFree, NTSTATUS, STATUS_ACCESS_DENIED, STATUS_CLOUD_FILE_UNSUCCESSFUL,
    STATUS_SUCCESS,
};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::Win32::Storage::CloudFilters::{
    CF_CALLBACK_DELETE_FLAG_IS_UNDELETE, CF_CALLBACK_DELETE_FLAGS, CF_CALLBACK_INFO, CF_CALLBACK_PARAMETERS,
    CF_CALLBACK_REGISTRATION, CF_CALLBACK_TYPE_FETCH_DATA, CF_CALLBACK_TYPE_NONE, CF_CALLBACK_TYPE_NOTIFY_DELETE,
    CF_CALLBACK_TYPE_NOTIFY_RENAME, CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, CF_CONNECTION_KEY,
    CF_CONVERT_FLAG_MARK_IN_SYNC, CF_CREATE_FLAG_NONE, CF_FS_METADATA, CF_HARDLINK_POLICY_NONE, CF_HYDRATION_POLICY,
    CF_HYDRATION_POLICY_FULL, CF_HYDRATION_POLICY_MODIFIER_NONE, CF_IN_SYNC_STATE_IN_SYNC, CF_INSYNC_POLICY_TRACK_ALL,
    CF_OPERATION_INFO, CF_OPERATION_PARAMETERS, CF_OPERATION_PARAMETERS_0, CF_OPERATION_PARAMETERS_0_0,
    CF_OPERATION_PARAMETERS_0_6, CF_OPERATION_PARAMETERS_0_7, CF_OPERATION_TYPE, CF_OPERATION_TYPE_ACK_DELETE,
    CF_OPERATION_TYPE_ACK_RENAME, CF_OPERATION_TYPE_TRANSFER_DATA,
    CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION, CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC,
    CF_PLACEHOLDER_CREATE_INFO, CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT, CF_PLACEHOLDER_STATE,
    CF_PLACEHOLDER_STATE_IN_SYNC, CF_PLACEHOLDER_STATE_PARTIAL, CF_PLACEHOLDER_STATE_PLACEHOLDER, CF_POPULATION_POLICY,
    CF_POPULATION_POLICY_ALWAYS_FULL, CF_POPULATION_POLICY_MODIFIER_NONE,
    CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT, CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT,
    CF_REGISTER_FLAG_UPDATE, CF_SYNC_POLICIES, CF_SYNC_REGISTRATION, CF_UPDATE_FLAG_DEHYDRATE,
    CF_UPDATE_FLAG_MARK_IN_SYNC, CF_UPDATE_FLAG_VERIFY_IN_SYNC, CfConnectSyncRoot, CfConvertToPlaceholder,
    CfCreatePlaceholders, CfDisconnectSyncRoot, CfExecute, CfGetPlaceholderStateFromAttributeTag, CfRegisterSyncRoot,
    CfReportProviderProgress, CfSetInSyncState, CfUnregisterSyncRoot, CfUpdatePlaceholder,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_TEMPORARY,
    FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES, FindClose, FindFirstFileW, OPEN_EXISTING, WIN32_FIND_DATAW, WRITE_DAC,
};
use windows::core::{GUID, HSTRING, PCWSTR, w};

use super::{Disk, Item, LOGIN_FILE, Root, STATUS, folder_names, ignored, join, normal, within};

/// How often kernoid is asked what changed, and Explorer's folders are looked through.
const ROUND: Duration = Duration::from_secs(60);
/// Content is handed to the platform in pieces of this size (a multiple of 4 KiB, as `CfExecute` requires).
const CHUNK: usize = 4 << 20;
/// A file changed in Explorer more recently than this is left for the next round: a program may still write it.
const SETTLE: Duration = Duration::from_secs(10);
/// kernoid's provider id at the platform (`CF_SYNC_REGISTRATION::ProviderId`).
const PROVIDER_ID: GUID = GUID::from_u128(0x6b1f_2c4e_9d3a_4f7b_8e21_5a0c_d4e3_b917);

/// Why the shell could not do something; `unauthorized`: its login has ended and must be set up again.
#[derive(Debug)]
pub(crate) struct Failure {
    pub message: String,
    pub unauthorized: bool,
}

impl Failure {
    fn new(message: impl Into<String>) -> Failure {
        Failure { message: message.into(), unauthorized: false }
    }
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Failure::new(error.to_string())
    }
}

impl From<windows::core::Error> for Failure {
    fn from(error: windows::core::Error) -> Self {
        Failure::new(error.message())
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The shell's session with the core, and where its login is kept: every renewal the core reports (`kept`) replaces
/// it there, protected with DPAPI for the user.
#[derive(Debug)]
struct Core {
    session: u64,
    login: PathBuf,
    keeping: Mutex<()>,
}

fn ask(request: &Value) -> Result<Value, Failure> {
    let answer: Value = serde_json::from_str(&crate::provider::call(&request.to_string()))
        .map_err(|e| Failure::new(format!("the core answered no JSON: {e}")))?;
    if let Some(ok) = answer.get("ok") {
        return Ok(ok.clone());
    }
    let error = &answer["error"];
    Err(Failure {
        message: error["message"].as_str().unwrap_or("the core failed").to_owned(),
        unauthorized: error["unauthorized"].as_bool().unwrap_or(false),
    })
}

impl Core {
    fn open(kept: &str, login: PathBuf) -> Result<Core, Failure> {
        let answer = ask(&json!({ "op": "open", "kept": kept }))?;
        let session = answer["session"].as_u64().ok_or_else(|| Failure::new("the core opened no session"))?;
        let core = Core { session, login, keeping: Mutex::new(()) };
        // Opening renewed the login: what was handed in is used up.
        core.keep(answer["kept"].as_str().unwrap_or(kept));
        Ok(core)
    }

    fn call(&self, mut request: Value) -> Result<Value, Failure> {
        request["session"] = json!(self.session);
        let answer = ask(&request)?;
        if let Some(kept) = answer.get("kept").and_then(Value::as_str) {
            self.keep(kept);
        }
        Ok(answer)
    }

    fn keep(&self, kept: &str) {
        let _keeping = lock(&self.keeping);
        let written = protect(kept.as_bytes()).and_then(|data| {
            let staged = self.login.with_extension("new");
            fs::write(&staged, data).and_then(|()| fs::rename(&staged, &self.login)).map_err(|e| e.to_string())
        });
        if let Err(problem) = written {
            report(format!("the login could not be kept: {problem}"));
        }
    }
}

/// Protects data for the signed-in Windows user (DPAPI).
fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|e| e.to_string())?,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    // SAFETY: `input` points to `data` for the call; `output` is filled by the system and freed in `taken`.
    unsafe { CryptProtectData(&input, w!("kernoid"), None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut output) }
        .map_err(|e| e.message())?;
    Ok(taken(output))
}

fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|e| e.to_string())?,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    // SAFETY: as in `protect`.
    unsafe { CryptUnprotectData(&input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut output) }
        .map_err(|e| e.message())?;
    Ok(taken(output))
}

/// Copies a blob the system allocated and frees it.
fn taken(blob: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    if blob.pbData.is_null() {
        return Vec::new();
    }
    // SAFETY: DPAPI returned `cbData` bytes at `pbData`, allocated with LocalAlloc and freed here once.
    unsafe {
        let data = std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec();
        LocalFree(Some(HLOCAL(blob.pbData.cast())));
        data
    }
}

/// A store connected as a sync root – what its callbacks reach through their context.
#[derive(Debug)]
struct Shared {
    core: Arc<Core>,
    root: Mutex<Root>,
    /// Where `root` is kept between starts.
    file: PathBuf,
    /// Where fetched content waits until it is handed over.
    temp: PathBuf,
    /// Paths the shell itself changes at the moment: their notifications are not sent back to kernoid.
    guard: Mutex<Vec<String>>,
}

impl Shared {
    fn root(&self) -> MutexGuard<'_, Root> {
        lock(&self.root)
    }

    fn save(&self, root: &Root) {
        let written = serde_json::to_vec(root).map_err(|e| e.to_string()).and_then(|data| {
            let staged = self.file.with_extension("new");
            fs::write(&staged, data).and_then(|()| fs::rename(&staged, &self.file)).map_err(|e| e.to_string())
        });
        if let Err(problem) = written {
            report(format!("{}: the state could not be kept: {problem}", root.path));
        }
    }

    fn guarded(&self, path: &str) -> bool {
        lock(&self.guard).iter().any(|g| within(path, g))
    }
}

/// Runs a change of the shell's own with its paths guarded.
fn guarding<T>(
    guard: &Mutex<Vec<String>>,
    paths: &[&str],
    change: impl FnOnce() -> std::io::Result<T>,
) -> Result<T, String> {
    let marks: Vec<String> = paths.iter().map(|p| normal(p)).collect();
    lock(guard).extend(marks.iter().cloned());
    let result = change();
    let mut guard = lock(guard);
    for mark in &marks {
        if let Some(at) = guard.iter().position(|g| g == mark) {
            guard.remove(at);
        }
    }
    result.map_err(|e| e.to_string())
}

#[derive(Debug)]
struct Connected {
    key: CF_CONNECTION_KEY,
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Provider {
    core: Arc<Core>,
    roots: Vec<Connected>,
    stop: mpsc::Sender<()>,
    rounds: Option<JoinHandle<()>>,
}

static PROVIDER: LazyLock<Mutex<Option<Provider>>> = LazyLock::new(Mutex::default);
/// The folders of all connected stores, to refuse moves from one store into another.
static FOLDERS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Notes a problem for the app to show (the newest 20).
fn report(problem: String) {
    let mut status = lock(&STATUS);
    status.problems.push(problem);
    let excess = status.problems.len().saturating_sub(20);
    status.problems.drain(..excess);
}

/// Shows the stores in Explorer: with `kept` a login of the shell's own (set up just now), else the one kept in
/// `state_dir`. Returns the folders. Started already: the folders as they are.
pub(crate) fn start(kept: Option<&str>, root_dir: &str, state_dir: &str) -> Result<Vec<String>, Failure> {
    let mut provider = lock(&PROVIDER);
    if provider.is_some() {
        return Ok(lock(&STATUS).folders.clone());
    }
    let state = PathBuf::from(state_dir);
    fs::create_dir_all(&state)?;
    let login = state.join(LOGIN_FILE);
    let kept = match kept {
        Some(kept) => kept.to_owned(),
        None => {
            let data = fs::read(&login).map_err(|_| Failure { message: "not set up".into(), unauthorized: true })?;
            let data = unprotect(&data).map_err(Failure::new)?;
            String::from_utf8(data).map_err(|e| Failure::new(e.to_string()))?
        }
    };
    let core = match Core::open(&kept, login.clone()) {
        Ok(core) => Arc::new(core),
        Err(failure) => {
            if failure.unauthorized {
                let _ = fs::remove_file(&login);
            }
            return Err(failure);
        }
    };
    let temp = state.join("fetch");
    fs::create_dir_all(&temp)?;
    let mut roots = Vec::new();
    if let Err(failure) = connect_all(&core, root_dir, &state, &temp, &mut roots) {
        disconnect(&roots);
        let _ = core.call(json!({ "op": "close" }));
        return Err(failure);
    }
    let folders: Vec<String> = roots.iter().map(|c| c.shared.root().path.clone()).collect();
    *lock(&FOLDERS) = folders.clone();
    {
        let mut status = lock(&STATUS);
        *status = super::Status { running: true, folders: folders.clone(), ..super::Status::default() };
    }
    let (stop, stopped) = mpsc::channel();
    let shared: Vec<Arc<Shared>> = roots.iter().map(|c| c.shared.clone()).collect();
    let rounds =
        std::thread::Builder::new().name("kernoid-cloud-files".into()).spawn(move || run(&shared, &stopped))?;
    *provider = Some(Provider { core, roots, stop, rounds: Some(rounds) });
    Ok(folders)
}

fn connect_all(
    core: &Arc<Core>,
    root_dir: &str,
    state: &Path,
    temp: &Path,
    roots: &mut Vec<Connected>,
) -> Result<(), Failure> {
    let answer = core.call(json!({ "op": "stores" }))?;
    let stores: Vec<(String, String)> = answer["stores"]
        .as_array()
        .map(|stores| {
            stores.iter().filter_map(|s| Some((s["id"].as_str()?.to_owned(), s["name"].as_str()?.to_owned()))).collect()
        })
        .unwrap_or_default();
    for ((store, _), name) in stores.iter().zip(folder_names(&stores)) {
        let file = state.join(format!("{}.json", safe(store)));
        let root = fs::read(&file)
            .ok()
            .and_then(|data| serde_json::from_slice::<Root>(&data).ok())
            .filter(|root| root.store == *store)
            .unwrap_or_else(|| Root::new(store, &join(root_dir, &name)));
        fs::create_dir_all(&root.path)?;
        register(&root)?;
        let shared = Arc::new(Shared {
            core: core.clone(),
            root: Mutex::new(root),
            file,
            temp: temp.to_path_buf(),
            guard: Mutex::default(),
        });
        let key = connect(&shared)?;
        roots.push(Connected { key, shared });
    }
    Ok(())
}

/// A store's id as a file name.
fn safe(store: &str) -> String {
    store.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

/// Stops the shell; with `forget` also unregisters the sync roots and drops the state and the login – the folders
/// stay, with what was downloaded.
pub(crate) fn stop(state_dir: &str, forget: bool) -> Result<(), Failure> {
    let provider = lock(&PROVIDER).take();
    let mut folders = Vec::new();
    if let Some(mut provider) = provider {
        let _ = provider.stop.send(());
        if let Some(rounds) = provider.rounds.take() {
            let _ = rounds.join();
        }
        disconnect(&provider.roots);
        folders.extend(provider.roots.iter().map(|c| c.shared.root().path.clone()));
        let _ = provider.core.call(json!({ "op": "close" }));
    }
    lock(&FOLDERS).clear();
    lock(&STATUS).running = false;
    if !forget {
        return Ok(());
    }
    let state = PathBuf::from(state_dir);
    if let Ok(entries) = fs::read_dir(&state) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json") {
                if let Some(root) = fs::read(&path).ok().and_then(|d| serde_json::from_slice::<Root>(&d).ok()) {
                    folders.push(root.path);
                }
                let _ = fs::remove_file(&path);
            }
        }
    }
    folders.sort();
    folders.dedup();
    for folder in &folders {
        // SAFETY: a plain call with a path that lives through it.
        if let Err(error) = unsafe { CfUnregisterSyncRoot(&HSTRING::from(folder.as_str())) } {
            report(format!("{folder}: {}", error.message()));
        }
    }
    let _ = fs::remove_dir_all(state.join("fetch"));
    let _ = fs::remove_file(state.join(LOGIN_FILE));
    *lock(&STATUS) = super::Status::default();
    Ok(())
}

fn disconnect(roots: &[Connected]) {
    for connected in roots {
        // SAFETY: a key `CfConnectSyncRoot` gave; its context (`shared`) lives until after this.
        let _ = unsafe { CfDisconnectSyncRoot(connected.key) };
    }
}

fn register(root: &Root) -> Result<(), Failure> {
    let (name, version) = (HSTRING::from("kernoid"), HSTRING::from(env!("CARGO_PKG_VERSION")));
    let identity = root.store.as_bytes();
    let registration = CF_SYNC_REGISTRATION {
        StructSize: size_of::<CF_SYNC_REGISTRATION>() as u32,
        ProviderName: PCWSTR(name.as_ptr()),
        ProviderVersion: PCWSTR(version.as_ptr()),
        SyncRootIdentity: identity.as_ptr().cast(),
        SyncRootIdentityLength: u32::try_from(identity.len()).map_err(|e| Failure::new(e.to_string()))?,
        FileIdentity: std::ptr::null(),
        FileIdentityLength: 0,
        ProviderId: PROVIDER_ID,
    };
    // The shell places every item itself, so the platform never asks for a folder's content (FETCH_PLACEHOLDERS);
    // a file's content is fetched whole before it opens.
    let policies = CF_SYNC_POLICIES {
        StructSize: size_of::<CF_SYNC_POLICIES>() as u32,
        Hydration: CF_HYDRATION_POLICY {
            Primary: CF_HYDRATION_POLICY_FULL,
            Modifier: CF_HYDRATION_POLICY_MODIFIER_NONE,
        },
        Population: CF_POPULATION_POLICY {
            Primary: CF_POPULATION_POLICY_ALWAYS_FULL,
            Modifier: CF_POPULATION_POLICY_MODIFIER_NONE,
        },
        InSync: CF_INSYNC_POLICY_TRACK_ALL,
        HardLink: CF_HARDLINK_POLICY_NONE,
        PlaceholderManagement: CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT,
    };
    let flags = CF_REGISTER_FLAG_UPDATE
        | CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT
        | CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT;
    // SAFETY: the structures and the strings they point to live through the call.
    unsafe { CfRegisterSyncRoot(&HSTRING::from(root.path.as_str()), &registration, &policies, flags) }?;
    Ok(())
}

static CALLBACKS: [CF_CALLBACK_REGISTRATION; 4] = [
    CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_FETCH_DATA, Callback: Some(on_fetch_data) },
    CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_NOTIFY_DELETE, Callback: Some(on_delete) },
    CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_NOTIFY_RENAME, Callback: Some(on_rename) },
    CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_NONE, Callback: None },
];

fn connect(shared: &Arc<Shared>) -> Result<CF_CONNECTION_KEY, Failure> {
    let path = HSTRING::from(shared.root().path.as_str());
    let context = Arc::as_ptr(shared).cast::<std::ffi::c_void>();
    // SAFETY: the table is static; the context is kept alive by `Connected` until after `CfDisconnectSyncRoot`, and
    // the callbacks take their own reference before they leave the platform's thread.
    let key =
        unsafe { CfConnectSyncRoot(&path, CALLBACKS.as_ptr(), Some(context), CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH) }?;
    Ok(key)
}

/// One round after another until the shell is stopped.
fn run(roots: &[Arc<Shared>], stopped: &mpsc::Receiver<()>) {
    loop {
        lock(&STATUS).problems.clear();
        for shared in roots {
            if let Err(failure) = round(shared) {
                if failure.unauthorized {
                    let mut status = lock(&STATUS);
                    status.signed_out = true;
                    status.problems.push(failure.message);
                    return;
                }
                report(format!("{}: {}", shared.root().path, failure.message));
            }
        }
        lock(&STATUS).last_round = Some(jiff::Timestamp::now().to_string());
        match stopped.recv_timeout(ROUND) {
            Err(RecvTimeoutError::Timeout) => {}
            _ => return,
        }
    }
}

/// A round for one store: what changed at kernoid placed, then what changed in Explorer uploaded.
fn round(shared: &Shared) -> Result<(), Failure> {
    let store = shared.root().store.clone();
    loop {
        let since = shared.root().anchor.clone();
        let answer = shared.core.call(json!({ "op": "changes", "store": store, "since": since }))?;
        if answer["expired"].as_bool().unwrap_or(false) {
            let mut root = shared.root();
            root.anchor.clear();
            continue;
        }
        let items: Vec<Item> = serde_json::from_value(answer["items"].clone())
            .map_err(|e| Failure::new(format!("items the shell cannot read: {e}")))?;
        let deleted: Vec<String> = serde_json::from_value(answer["deleted"].clone()).unwrap_or_default();
        let reset = answer["reset"].as_bool().unwrap_or(false);
        // Held while the disk changes: notifications of the user's own wait for it, the shell's own pass the guard.
        let mut root = shared.root();
        let failed = root.apply(&items, &deleted, reset, &mut Placeholders { guard: &shared.guard });
        root.anchor =
            if failed.is_empty() { answer["anchor"].as_str().unwrap_or_default().to_owned() } else { String::new() };
        shared.save(&root);
        let path = root.path.clone();
        drop(root);
        for problem in &failed {
            report(format!("{path}: {problem}"));
        }
        if !failed.is_empty() || !answer["more"].as_bool().unwrap_or(false) {
            break;
        }
    }
    let path = shared.root().path.clone();
    scan(shared, &path, None);
    Ok(())
}

/// The disk of [`Root::apply`]: placeholders.
struct Placeholders<'a> {
    guard: &'a Mutex<Vec<String>>,
}

fn metadata(item: &Item) -> CF_FS_METADATA {
    let time = item.filetime();
    let attributes = match (item.directory, item.rights.write) {
        (true, _) => FILE_ATTRIBUTE_DIRECTORY,
        (false, true) => FILE_ATTRIBUTE_NORMAL,
        (false, false) => FILE_ATTRIBUTE_READONLY,
    };
    CF_FS_METADATA {
        BasicInfo: FILE_BASIC_INFO {
            CreationTime: time,
            LastAccessTime: time,
            LastWriteTime: time,
            ChangeTime: time,
            FileAttributes: attributes.0,
        },
        FileSize: if item.directory { 0 } else { i64::try_from(item.size).unwrap_or(i64::MAX) },
    }
}

impl Disk for Placeholders<'_> {
    fn create(&mut self, dir: &str, item: &Item) -> Result<(), String> {
        let name = HSTRING::from(item.name.as_str());
        let mut flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
        if item.directory {
            flags |= CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION;
        }
        let mut info = [CF_PLACEHOLDER_CREATE_INFO {
            RelativeFileName: PCWSTR(name.as_ptr()),
            FsMetadata: metadata(item),
            FileIdentity: item.id.as_ptr().cast(),
            FileIdentityLength: u32::try_from(item.id.len()).map_err(|e| e.to_string())?,
            Flags: flags,
            Result: windows::core::HRESULT(0),
            CreateUsn: 0,
        }];
        // SAFETY: the name and the identity live through the call.
        unsafe { CfCreatePlaceholders(&HSTRING::from(dir), &mut info, CF_CREATE_FLAG_NONE, None) }
            .map_err(|e| e.message())?;
        info[0].Result.ok().map_err(|e| e.message())
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), String> {
        guarding(self.guard, &[from, to], || fs::rename(from, to))
    }

    fn replace(&mut self, path: &str, item: &Item) -> Result<(), String> {
        let handle = open(path)?;
        let metadata = metadata(item);
        // Dropped only while in sync: content changed here as well is kept and uploaded by the scan (**OPEN**: keep
        // both versions, as kernoid-sync does).
        let flags = CF_UPDATE_FLAG_MARK_IN_SYNC | CF_UPDATE_FLAG_DEHYDRATE | CF_UPDATE_FLAG_VERIFY_IN_SYNC;
        // SAFETY: an open handle and metadata that live through the call.
        unsafe { CfUpdatePlaceholder(handle.0, Some(&metadata), None, 0, None, flags, None, None) }
            .map_err(|e| e.message())
    }

    fn delete(&mut self, path: &str, directory: bool) -> Result<(), String> {
        guarding(self.guard, &[path], || if directory { fs::remove_dir_all(path) } else { fs::remove_file(path) })
    }
}

/// A handle closed when dropped.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: a handle `CreateFileW` gave, closed once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Opens a file or folder to change it as a placeholder, without reading or writing its content.
fn open(path: &str) -> Result<Handle, String> {
    // SAFETY: a plain call with a path that lives through it.
    unsafe {
        CreateFileW(
            &HSTRING::from(path),
            (FILE_WRITE_ATTRIBUTES | WRITE_DAC).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .map(Handle)
    .map_err(|e| e.message())
}

/// What the file system says of a path: its attributes and its state as a placeholder.
fn look(path: &str) -> Option<(u32, CF_PLACEHOLDER_STATE)> {
    let mut data = WIN32_FIND_DATAW::default();
    // SAFETY: plain calls; the search handle is closed at once.
    unsafe {
        let search = FindFirstFileW(&HSTRING::from(path), &mut data).ok()?;
        let _ = FindClose(search);
        Some((data.dwFileAttributes, CfGetPlaceholderStateFromAttributeTag(data.dwFileAttributes, data.dwReserved0)))
    }
}

/// Looks through a folder of a sync root for what changed in Explorer: new files and folders are uploaded and become
/// placeholders, changed files are uploaded again. Problems are reported and tried again in the next round.
fn scan(shared: &Shared, dir: &str, parent: Option<String>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if ignored(&name) || !super::windows_name(&name) {
            continue;
        }
        let path = join(dir, &name);
        let Some((attributes, state)) = look(&path) else { continue };
        if attributes & FILE_ATTRIBUTE_TEMPORARY.0 != 0 {
            continue;
        }
        let directory = attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
        let settled = entry
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|modified| modified.elapsed().unwrap_or_default() > SETTLE);
        let known = shared.root().child(parent.as_deref(), &name);
        let result = match known {
            Some(id) if !state.contains(CF_PLACEHOLDER_STATE_PLACEHOLDER) => convert(&path, &id).map(|()| Some(id)),
            Some(id)
                if !directory
                    && settled
                    && !state.contains(CF_PLACEHOLDER_STATE_IN_SYNC)
                    && !state.contains(CF_PLACEHOLDER_STATE_PARTIAL) =>
            {
                upload_again(shared, &id, &path).map(|()| Some(id))
            }
            Some(id) => Ok(Some(id)),
            // A placeholder the shell did not place here (moved in from elsewhere): left alone (**OPEN**).
            None if state.contains(CF_PLACEHOLDER_STATE_PLACEHOLDER) => Ok(None),
            None if !settled && !directory => Ok(None),
            None => upload_new(shared, parent.as_deref(), &name, &path, directory).map(Some),
        };
        match result {
            Ok(Some(id)) if directory => scan(shared, &path, Some(id)),
            Ok(_) => {}
            Err(problem) => report(format!("{path}: {problem}")),
        }
    }
}

fn convert(path: &str, id: &str) -> Result<(), String> {
    let handle = open(path)?;
    let length = u32::try_from(id.len()).map_err(|e| e.to_string())?;
    // SAFETY: an open handle and an identity that lives through the call.
    unsafe {
        CfConvertToPlaceholder(handle.0, Some(id.as_ptr().cast()), length, CF_CONVERT_FLAG_MARK_IN_SYNC, None, None)
    }
    .map_err(|e| e.message())
}

fn upload_new(
    shared: &Shared,
    parent: Option<&str>,
    name: &str,
    path: &str,
    directory: bool,
) -> Result<String, String> {
    let store = shared.root().store.clone();
    let mut request = json!({ "op": "create", "store": store, "parent": parent, "name": name, "directory": directory });
    if !directory {
        request["from"] = json!(path);
    }
    let answer = shared.core.call(request).map_err(|f| f.message)?;
    let item: Item = serde_json::from_value(answer["item"].clone()).map_err(|e| e.to_string())?;
    {
        let mut root = shared.root();
        root.place(&item);
        shared.save(&root);
    }
    // Placed even when converting fails: the next round converts it, never uploads it twice.
    convert(path, &item.id)?;
    Ok(item.id)
}

fn upload_again(shared: &Shared, id: &str, path: &str) -> Result<(), String> {
    let store = shared.root().store.clone();
    let answer =
        shared.core.call(json!({ "op": "modify", "store": store, "id": id, "from": path })).map_err(|f| f.message)?;
    let item: Item = serde_json::from_value(answer["item"].clone()).map_err(|e| e.to_string())?;
    {
        let mut root = shared.root();
        root.place(&item);
        shared.save(&root);
    }
    let handle = open(path)?;
    // SAFETY: an open handle. **OPEN**: a change while uploading is marked in sync too (`InSyncUsn`).
    unsafe { CfSetInSyncState(handle.0, CF_IN_SYNC_STATE_IN_SYNC, Default::default(), None) }.map_err(|e| e.message())
}

/// What a callback needs after it returned: the keys to answer with, the item, its path, the store.
struct Request {
    key: CF_CONNECTION_KEY,
    transfer: i64,
    request: i64,
    id: String,
    path: String,
    volume: String,
    shared: Arc<Shared>,
}

fn text(text: PCWSTR) -> String {
    if text.is_null() {
        return String::new();
    }
    // SAFETY: the platform's strings are NUL-terminated and valid during the callback.
    unsafe { text.to_string() }.unwrap_or_default()
}

/// Copies what the callback info holds for later.
///
/// # Safety
/// `info` must be the platform's callback info, valid for the call; its context a `Shared` kept alive by `Connected`.
unsafe fn request(info: *const CF_CALLBACK_INFO) -> Option<Request> {
    // SAFETY: valid for the call, as the caller promises.
    let info = unsafe { info.as_ref()? };
    let context = info.CallbackContext.cast_const().cast::<Shared>();
    if context.is_null() {
        return None;
    }
    // SAFETY: the context is an `Arc<Shared>` alive while connected; a reference of the callback's own is taken.
    let shared = unsafe {
        Arc::increment_strong_count(context);
        Arc::from_raw(context)
    };
    let id = if info.FileIdentity.is_null() {
        String::new()
    } else {
        // SAFETY: `FileIdentityLength` bytes at `FileIdentity`, valid for the call.
        let bytes =
            unsafe { std::slice::from_raw_parts(info.FileIdentity.cast::<u8>(), info.FileIdentityLength as usize) };
        String::from_utf8_lossy(bytes).into_owned()
    };
    let volume = text(info.VolumeDosName);
    Some(Request {
        key: info.ConnectionKey,
        transfer: info.TransferKey,
        request: info.RequestKey,
        path: format!("{volume}{}", text(info.NormalizedPath)),
        id,
        volume,
        shared,
    })
}

fn execute(r: &Request, kind: CF_OPERATION_TYPE, mut parameters: CF_OPERATION_PARAMETERS) -> Result<(), String> {
    let info = CF_OPERATION_INFO {
        StructSize: size_of::<CF_OPERATION_INFO>() as u32,
        Type: kind,
        ConnectionKey: r.key,
        TransferKey: r.transfer,
        CorrelationVector: std::ptr::null(),
        SyncStatus: std::ptr::null(),
        RequestKey: r.request,
    };
    // SAFETY: both structures live through the call; a buffer in them is valid for its length.
    unsafe { CfExecute(&info, &mut parameters) }.map_err(|e| e.message())
}

/// `ParamSize` as `CF_SIZE_OF_OP_PARAM` computes it: up to the end of the member used.
fn param_size<T>() -> u32 {
    (offset_of!(CF_OPERATION_PARAMETERS, Anonymous) + size_of::<T>()) as u32
}

fn transfer(r: &Request, status: NTSTATUS, buffer: *const u8, offset: i64, length: i64) -> Result<(), String> {
    let parameters = CF_OPERATION_PARAMETERS {
        ParamSize: param_size::<CF_OPERATION_PARAMETERS_0_0>(),
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            TransferData: CF_OPERATION_PARAMETERS_0_0 {
                Flags: Default::default(),
                CompletionStatus: status,
                Buffer: buffer.cast(),
                Offset: offset,
                Length: length,
            },
        },
    };
    execute(r, CF_OPERATION_TYPE_TRANSFER_DATA, parameters)
}

/// FETCH_DATA: a program opened a placeholder.
unsafe extern "system" fn on_fetch_data(info: *const CF_CALLBACK_INFO, parameters: *const CF_CALLBACK_PARAMETERS) {
    // SAFETY: the platform's pointers, valid for the call.
    let Some(request) = (unsafe { request(info) }) else { return };
    // SAFETY: as above; for FETCH_DATA the union holds `FetchData`.
    let Some(fetch) = (unsafe { parameters.as_ref() }).map(|p| unsafe { p.Anonymous.FetchData }) else { return };
    // SAFETY: as above.
    let size = unsafe { (*info).FileSize };
    std::thread::spawn(move || hydrate(&request, fetch.RequiredFileOffset, fetch.RequiredLength, size));
}

/// Fetches an item's content into a temporary file and hands it over from the offset asked for to its end.
fn hydrate(r: &Request, offset: i64, length: i64, size: i64) {
    let temp = r.shared.temp.join(format!("{}-{}.part", std::process::id(), r.transfer));
    let store = r.shared.root().store.clone();
    let fetched = r.shared.core.call(json!({
        "op": "fetch", "store": store, "id": r.id, "to": temp.to_string_lossy(),
    }));
    let handed = fetched.map_err(|f| f.message).and_then(|_| {
        let mut file = fs::File::open(&temp).map_err(|e| e.to_string())?;
        let length = i64::try_from(file.metadata().map_err(|e| e.to_string())?.len()).unwrap_or(i64::MAX);
        if length != size {
            return Err("it changed at kernoid – it is placed again within a minute".into());
        }
        file.seek(SeekFrom::Start(u64::try_from(offset).unwrap_or_default())).map_err(|e| e.to_string())?;
        let mut buffer = vec![0u8; CHUNK];
        let mut at = offset;
        while at < length {
            let piece = usize::try_from(length - at).unwrap_or(CHUNK).min(CHUNK);
            file.read_exact(&mut buffer[..piece]).map_err(|e| e.to_string())?;
            transfer(r, STATUS_SUCCESS, buffer.as_ptr(), at, piece as i64)?;
            at += piece as i64;
            // SAFETY: plain call with the keys of this fetch.
            let _ = unsafe { CfReportProviderProgress(r.key, r.transfer, length, at) };
        }
        Ok(())
    });
    let _ = fs::remove_file(&temp);
    if let Err(problem) = handed {
        report(format!("{}: {problem}", r.path));
        let _ = transfer(r, STATUS_CLOUD_FILE_UNSUCCESSFUL, std::ptr::null(), offset, length);
    }
}

/// NOTIFY_DELETE: a placeholder is to be deleted in Explorer – it goes into the store's Trash first.
unsafe extern "system" fn on_delete(info: *const CF_CALLBACK_INFO, parameters: *const CF_CALLBACK_PARAMETERS) {
    // SAFETY: the platform's pointers, valid for the call.
    let Some(request) = (unsafe { request(info) }) else { return };
    // SAFETY: as above; for NOTIFY_DELETE the union holds `Delete`.
    let flags = (unsafe { parameters.as_ref() }).map(|p| unsafe { p.Anonymous.Delete.Flags }).unwrap_or_default();
    std::thread::spawn(move || {
        let status = deleted(&request, flags);
        let parameters = CF_OPERATION_PARAMETERS {
            ParamSize: param_size::<CF_OPERATION_PARAMETERS_0_7>(),
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                AckDelete: CF_OPERATION_PARAMETERS_0_7 { Flags: Default::default(), CompletionStatus: status },
            },
        };
        if let Err(problem) = execute(&request, CF_OPERATION_TYPE_ACK_DELETE, parameters) {
            report(format!("{}: {problem}", request.path));
        }
    });
}

fn deleted(r: &Request, flags: CF_CALLBACK_DELETE_FLAGS) -> NTSTATUS {
    if r.id.is_empty() || flags.contains(CF_CALLBACK_DELETE_FLAG_IS_UNDELETE) || r.shared.guarded(&r.path) {
        return STATUS_SUCCESS;
    }
    trash(r)
}

/// Puts an item into its store's Trash and forgets it.
fn trash(r: &Request) -> NTSTATUS {
    let store = r.shared.root().store.clone();
    match r.shared.core.call(json!({ "op": "delete", "store": store, "id": r.id })) {
        Ok(_) => {
            let mut root = r.shared.root();
            root.remove(&r.id);
            r.shared.save(&root);
            STATUS_SUCCESS
        }
        Err(failure) => {
            report(format!("{}: {}", r.path, failure.message));
            STATUS_CLOUD_FILE_UNSUCCESSFUL
        }
    }
}

/// NOTIFY_RENAME: a placeholder is to be renamed or moved in Explorer – at kernoid first.
unsafe extern "system" fn on_rename(info: *const CF_CALLBACK_INFO, parameters: *const CF_CALLBACK_PARAMETERS) {
    // SAFETY: the platform's pointers, valid for the call.
    let Some(request) = (unsafe { request(info) }) else { return };
    // SAFETY: as above; for NOTIFY_RENAME the union holds `Rename`.
    let target = (unsafe { parameters.as_ref() }).map(|p| text(unsafe { p.Anonymous.Rename.TargetPath }));
    let target = format!("{}{}", request.volume, target.unwrap_or_default());
    std::thread::spawn(move || {
        let status = renamed(&request, &target);
        let parameters = CF_OPERATION_PARAMETERS {
            ParamSize: param_size::<CF_OPERATION_PARAMETERS_0_6>(),
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                AckRename: CF_OPERATION_PARAMETERS_0_6 { Flags: Default::default(), CompletionStatus: status },
            },
        };
        if let Err(problem) = execute(&request, CF_OPERATION_TYPE_ACK_RENAME, parameters) {
            report(format!("{}: {problem}", request.path));
        }
    });
}

fn renamed(r: &Request, target: &str) -> NTSTATUS {
    if r.id.is_empty() || r.shared.guarded(&r.path) {
        return STATUS_SUCCESS;
    }
    let folder = r.shared.root().path.clone();
    if !within(target, &folder) {
        // Into another store: refused – a copy goes (**OPEN**: moving between stores, as the app does).
        if lock(&FOLDERS).iter().any(|other| within(target, other)) {
            return STATUS_ACCESS_DENIED;
        }
        // Out of kernoid's folders, also into the Recycle Bin: into the store's Trash (**OPEN**: whether the platform
        // always hydrates a placeholder moved out first).
        return trash(r);
    }
    let Some((dir, name)) = target.trim_end_matches('\\').rsplit_once('\\') else { return STATUS_ACCESS_DENIED };
    let Some(parent) = r.shared.root().at(dir) else { return STATUS_CLOUD_FILE_UNSUCCESSFUL };
    let store = r.shared.root().store.clone();
    let change = json!({ "op": "modify", "store": store, "id": r.id, "name": name, "parent": parent });
    let item = r.shared.core.call(change).and_then(|answer| {
        serde_json::from_value::<Item>(answer["item"].clone()).map_err(|e| Failure::new(e.to_string()))
    });
    match item {
        Ok(item) => {
            let mut root = r.shared.root();
            root.place(&item);
            r.shared.save(&root);
            STATUS_SUCCESS
        }
        Err(failure) => {
            report(format!("{}: {}", r.path, failure.message));
            STATUS_CLOUD_FILE_UNSUCCESSFUL
        }
    }
}
