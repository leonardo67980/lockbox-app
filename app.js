const ACCOUNTS_KEY = "lockbox.accounts.v2";
const SYNC_SETTINGS_KEY = "lockbox.githubSync.v1";
const LEGACY_STORAGE_KEY = "lockbox.encryptedVault.v1";
const PBKDF2_ITERATIONS = 310000;

const state = {
  accountId: null,
  accountName: "",
  masterKey: null,
  vault: { entries: [], updatedAt: null },
  selectedId: null,
  editingId: null,
  generatorTarget: null,
  syncMode: "auth",
  activeFilter: "all",
  passwordVisible: false,
  sortAsc: true,
  lockTimer: null,
  timeoutMs: 900000
};

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();
const LEGACY_FERNET_SALT = enc.encode("password_manager_salt");

const authView = $("authView");
const vaultView = $("vaultView");
const authForm = $("authForm");
const authHint = $("authHint");
const accountNameInput = $("accountName");
const masterPassword = $("masterPassword");
const searchInput = $("searchInput");
const entryList = $("entryList");
const entryCount = $("entryCount");
const detailCard = $("detailCard");
const emptyState = $("emptyState");
const entryDialog = $("entryDialog");
const entryForm = $("entryForm");
const generatorDialog = $("generatorDialog");
const syncDialog = $("syncDialog");
const toast = $("toast");

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function base64UrlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return base64ToBytes(padded);
}

function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

function normalizeAccountName(name) {
  return name.trim().replace(/\s+/g, " ");
}

function accountIdFromName(name) {
  return normalizeAccountName(name).toLowerCase();
}

function getAccounts() {
  const raw = localStorage.getItem(ACCOUNTS_KEY);
  const data = raw ? JSON.parse(raw) : { version: 2, accounts: {} };
  return data.accounts ? data : { version: 2, accounts: {} };
}

function saveAccounts(data) {
  localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(data));
}

function getSyncSettings() {
  const raw = localStorage.getItem(SYNC_SETTINGS_KEY);
  return raw ? JSON.parse(raw) : {
    owner: "",
    repo: "",
    branch: "main",
    path: "vaults/{account}.lockbox.json",
    token: ""
  };
}

function saveSyncSettings(settings) {
  localStorage.setItem(SYNC_SETTINGS_KEY, JSON.stringify(settings));
}

function getAccount(nameOrId) {
  const accounts = getAccounts();
  return accounts.accounts[accountIdFromName(nameOrId)] || null;
}

function setAccountRecord(accountId, record) {
  const accounts = getAccounts();
  const existing = accounts.accounts[accountId];
  accounts.accounts[accountId] = {
    ...existing,
    record,
    updatedAt: new Date().toISOString()
  };
  saveAccounts(accounts);
}

function migrateLegacyVault() {
  const legacy = localStorage.getItem(LEGACY_STORAGE_KEY);
  const accounts = getAccounts();
  if (!legacy || Object.keys(accounts.accounts).length) return;
  accounts.accounts["principale"] = {
    id: "principale",
    name: "Principale",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    record: JSON.parse(legacy)
  };
  saveAccounts(accounts);
}

async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptVault(vault, key, existingSalt) {
  const salt = existingSalt || randomBytes(16);
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(JSON.stringify(vault))
  );
  return {
    version: 2,
    app: "Lockbox Password",
    kdf: "PBKDF2-SHA256",
    iterations: PBKDF2_ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    data: bytesToBase64(encrypted)
  };
}

async function decryptVault(record, password) {
  const salt = base64ToBytes(record.salt);
  const iv = base64ToBytes(record.iv);
  const key = await deriveKey(password, salt);
  const vault = await decryptVaultWithKey(record, key);
  return { key, vault };
}

async function decryptVaultWithKey(record, key) {
  const iv = base64ToBytes(record.iv);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    base64ToBytes(record.data)
  );
  return normalizeVault(JSON.parse(dec.decode(decrypted)));
}

async function decryptLegacyFernetBackup(token, password) {
  const raw = base64UrlToBytes(token.trim());
  if (raw[0] !== 0x80 || raw.length < 73) throw new Error("Invalid Fernet token");

  const signingInput = raw.slice(0, raw.length - 32);
  const signature = raw.slice(raw.length - 32);
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const derived = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: LEGACY_FERNET_SALT, iterations: 100000, hash: "SHA-256" },
      keyMaterial,
      256
    )
  );
  const signingKey = derived.slice(0, 16);
  const encryptionKey = derived.slice(16, 32);
  const hmacKey = await crypto.subtle.importKey("raw", signingKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, signingInput));
  if (!constantTimeEqual(signature, expected)) throw new Error("Invalid Fernet password");

  const iv = raw.slice(9, 25);
  const ciphertext = raw.slice(25, raw.length - 32);
  const aesKey = await crypto.subtle.importKey("raw", encryptionKey, "AES-CBC", false, ["decrypt"]);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aesKey, ciphertext));
  return dec.decode(plaintext);
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) diff |= a[index] ^ b[index];
  return diff === 0;
}

function legacyPasswordsToEntries(passwords) {
  const source = Array.isArray(passwords) ? passwords : Object.entries(passwords || {}).map(([id, value]) => ({ id, ...value }));
  const now = new Date().toISOString();
  return source.map((item) => ({
    id: crypto.randomUUID(),
    title: item.title || item.Titolo || "Importata",
    username: item.username || item.Username || "",
    password: item.password || item.Password || "",
    url: item.url || item.URL || item.site || "",
    notes: item.notes || item.Note || "",
    category: "Importate",
    favorite: false,
    createdAt: now,
    updatedAt: now
  }));
}

function normalizeVault(vault) {
  const entries = Array.isArray(vault.entries) ? vault.entries : [];
  return {
    entries: entries.map((entry) => ({
      id: entry.id || crypto.randomUUID(),
      title: entry.title || "Senza titolo",
      username: entry.username || "",
      password: entry.password || "",
      url: entry.url || "",
      notes: entry.notes || "",
      category: entry.category || "Personale",
      favorite: Boolean(entry.favorite),
      createdAt: entry.createdAt || entry.updatedAt || new Date().toISOString(),
      updatedAt: entry.updatedAt || new Date().toISOString()
    })),
    updatedAt: vault.updatedAt || new Date().toISOString()
  };
}

async function persistVault() {
  const current = getAccount(state.accountId);
  state.vault.updatedAt = new Date().toISOString();
  const salt = current?.record?.salt ? base64ToBytes(current.record.salt) : null;
  const record = await encryptVault(state.vault, state.masterKey, salt);
  setAccountRecord(state.accountId, record);
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("show"), 2400);
}

function normalizeUrl(url) {
  if (!url) return "";
  if (/^https?:\/\//i.test(url)) return url;
  return `https://${url}`;
}

function formatDate(value) {
  if (!value) return "";
  return new Intl.DateTimeFormat("it-IT", { day: "2-digit", month: "short", year: "numeric" }).format(new Date(value));
}

function scorePassword(password) {
  let score = 0;
  if (password.length >= 12) score += 1;
  if (password.length >= 18) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  return Math.min(score, 5);
}

function strengthInfo(password) {
  const score = scorePassword(password || "");
  const labels = ["Molto debole", "Debole", "Media", "Buona", "Forte", "Ottima"];
  const hints = [
    "Aggiungi una password piu lunga e complessa.",
    "Usa almeno 12 caratteri con numeri e simboli.",
    "Accettabile, ma conviene renderla piu lunga.",
    "Buona per la maggior parte degli account.",
    "Password robusta.",
    "Password molto robusta."
  ];
  return { score, label: labels[score], hint: hints[score] };
}

function isWeak(entry) {
  return scorePassword(entry.password || "") < 3;
}

function resetLockTimer() {
  window.clearTimeout(state.lockTimer);
  state.lockTimer = window.setTimeout(lockVault, state.timeoutMs);
}

function lockVault() {
  state.accountId = null;
  state.accountName = "";
  state.masterKey = null;
  state.vault = { entries: [], updatedAt: null };
  state.selectedId = null;
  state.passwordVisible = false;
  masterPassword.value = "";
  authView.classList.remove("hidden");
  vaultView.classList.add("hidden");
  window.clearTimeout(state.lockTimer);
  renderAccountOptions();
}

function unlockUi() {
  authView.classList.add("hidden");
  vaultView.classList.remove("hidden");
  $("currentAccountLabel").textContent = `Account: ${state.accountName}`;
  searchInput.value = "";
  renderEntries();
  resetLockTimer();
}

function renderAccountOptions() {
  const accounts = Object.values(getAccounts().accounts).sort((a, b) => a.name.localeCompare(b.name, "it"));
  $("accountList").innerHTML = accounts.map((account) => `<option value="${escapeHtml(account.name)}"></option>`).join("");
  $("accountPills").innerHTML = "";
  for (const account of accounts) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "account-pill";
    button.textContent = account.name;
    button.addEventListener("click", () => {
      accountNameInput.value = account.name;
      masterPassword.focus();
    });
    $("accountPills").appendChild(button);
  }
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value;
  return div.innerHTML;
}

function getFilteredEntries() {
  const term = searchInput.value.trim().toLowerCase();
  const entries = [...state.vault.entries].filter((entry) => {
    if (state.activeFilter === "favorites" && !entry.favorite) return false;
    if (state.activeFilter === "weak" && !isWeak(entry)) return false;
    if (state.activeFilter === "recent") {
      const age = Date.now() - new Date(entry.updatedAt || 0).getTime();
      if (age > 1000 * 60 * 60 * 24 * 30) return false;
    }
    if (!term) return true;
    return [entry.title, entry.username, entry.url, entry.notes, entry.category].some((value) =>
      (value || "").toLowerCase().includes(term)
    );
  });

  return entries.sort((a, b) => {
    const result = a.title.localeCompare(b.title, "it", { sensitivity: "base" });
    return state.sortAsc ? result : -result;
  });
}

function renderStats() {
  const entries = state.vault.entries;
  $("totalCount").textContent = entries.length;
  $("weakCount").textContent = entries.filter(isWeak).length;
  $("favoriteCount").textContent = entries.filter((entry) => entry.favorite).length;
}

function renderEntries() {
  renderStats();
  const entries = getFilteredEntries();
  entryCount.textContent = `${entries.length} ${entries.length === 1 ? "elemento" : "elementi"}`;
  entryList.innerHTML = "";

  if (!entries.length) {
    entryList.innerHTML = `<div class="empty-list"><h2>Nessun risultato</h2><p>Aggiungi una password o cambia filtro.</p></div>`;
  }

  for (const entry of entries) {
    const button = document.createElement("button");
    button.className = `entry-item${entry.id === state.selectedId ? " active" : ""}`;
    button.type = "button";
    button.setAttribute("aria-label", `${entry.title} ${entry.username} ${entry.url}`);
    button.innerHTML = `
      <span class="entry-icon"></span>
      <span class="entry-body">
        <span class="entry-title"></span>
        <span class="entry-subtitle"></span>
        <span class="entry-footer"><span class="entry-url"></span><span class="entry-tag"></span></span>
      </span>
    `;
    button.querySelector(".entry-icon").textContent = entry.title.slice(0, 1).toUpperCase();
    button.querySelector(".entry-title").textContent = `${entry.favorite ? "* " : ""}${entry.title}`;
    button.querySelector(".entry-subtitle").textContent = entry.username || "Nessun username";
    button.querySelector(".entry-url").textContent = entry.url || "Nessun URL";
    button.querySelector(".entry-tag").textContent = entry.category || "Personale";
    button.addEventListener("click", () => {
      state.selectedId = entry.id;
      state.passwordVisible = false;
      renderEntries();
      renderDetail();
    });
    entryList.appendChild(button);
  }

  renderDetail();
}

function selectedEntry() {
  return state.vault.entries.find((entry) => entry.id === state.selectedId) || null;
}

function renderDetail() {
  const entry = selectedEntry();
  if (!entry) {
    detailCard.classList.add("hidden");
    emptyState.classList.remove("hidden");
    return;
  }

  const strength = strengthInfo(entry.password);
  detailCard.classList.remove("hidden");
  emptyState.classList.add("hidden");
  $("detailUsername").textContent = entry.username || "senza username";
  $("detailTitle").textContent = entry.title;
  $("detailCategory").textContent = `${entry.category || "Personale"} - aggiornato ${formatDate(entry.updatedAt)}`;
  $("usernameValue").textContent = entry.username || "-";
  $("passwordValue").textContent = state.passwordVisible ? entry.password || "" : "************";
  $("passwordValue").classList.toggle("masked", !state.passwordVisible);
  $("revealButton").textContent = state.passwordVisible ? "Nascondi" : "Mostra";
  $("favoriteButton").classList.toggle("active", entry.favorite);
  const url = normalizeUrl(entry.url);
  $("urlValue").textContent = entry.url || "-";
  $("urlValue").href = url || "#";
  $("notesValue").textContent = entry.notes || "-";
  $("strengthLabel").textContent = strength.label;
  $("strengthHint").textContent = strength.hint;
  $("strengthBar").style.width = `${Math.max(12, strength.score * 20)}%`;
  $("strengthCard").dataset.score = String(strength.score);
}

function openEntryDialog(entry = null) {
  state.editingId = entry ? entry.id : null;
  $("dialogTitle").textContent = entry ? "Modifica password" : "Nuova password";
  $("entryTitle").value = entry?.title || "";
  $("entryCategory").value = entry?.category || "Personale";
  $("entryUsername").value = entry?.username || "";
  $("entryPassword").value = entry?.password || "";
  $("entryUrl").value = entry?.url || "";
  $("entryNotes").value = entry?.notes || "";
  $("entryFavorite").checked = Boolean(entry?.favorite);
  entryDialog.showModal();
}

function generatePassword(options = {}) {
  const length = Math.max(8, Math.min(64, Number(options.length || 16)));
  const pools = [];
  if (options.uppercase !== false) pools.push("ABCDEFGHJKLMNPQRSTUVWXYZ");
  if (options.lowercase !== false) pools.push("abcdefghijkmnopqrstuvwxyz");
  if (options.numbers !== false) pools.push("23456789");
  if (options.symbols !== false) pools.push("!@#$%&*?-_");
  if (!pools.length) throw new Error("No character groups selected");

  const allChars = pools.join("");
  const password = pools.map((pool) => pool[randomBytes(1)[0] % pool.length]);
  while (password.length < length) {
    password.push(allChars[randomBytes(1)[0] % allChars.length]);
  }

  const shuffleBytes = randomBytes(password.length);
  for (let index = password.length - 1; index > 0; index -= 1) {
    const swapIndex = shuffleBytes[index] % (index + 1);
    [password[index], password[swapIndex]] = [password[swapIndex], password[index]];
  }
  return password.join("");
}

function getGeneratorOptions() {
  return {
    length: $("generatorLength").value,
    uppercase: $("generatorUppercase").checked,
    lowercase: $("generatorLowercase").checked,
    numbers: $("generatorNumbers").checked,
    symbols: $("generatorSymbols").checked
  };
}

function refreshGeneratedPassword() {
  try {
    $("generatedPassword").value = generatePassword(getGeneratorOptions());
  } catch {
    $("generatedPassword").value = "";
    showToast("Seleziona almeno un tipo di carattere");
  }
}

function openGenerator(target) {
  state.generatorTarget = target;
  refreshGeneratedPassword();
  generatorDialog.showModal();
}

function touchActivity() {
  if (state.masterKey) resetLockTimer();
}

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const accountName = normalizeAccountName(accountNameInput.value);
  const account = getAccount(accountName);
  if (!account) {
    authHint.textContent = "Account non trovato. Usa Crea account per aggiungerlo.";
    return;
  }

  try {
    const unlocked = await decryptVault(account.record, masterPassword.value);
    state.accountId = account.id;
    state.accountName = account.name;
    state.masterKey = unlocked.key;
    state.vault = unlocked.vault;
    unlockUi();
  } catch {
    authHint.textContent = "Master password non valida per questo account.";
  }
});

$("createVaultButton").addEventListener("click", async () => {
  const accountName = normalizeAccountName(accountNameInput.value);
  if (!accountName) {
    authHint.textContent = "Inserisci un nome account, ad esempio Leonardo o Lavoro.";
    return;
  }
  if (masterPassword.value.length < 10) {
    authHint.textContent = "Usa almeno 10 caratteri. Meglio una frase lunga.";
    return;
  }

  const accountId = accountIdFromName(accountName);
  const accounts = getAccounts();
  if (accounts.accounts[accountId]) {
    authHint.textContent = "Questo account esiste gia. Usa Sblocca.";
    return;
  }

  const salt = randomBytes(16);
  state.masterKey = await deriveKey(masterPassword.value, salt);
  state.accountId = accountId;
  state.accountName = accountName;
  state.vault = { entries: [], updatedAt: new Date().toISOString() };
  accounts.accounts[accountId] = {
    id: accountId,
    name: accountName,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    record: await encryptVault(state.vault, state.masterKey, salt)
  };
  saveAccounts(accounts);
  renderAccountOptions();
  unlockUi();
});

$("addEntryButton").addEventListener("click", () => openEntryDialog());
$("editEntryButton").addEventListener("click", () => selectedEntry() && openEntryDialog(selectedEntry()));
$("lockButton").addEventListener("click", lockVault);
$("changeAccountButton").addEventListener("click", lockVault);

$("sortButton").addEventListener("click", () => {
  state.sortAsc = !state.sortAsc;
  $("sortButton").textContent = state.sortAsc ? "A-Z" : "Z-A";
  renderEntries();
});

document.querySelectorAll(".filter-chip").forEach((button) => {
  button.addEventListener("click", () => {
    state.activeFilter = button.dataset.filter;
    document.querySelectorAll(".filter-chip").forEach((chip) => chip.classList.toggle("active", chip === button));
    renderEntries();
  });
});

searchInput.addEventListener("input", renderEntries);

$("revealButton").addEventListener("click", () => {
  state.passwordVisible = !state.passwordVisible;
  renderDetail();
});

$("favoriteButton").addEventListener("click", async () => {
  const entry = selectedEntry();
  if (!entry) return;
  entry.favorite = !entry.favorite;
  entry.updatedAt = new Date().toISOString();
  await persistVault();
  renderEntries();
});

$("generateButton").addEventListener("click", () => openGenerator("clipboard"));

$("dialogGenerateButton").addEventListener("click", () => {
  openGenerator("entryPassword");
});

$("generateOnlyButton").addEventListener("click", refreshGeneratedPassword);

["generatorLength", "generatorUppercase", "generatorLowercase", "generatorNumbers", "generatorSymbols"].forEach((id) => {
  $(id).addEventListener("change", refreshGeneratedPassword);
});

$("copyGeneratedButton").addEventListener("click", async () => {
  if (!$("generatedPassword").value) refreshGeneratedPassword();
  if (!$("generatedPassword").value) return;
  await navigator.clipboard.writeText($("generatedPassword").value);
  showToast("Password copiata");
});

$("useGeneratedButton").addEventListener("click", async (event) => {
  event.preventDefault();
  if (!$("generatedPassword").value) refreshGeneratedPassword();
  const password = $("generatedPassword").value;
  if (!password) return;
  if (state.generatorTarget === "entryPassword") {
    $("entryPassword").value = password;
  } else {
    await navigator.clipboard.writeText(password);
    showToast("Password generata e copiata");
  }
  generatorDialog.close();
});

$("authSyncButton").addEventListener("click", () => openSyncDialog("auth"));
$("syncButton").addEventListener("click", () => openSyncDialog("vault"));
$("saveSyncSettingsButton").addEventListener("click", () => {
  saveSyncSettings(readSyncForm());
  $("syncHint").textContent = "Impostazioni GitHub salvate su questo dispositivo.";
});
$("downloadSyncButton").addEventListener("click", () => runSyncAction("download"));
$("uploadSyncButton").addEventListener("click", () => runSyncAction("upload"));

entryForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (event.submitter?.value === "cancel") {
    entryDialog.close();
    return;
  }

  const existing = selectedEntry();
  const now = new Date().toISOString();
  const entry = {
    id: state.editingId || crypto.randomUUID(),
    title: $("entryTitle").value.trim(),
    category: $("entryCategory").value,
    username: $("entryUsername").value.trim(),
    password: $("entryPassword").value,
    url: $("entryUrl").value.trim(),
    notes: $("entryNotes").value.trim(),
    favorite: $("entryFavorite").checked,
    createdAt: existing?.createdAt || now,
    updatedAt: now
  };

  if (!entry.title) return;

  const index = state.vault.entries.findIndex((item) => item.id === entry.id);
  if (index >= 0) {
    state.vault.entries[index] = entry;
  } else {
    state.vault.entries.push(entry);
  }
  state.selectedId = entry.id;
  await persistVault();
  entryDialog.close();
  renderEntries();
  showToast("Vault salvato");
});

$("deleteEntryButton").addEventListener("click", async () => {
  const entry = selectedEntry();
  if (!entry || !confirm(`Eliminare "${entry.title}"?`)) return;
  state.vault.entries = state.vault.entries.filter((item) => item.id !== entry.id);
  state.selectedId = null;
  await persistVault();
  renderEntries();
  showToast("Password eliminata");
});

$("deleteAccountButton").addEventListener("click", () => {
  if (!state.accountId) return;
  if (!confirm(`Eliminare l'account "${state.accountName}" da questo dispositivo? I backup esterni non verranno toccati.`)) return;
  const accounts = getAccounts();
  delete accounts.accounts[state.accountId];
  saveAccounts(accounts);
  lockVault();
  showToast("Account eliminato");
});

document.addEventListener("click", async (event) => {
  const copyType = event.target.dataset?.copy;
  if (!copyType) return;
  const entry = selectedEntry();
  if (!entry) return;
  const values = { username: entry.username, password: entry.password, url: entry.url };
  await navigator.clipboard.writeText(values[copyType] || "");
  showToast("Copiato negli appunti");
});

$("exportButton").addEventListener("click", () => {
  const account = getAccount(state.accountId);
  if (!account?.record) return;
  const backup = {
    type: "lockbox-account-backup",
    accountName: state.accountName,
    exportedAt: new Date().toISOString(),
    record: account.record
  };
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `lockbox-${state.accountName.toLowerCase().replace(/\s+/g, "-")}-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  URL.revokeObjectURL(url);
});

function slugAccountName(name) {
  return accountIdFromName(name).replace(/[^a-z0-9._-]+/g, "-") || "vault";
}

function currentSyncAccountName() {
  return state.accountName || normalizeAccountName(accountNameInput.value);
}

function readSyncForm() {
  return {
    owner: $("syncOwner").value.trim(),
    repo: $("syncRepo").value.trim(),
    branch: $("syncBranch").value.trim() || "main",
    path: $("syncPath").value.trim() || "vaults/{account}.lockbox.json",
    token: $("syncToken").value.trim()
  };
}

function fillSyncForm() {
  const settings = getSyncSettings();
  $("syncOwner").value = settings.owner || "";
  $("syncRepo").value = settings.repo || "";
  $("syncBranch").value = settings.branch || "main";
  $("syncPath").value = settings.path || "vaults/{account}.lockbox.json";
  $("syncToken").value = settings.token || "";
}

function openSyncDialog(mode) {
  state.syncMode = mode;
  fillSyncForm();
  $("uploadSyncButton").disabled = !state.masterKey;
  $("syncHint").textContent = state.masterKey
    ? "Carica o scarica il vault cifrato dell'account aperto."
    : "Da qui puoi scaricare un vault cifrato da GitHub prima del login.";
  syncDialog.showModal();
}

function syncPathForAccount(settings, accountName) {
  return settings.path.replaceAll("{account}", slugAccountName(accountName)).replace(/^\/+/, "");
}

function validateSyncSettings(settings) {
  if (!settings.owner || !settings.repo || !settings.branch || !settings.path || !settings.token) {
    throw new Error("Configurazione GitHub incompleta");
  }
}

async function githubContentRequest(settings, path, options = {}) {
  validateSyncSettings(settings);
  const encodedPath = path.split("/").map((part) => encodeURIComponent(part)).join("/");
  const url = `https://api.github.com/repos/${encodeURIComponent(settings.owner)}/${encodeURIComponent(settings.repo)}/contents/${encodedPath}`;
  const headers = {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${settings.token}`,
    "X-GitHub-Api-Version": "2022-11-28",
    ...options.headers
  };
  const response = await fetch(options.query ? `${url}?${options.query}` : url, {
    ...options,
    headers
  });
  if (response.status === 404) return null;
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `GitHub error ${response.status}`);
  }
  return response.json();
}

function decodeGithubContent(content) {
  return dec.decode(base64ToBytes(content.replace(/\n/g, "")));
}

function encodeGithubContent(value) {
  return bytesToBase64(enc.encode(value));
}

async function fetchRemoteVault(settings, accountName) {
  const path = syncPathForAccount(settings, accountName);
  const response = await githubContentRequest(settings, path, {
    method: "GET",
    query: `ref=${encodeURIComponent(settings.branch)}`
  });
  if (!response) return null;
  return {
    path,
    sha: response.sha,
    payload: JSON.parse(decodeGithubContent(response.content))
  };
}

async function uploadRemoteVault(settings) {
  if (!state.masterKey || !state.accountId) throw new Error("Account non sbloccato");
  const account = getAccount(state.accountId);
  const path = syncPathForAccount(settings, state.accountName);
  const remote = await fetchRemoteVault(settings, state.accountName);
  if (remote?.payload?.updatedAt && account?.updatedAt && new Date(remote.payload.updatedAt) > new Date(account.updatedAt)) {
    const overwrite = confirm("Su GitHub c'e un vault piu recente. Vuoi sovrascriverlo con quello locale?");
    if (!overwrite) return;
  }
  const payload = {
    type: "lockbox-account-backup",
    accountName: state.accountName,
    accountId: state.accountId,
    updatedAt: account?.updatedAt || new Date().toISOString(),
    record: account.record
  };
  await githubContentRequest(settings, path, {
    method: "PUT",
    body: JSON.stringify({
      message: `Sync Lockbox vault ${state.accountName}`,
      branch: settings.branch,
      content: encodeGithubContent(JSON.stringify(payload, null, 2)),
      sha: remote?.sha
    })
  });
  showToast("Vault caricato su GitHub");
}

async function downloadRemoteVault(settings) {
  const accountName = currentSyncAccountName();
  if (!accountName) {
    $("syncHint").textContent = "Inserisci prima il nome account.";
    return;
  }
  const remote = await fetchRemoteVault(settings, accountName);
  if (!remote?.payload?.record) {
    $("syncHint").textContent = "Nessun vault trovato su GitHub per questo account.";
    return;
  }
  const accountId = accountIdFromName(remote.payload.accountName || accountName);
  const accounts = getAccounts();
  const existing = accounts.accounts[accountId];
  if (existing?.updatedAt && remote.payload.updatedAt && new Date(existing.updatedAt) > new Date(remote.payload.updatedAt)) {
    const overwrite = confirm("Sul dispositivo c'e un vault piu recente. Vuoi sostituirlo con quello GitHub?");
    if (!overwrite) return;
  }
  accounts.accounts[accountId] = {
    id: accountId,
    name: remote.payload.accountName || accountName,
    createdAt: existing?.createdAt || new Date().toISOString(),
    updatedAt: remote.payload.updatedAt || new Date().toISOString(),
    record: remote.payload.record
  };
  saveAccounts(accounts);
  renderAccountOptions();
  accountNameInput.value = accounts.accounts[accountId].name;
  if (state.masterKey && state.accountId === accountId) {
    try {
      state.vault = await decryptVaultWithKey(remote.payload.record, state.masterKey);
      state.selectedId = null;
      renderEntries();
    } catch {
      lockVault();
    }
  }
  $("syncHint").textContent = "Vault scaricato. Inserisci la master password per sbloccarlo.";
  authHint.textContent = "Vault scaricato da GitHub. Inserisci la master password per sbloccarlo.";
  showToast("Vault scaricato da GitHub");
}

async function runSyncAction(action) {
  const settings = readSyncForm();
  saveSyncSettings(settings);
  try {
    if (action === "upload") {
      await uploadRemoteVault(settings);
    } else {
      await downloadRemoteVault(settings);
    }
  } catch (error) {
    $("syncHint").textContent = error.message.includes("Bad credentials")
      ? "Token GitHub non valido o senza permessi sul repository."
      : "Errore sync GitHub. Controlla repo, branch, percorso e token.";
  }
}

async function createAccountFromLegacyEntries(name, masterPasswordValue, entries) {
  const accountId = accountIdFromName(name);
  const accounts = getAccounts();
  const salt = randomBytes(16);
  const key = await deriveKey(masterPasswordValue, salt);
  const vault = { entries, updatedAt: new Date().toISOString() };
  accounts.accounts[accountId] = {
    id: accountId,
    name,
    createdAt: accounts.accounts[accountId]?.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    record: await encryptVault(vault, key, salt)
  };
  saveAccounts(accounts);
  renderAccountOptions();
}

async function handleBackupImport(event, mode) {
  const file = event.target.files?.[0];
  if (!file) return;
  try {
    const fileText = await file.text();
    if (file.name.toLowerCase().endsWith(".enc") || fileText.trim().startsWith("gAAAA")) {
      const legacyPassword = prompt("Password usata nel vecchio programma per questo backup .enc:");
      if (!legacyPassword) return;
      const decrypted = await decryptLegacyFernetBackup(fileText, legacyPassword);
      const importedEntries = legacyPasswordsToEntries(JSON.parse(decrypted));
      if (!importedEntries.length) throw new Error("Empty legacy backup");
      if (!state.masterKey || mode === "auth") {
        const fallbackName = normalizeAccountName(accountNameInput.value) || file.name.replace(/\.[^.]+$/, "") || "Importato";
        const name = normalizeAccountName(prompt("Nome account da creare per questo backup:", fallbackName) || fallbackName);
        const newMasterPassword = prompt("Scegli la nuova master password per questo account:");
        if (!name || !newMasterPassword || newMasterPassword.length < 10) {
          authHint.textContent = "Import annullato: nome account e master password di almeno 10 caratteri sono obbligatori.";
          return;
        }
        await createAccountFromLegacyEntries(name, newMasterPassword, importedEntries);
        accountNameInput.value = name;
        authHint.textContent = "Backup .enc importato. Inserisci la nuova master password per sbloccarlo.";
        return;
      }
      state.vault.entries.push(...importedEntries);
      state.selectedId = importedEntries[0].id;
      await persistVault();
      renderEntries();
      showToast(`${importedEntries.length} password importate dal backup .enc`);
      return;
    }

    const imported = JSON.parse(fileText);
    const record = imported.record || imported;
    if (!record.salt || !record.iv || !record.data) throw new Error("Invalid backup");
    const fallbackName = normalizeAccountName(accountNameInput.value) || imported.accountName || `Import ${new Date().toLocaleDateString("it-IT")}`;
    const name = normalizeAccountName(prompt("Nome account per questo backup:", imported.accountName || fallbackName) || fallbackName);
    const accountId = accountIdFromName(name);
    const accounts = getAccounts();
    accounts.accounts[accountId] = {
      id: accountId,
      name,
      createdAt: accounts.accounts[accountId]?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      record
    };
    saveAccounts(accounts);
    lockVault();
    accountNameInput.value = name;
    authHint.textContent = "Backup importato. Inserisci la master password del backup per sbloccarlo.";
  } catch {
    showToast("Backup non valido");
  } finally {
    event.target.value = "";
  }
}

$("importInput").addEventListener("change", (event) => handleBackupImport(event, "vault"));
$("authImportInput").addEventListener("change", (event) => handleBackupImport(event, "auth"));

$("timeoutSelect").addEventListener("change", (event) => {
  state.timeoutMs = Number(event.target.value);
  resetLockTimer();
  showToast("Timeout aggiornato");
});

["mousemove", "keydown", "touchstart", "visibilitychange"].forEach((eventName) => {
  document.addEventListener(eventName, touchActivity, { passive: true });
});

migrateLegacyVault();
renderAccountOptions();

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("service-worker.js").catch(() => {});
}
