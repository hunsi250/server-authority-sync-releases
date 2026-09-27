"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);

// src/main.ts
var main_exports = {};
__export(main_exports, {
  default: () => ServerAuthoritySyncPlugin,
  userFacingServerError: () => userFacingServerError,
  validateSetupConfig: () => validateSetupConfig
});
module.exports = __toCommonJS(main_exports);

// src/state.ts
var SYNC_STATE_VERSION = 1;
var SERVER_FINGERPRINT = /^(?:sha256:)?[0-9a-f]{64}$/;
var PUBLIC_IDENTITY = /^public:[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
function validateServerFingerprint(value) {
  if (typeof value !== "string" || !SERVER_FINGERPRINT.test(value) && !PUBLIC_IDENTITY.test(value)) throw new Error("server_fingerprint must be sha256:<64 lowercase hex> or public:<safe identity>");
  return value;
}
function serverFingerprintMatches(configured, returned) {
  return !configured || typeof returned === "string" && returned === configured;
}
function validateSetupUriParameters(input) {
  const allowed = /* @__PURE__ */ new Set(["action", "protocol_version", "server_url", "api_prefix", "vault_id", "setup_token"]);
  for (const key of Object.keys(input)) if (!allowed.has(key)) throw new Error("setup URI contains unsupported parameters");
  if (input.action !== "setup" || input.protocol_version !== "1" || typeof input.setup_token !== "string" || !input.setup_token || typeof input.server_url !== "string" || typeof input.vault_id !== "string" || !input.vault_id.trim()) throw new Error("invalid setup URI");
  let url;
  try {
    url = new URL(input.server_url);
  } catch (e) {
    throw new Error("server_url must be a valid URL");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) throw new Error("setup URI server_url must be HTTPS without credentials or query data");
  if (input.api_prefix !== void 0 && (typeof input.api_prefix !== "string" || !input.api_prefix.startsWith("/") || input.api_prefix.endsWith("/") || input.api_prefix.includes("\\") || input.api_prefix.includes("?") || input.api_prefix.includes("#") || input.api_prefix.includes("..") || input.api_prefix.includes("//"))) throw new Error("api_prefix must be a safe URL path");
  return { protocol_version: "1", server_url: input.server_url, ...input.api_prefix === void 0 ? {} : { api_prefix: input.api_prefix }, vault_id: input.vault_id, setup_token: input.setup_token };
}
function nonSensitiveLinkConfiguration(settings) {
  var _a;
  return { protocol_version: "1", server_url: settings.serverUrl, api_prefix: settings.apiPrefix, vault_id: settings.vaultId, server_fingerprint: (_a = settings.serverFingerprint) != null ? _a : "" };
}
function hashLabel(hash) {
  return hash != null ? hash : "(missing)";
}
function conflictDisplayRows(conflicts) {
  return conflicts.map((conflict) => ({ ...conflict, baseLabel: hashLabel(conflict.baseHash), localLabel: hashLabel(conflict.localHash), serverLabel: hashLabel(conflict.serverHash) }));
}
function pendingDisplayRows(pending) {
  return pending.map((item) => {
    var _a;
    return {
      submissionId: item.submissionId,
      paths: item.changes.map((change) => change.path),
      baseRevisionId: item.baseRevisionId,
      retryCount: item.retryCount,
      status: item.submitted ? "sent; awaiting server review" : item.blocked ? `blocked: ${(_a = item.lastError) != null ? _a : "review required; refresh or rebuild this submission"}` : item.lastError ? `error: ${item.lastError}` : item.retryCount ? "retry pending" : "pending"
    };
  });
}
function createPendingSubmission(baseRevisionId, changes) {
  if (!baseRevisionId) throw new Error("base revision is required");
  return { submissionId: crypto.randomUUID(), baseRevisionId, changes, createdAt: (/* @__PURE__ */ new Date()).toISOString(), retryCount: 0 };
}
function emptySyncState() {
  return { version: SYNC_STATE_VERSION, serverRevision: null, files: {}, excludedFiles: {}, pendingSubmissions: [], conflicts: [], overwriteBackups: [], deletionBackups: [] };
}
function normalizeSyncState(value) {
  var _a, _b;
  if (!value || typeof value !== "object") return emptySyncState();
  const input = value;
  const files = {};
  for (const [path, entry] of Object.entries((_a = input.files) != null ? _a : {})) {
    if (entry && (typeof entry.baseHash === "string" || entry.baseHash === null)) files[path] = { baseHash: entry.baseHash, ...typeof entry.localHash === "string" || entry.localHash === null ? { localHash: entry.localHash } : {}, ...typeof entry.localSize === "number" ? { localSize: entry.localSize } : {}, ...typeof entry.localMtime === "number" ? { localMtime: entry.localMtime } : {} };
  }
  const excludedFiles = {};
  for (const [path, entry] of Object.entries((_b = input.excludedFiles) != null ? _b : {})) if (entry && typeof entry.serverHash === "string" && typeof entry.size === "number" && entry.reason === "file-too-large") excludedFiles[path] = entry;
  const overwriteBackups = Array.isArray(input.overwriteBackups) ? input.overwriteBackups.filter((item) => item && typeof item.path === "string" && typeof item.localHash === "string" && typeof item.serverHash === "string" && typeof item.serverRevisionId === "string" && typeof item.cachePath === "string" && typeof item.cacheHash === "string" && typeof item.createdAt === "string") : [];
  const rawDeletionBackups = input.deletionBackups;
  const deletionBackups = Array.isArray(rawDeletionBackups) ? rawDeletionBackups.filter((item) => item && typeof item.path === "string" && typeof item.localHash === "string" && typeof item.serverRevisionId === "string" && typeof item.cachePath === "string" && typeof item.cacheHash === "string" && typeof item.createdAt === "string") : void 0;
  return { version: SYNC_STATE_VERSION, serverRevision: typeof input.serverRevision === "string" ? input.serverRevision : null, files, excludedFiles, pendingSubmissions: Array.isArray(input.pendingSubmissions) ? input.pendingSubmissions : [], conflicts: Array.isArray(input.conflicts) ? input.conflicts : [], overwriteBackups, ...deletionBackups ? { deletionBackups } : {} };
}
function isLocalClean(state, local) {
  return [.../* @__PURE__ */ new Set([...Object.keys(local), ...Object.keys(state.files)])].every((path) => {
    var _a, _b, _c;
    return ((_a = local[path]) != null ? _a : null) === ((_c = (_b = state.files[path]) == null ? void 0 : _b.baseHash) != null ? _c : null);
  });
}
var MAX_SYNC_FILE_BYTES = 16 * 1024 * 1024;
function safeManifestPath(path) {
  return typeof path === "string" && !!path && !path.startsWith("/") && !path.includes("\\") && path.split("/").every((part) => !!part && part !== "." && part !== "..");
}
function validateSyncManifest(input) {
  if (!input || typeof input !== "object") return { complete: false, files: [], blocked: [], reason: "manifest-not-an-object" };
  const value = input;
  if (value.protocol_version !== "1" || typeof value.revision_id !== "string" || !value.revision_id || !Array.isArray(value.files)) return { complete: false, files: [], blocked: [], reason: "manifest-header-invalid" };
  const files = [];
  const paths = /* @__PURE__ */ new Set();
  let reason;
  for (const item of value.files) {
    const file = item;
    if (!safeManifestPath(file.path) || typeof file.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(file.sha256) || !Number.isInteger(file.size) || file.size < 0 || paths.has(file.path)) {
      reason != null ? reason : reason = "manifest-file-invalid";
      continue;
    }
    paths.add(file.path);
    files.push({ path: file.path, sha256: file.sha256, size: file.size });
  }
  const blocked = [];
  if (value.blocked !== void 0 && !Array.isArray(value.blocked)) reason != null ? reason : reason = "manifest-blocked-invalid";
  for (const item of Array.isArray(value.blocked) ? value.blocked : []) {
    const entry = item;
    if (!safeManifestPath(entry.path) || entry.reason !== void 0 && typeof entry.reason !== "string") {
      reason != null ? reason : reason = "manifest-blocked-invalid";
      continue;
    }
    blocked.push({ path: entry.path, ...entry.reason === void 0 ? {} : { reason: entry.reason } });
  }
  const allPaths = [...paths];
  if (allPaths.some((path) => allPaths.some((other) => path !== other && other.startsWith(path + "/")))) reason != null ? reason : reason = "manifest-file-directory-collision";
  return { complete: !reason && blocked.length === 0, files, blocked, ...reason ? { reason } : {} };
}
function uploadConfirmation(paths, server) {
  const exact = [...new Set(paths)].sort();
  return { paths: exact, additions: exact.filter((path) => !server[path]).length, overwrites: exact.filter((path) => !!server[path]).length };
}
function planSync(state, local, server, localKinds = {}, serverKinds = {}, blocked = /* @__PURE__ */ new Set(), options = { allowLocalSubmissions: false }) {
  const paths = /* @__PURE__ */ new Set([...Object.keys(state.files), ...Object.keys(local), ...Object.keys(server), ...Object.keys(localKinds), ...Object.keys(serverKinds)]);
  const localAdded = Object.keys(local).filter((path) => !state.files[path]);
  const deletedBasePaths = Object.keys(state.files).filter((path) => !Object.prototype.hasOwnProperty.call(local, path) && !Object.prototype.hasOwnProperty.call(server, path));
  const serverAdded = Object.keys(server).filter((path) => !state.files[path]);
  const renameLike = deletedBasePaths.length > 0 && deletedBasePaths.length === localAdded.length && serverAdded.length === 0;
  const blockedPrefixes = [...blocked];
  return [...paths].sort().map((path) => {
    var _a, _b, _c, _d, _e, _f, _g, _h;
    if (blockedPrefixes.some((entry) => entry === path || path.startsWith(entry + "/"))) return { kind: "blocked", path, reason: "server-cannot-read" };
    const base = (_b = (_a = state.files[path]) == null ? void 0 : _a.baseHash) != null ? _b : null;
    const localHash = Object.prototype.hasOwnProperty.call(local, path) ? local[path] : null;
    const serverHash = (_d = (_c = server[path]) == null ? void 0 : _c.sha256) != null ? _d : null;
    if (server[path] && server[path].size > MAX_SYNC_FILE_BYTES && !((_e = options.retryExcluded) == null ? void 0 : _e.has(path))) return { kind: "excluded", path, serverHash: server[path].sha256, size: server[path].size, reason: ((_f = state.excludedFiles[path]) == null ? void 0 : _f.serverHash) === server[path].sha256 ? "file-too-large-cached" : "file-too-large" };
    const localKind = (_g = localKinds[path]) != null ? _g : localHash !== null ? "file" : void 0;
    const serverKind = (_h = serverKinds[path]) != null ? _h : serverHash !== null ? "file" : void 0;
    const collision = localKind && serverKind && localKind !== serverKind;
    const ancestorCollision = [.../* @__PURE__ */ new Set([...Object.keys(localKinds), ...Object.keys(serverKinds)])].some((parent) => {
      var _a2;
      return path.startsWith(parent + "/") && ((_a2 = localKinds[parent]) != null ? _a2 : serverKinds[parent]) === "file";
    });
    if (collision || ancestorCollision) return { kind: "conflict", path, baseHash: base, localHash, serverHash, reason: "file-directory-collision" };
    if (serverHash === null && localHash !== null && options.allowLocalDeletes && options.manifestComplete !== false) return { kind: "delete-local", path, localHash, reason: "not-present-on-server" };
    if (serverHash === null && localHash !== null && base === localHash && state.files[path]) {
      return { kind: "conflict", path, baseHash: base, localHash, serverHash, reason: renameLike ? "rename-like-delete-review" : "server-deletion-retained-locally" };
    }
    if (serverHash === null && localHash === null) return { kind: "clean", path, hash: null };
    if (localHash === serverHash) return { kind: "clean", path, hash: localHash };
    if (serverHash !== null) return { kind: "pull", path, serverHash, ...localHash === null ? {} : { reason: "server-authoritative-overwrite" } };
    if (localHash === null) return { kind: "clean", path, hash: null };
    return { kind: "review", path, localHash, reason: "incomplete-server-manifest" };
  });
}
function classifySubmitResult(result) {
  var _a;
  if (result.status === 201 || result.statusText === "pending") return "sent-to-review";
  if (result.status === 409 || result.code === "conflict" || result.code === "stale_revision") return "conflict-review-required";
  if (((_a = result.status) != null ? _a : 0) >= 500 || result.status === 408 || result.status === 429 || result.code === "retryable_server_error") return "retryable-failure";
  if (result.status === 208 || result.code === "already_submitted") return "already-sent-skipped";
  return "non-retryable-blocked";
}
function validCredential(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,512}$/.test(value);
}
function sessionStructure(value) {
  const s = value;
  return !!s && typeof s.ticket === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(s.ticket) && typeof s.expires_at === "string" && Number.isFinite(Date.parse(s.expires_at));
}
function enrollmentStructure(value) {
  const e = value;
  return !!e && validCredential(e.request_id) && validCredential(e.poll_secret) && typeof e.expires_at === "string" && Number.isFinite(Date.parse(e.expires_at));
}
function validSession(value) {
  return sessionStructure(value) && Date.parse(value.expires_at) > Date.now();
}
function validEnrollment(value) {
  return enrollmentStructure(value) && Date.parse(value.expires_at) > Date.now();
}
function credentialState(input, binding) {
  if (!validCredential(input.device_token) && !sessionStructure(input.session) && !enrollmentStructure(input.enrollment)) return "missing";
  if (input.credentialBinding !== binding) return "invalid-binding";
  if (validEnrollment(input.enrollment)) return "enrollment";
  if (validSession(input.session)) return "session";
  return validCredential(input.device_token) ? "renewable" : "missing";
}
function shouldRenewSession(session, deviceToken) {
  return validCredential(deviceToken) && !validSession(session);
}
async function pairDevice(transport, identity, save, pending, wait = () => new Promise((resolve) => setTimeout(resolve, 2e3)), active = () => true, creating = () => {
}) {
  validateServerFingerprint(identity.server_fingerprint);
  const health = await transport.health();
  const info = await transport.serverInfo();
  if (!health.ok || health.protocol_version !== "1" || identity.protocol_version !== "1" || Object.entries(identity).some(([k, v]) => info[k] !== v)) throw new Error("Server identity does not match settings.");
  if (!active()) throw new Error("Pairing cancelled.");
  await creating();
  const enrollment = await transport.createEnrollment(identity);
  const expires = Math.min(Date.parse(enrollment.expires_at), Date.now() + 3e5);
  if (!enrollment.request_id || !enrollment.poll_secret || !Number.isFinite(expires)) throw new Error("Invalid enrollment response.");
  await pending(enrollment.request_id);
  while (active() && Date.now() < expires) {
    const result = await transport.pollEnrollment(enrollment.request_id, identity, enrollment.poll_secret);
    if (!active() || Date.now() >= expires) throw new Error("Pairing expired or was cancelled.");
    if (result.status === "approved" && typeof result.device_token === "string" && result.device_token && validSession(result)) {
      const approved = result.enrollment_session;
      if (approved !== void 0 && (!approved || typeof approved !== "object" || approved.request_id !== enrollment.request_id || typeof approved.poll_secret !== "string" || !approved.poll_secret || approved.poll_secret === enrollment.poll_secret || !(Date.parse(approved.expires_at) > Date.now()))) throw new Error("Invalid approved enrollment session. Test and pair again.");
      await save({ device_token: result.device_token, ticket: result.ticket, expires_at: result.expires_at }, approved);
      return;
    }
    if (result.status !== "pending" || result.device_token || result.ticket || result.expires_at) throw new Error("Pairing expired or was rejected.");
    await wait();
  }
  throw new Error("Pairing expired or was cancelled. Test and pair again.");
}
function pairingStatusLabel(status) {
  const labels = { recovering: "Recovering saved credentials; retry sync if offline", "binding-mismatch": "Saved credentials do not match these settings; restore the previous settings or Test and pair", "not-paired": "Not paired", testing: "Checking server identity", creating: "Creating pairing request", saving: "Saving pairing credentials", waiting: "Waiting for administrator approval", approved: "Pairing approved; saving credentials", ready: "Paired and ready", expired: "Pairing expired", "settings-changed": "Pairing stopped: settings changed", "server-rejected": "Pairing failed: server rejected the request", "connection-failed": "Pairing failed: connection failure", "save-failed": "Pairing failed: credentials could not be saved" };
  return labels[status.kind] + (status.reason ? ` (${status.reason})` : "");
}
function transitionPairingStatus(status, event) {
  if (event === "reset") return { kind: "not-paired" };
  if (event === "saved") return { kind: "ready" };
  if (event === "save-failed") return { kind: "save-failed", reason: "save failed: credential storage failed" };
  if (event === "settings-changed") return { kind: "settings-changed", reason: "settings changed during pairing" };
  if (event === "connection-failed") return { kind: "connection-failed" };
  if (event === "server-rejected") return { kind: "server-rejected" };
  if (event === "expired") return { kind: "expired" };
  return { kind: event };
}
function planLocalWrite(input) {
  if (input.expectedLocalHash !== void 0 && input.localHash !== input.expectedLocalHash) return { action: "abort", reason: "local file changed after preflight" };
  if (input.existing === "folder") return { action: "conflict", reason: "path is a folder" };
  if (input.existing === "file") {
    if (input.localHash === input.incomingHash) return { action: "skip" };
    return input.planner === "pull" ? { action: "modify" } : { action: "conflict", reason: "local file differs" };
  }
  return { action: "create" };
}
function reconcileCreateRace(input) {
  if (input.existing === "file" && input.existingHash === input.incomingHash) return { action: "reconciled" };
  if (input.existing === "none") return { action: "retry-create" };
  return { action: "conflict", reason: input.existing === "folder" ? "path is a folder" : "local file appeared during pull" };
}
function classifySyncOutcome(input) {
  var _a, _b, _c, _d, _e, _f, _g, _h, _i, _j;
  const decisions = (_a = input.decisions) != null ? _a : [];
  const reviewTexts = (_b = input.reviews) != null ? _b : [];
  const errors = (_c = input.errors) != null ? _c : [];
  const pulls = decisions.filter((d) => d.kind === "pull");
  const deletes = decisions.filter((d) => d.kind === "delete-local");
  const clean = decisions.filter((d) => d.kind === "clean");
  const pending = decisions.filter((d) => d.kind === "submit");
  const conflicts = decisions.filter((d) => d.kind === "conflict");
  const policyReviews = decisions.filter((d) => d.kind === "review");
  const blocked = decisions.filter((d) => d.kind === "blocked");
  const reviewPaths = [.../* @__PURE__ */ new Set([...reviewTexts.map((text) => text.split(":", 1)[0]), ...conflicts.map((d) => d.path), ...policyReviews.map((d) => d.path)])];
  const retryableFailures = errors.filter((error) => {
    var _a2;
    return typeof error === "object" && error !== null && (error.retryable || [408, 429, 500, 502, 503, 504].includes((_a2 = error.status) != null ? _a2 : 0));
  }).length;
  const nonRetryableFailures = errors.length - retryableFailures;
  const pendingAdditions = pending.filter((d) => d.reason === "local-addition-pending" || d.reason === "local-addition-review").length;
  const pulled = (_e = (_d = input.actual) == null ? void 0 : _d.pulled) != null ? _e : pulls.length;
  const deleted = (_g = (_f = input.actual) == null ? void 0 : _f.deleted) != null ? _g : deletes.length;
  const alreadyCurrent = (_i = (_h = input.actual) == null ? void 0 : _h.alreadyCurrent) != null ? _i : clean.length;
  const kind = errors.length && !pulled && !deleted && !pending.length && !reviewPaths.length ? "failed" : reviewPaths.length || errors.length ? "review" : pulled || deleted || pending.length || blocked.length ? "complete" : "no-op";
  const failurePaths = errors.map((error) => error == null ? void 0 : error.path).filter((path) => typeof path === "string");
  return { kind, manifestFiles: (_j = input.manifestFiles) != null ? _j : decisions.length, pulled, deleted, skipped: alreadyCurrent, alreadyCurrent, pendingAdditions, reviews: reviewPaths.length, retryableFailures, nonRetryableFailures, paths: pulls.map((d) => d.path), reviewPaths, errors, blocked: blocked.length, blockedPaths: blocked.map((d) => d.path), pendingChanges: pending.length, failurePaths };
}
function listPaths(paths, limit = 3) {
  const unique = [...new Set(paths)];
  if (unique.length <= limit) return unique.join(", ");
  return `${unique.slice(0, limit).join(", ")} and ${unique.length - limit} more`;
}
function syncNotice(decisions, reviews = [], errors = [], manifestFiles = decisions.length, actual) {
  const outcome = classifySyncOutcome({ decisions, reviews, errors, manifestFiles, actual });
  if (outcome.kind === "no-op") return "All files are up to date. No synchronization needed.";
  const summary = `Sync complete: ${outcome.manifestFiles} manifest file(s); Pulled/updated: ${outcome.pulled}, Local deletions: ${outcome.deleted}, Already current: ${outcome.alreadyCurrent}, ${outcome.pendingChanges} pending local change(s) (${outcome.pendingAdditions} addition(s)), ${outcome.reviews} needs review.${outcome.paths.length ? ` Pulled paths: ${listPaths(outcome.paths)}.` : ""}`;
  const blocked = outcome.blocked ? ` ${outcome.blocked} file(s) the server cannot read, so they were not pulled: ${listPaths(outcome.blockedPaths)}. Nothing was deleted locally; ask the administrator to fix vault ownership/permissions.` : "";
  const reasons = errors.map((error) => error == null ? void 0 : error.message).filter((message) => !!message).slice(0, 2);
  const failures = errors.length ? ` Retryable failures: ${outcome.retryableFailures}; non-retryable failures: ${outcome.nonRetryableFailures}${outcome.failurePaths.length ? ` (${listPaths(outcome.failurePaths)})` : ""}.${reasons.length ? ` ${reasons.join(" ")}` : ""}` : "";
  const detailPaths = outcome.reviewPaths.length ? outcome.reviewPaths.slice(0, 3).map((path) => {
    var _a;
    return (_a = reviews.find((text) => text.startsWith(`${path}:`))) != null ? _a : path;
  }) : outcome.failurePaths.slice(0, 3);
  const detail = detailPaths.length ? ` Review paths: ${detailPaths.join("; ")}.` : "";
  if (outcome.kind === "failed") return `Sync failed: ${outcome.nonRetryableFailures + outcome.retryableFailures} transport or file error(s)${outcome.failurePaths.length ? ` (${listPaths(outcome.failurePaths)}). Review paths: ${listPaths(outcome.failurePaths)}` : ""}. State was retained.`;
  return summary + blocked + failures + detail;
}

// src/main.ts
var import_obsidian = require("obsidian");

// src/ui.ts
function actionRowLayout(buttonCount) {
  void buttonCount;
  return {
    display: "flex",
    flexDirection: "column",
    flexWrap: "nowrap",
    gap: "0.5em",
    width: "100%",
    maxWidth: "100%",
    overflowX: "hidden",
    button: { display: "block", width: "100%", maxWidth: "100%", whiteSpace: "normal" }
  };
}
function applyActionRowLayout(controlEl) {
  const layout = actionRowLayout(controlEl.querySelectorAll("button").length);
  controlEl.style.display = layout.display;
  controlEl.style.flexDirection = layout.flexDirection;
  controlEl.style.flexWrap = layout.flexWrap;
  controlEl.style.gap = layout.gap;
  controlEl.style.width = layout.width;
  controlEl.style.maxWidth = layout.maxWidth;
  controlEl.style.overflowX = layout.overflowX;
  for (const button of controlEl.querySelectorAll("button")) {
    button.style.display = layout.button.display;
    button.style.width = layout.button.width;
    button.style.maxWidth = layout.button.maxWidth;
    button.style.whiteSpace = layout.button.whiteSpace;
  }
}

// src/main.ts
var PROTOCOL_VERSION = "1";
var DEFAULT_API_PREFIX = "/api/v1";
var CACHE_ROOT = ".obsidian/server-authority-sync";
var DEFAULT_SETTINGS = { serverUrl: "", apiPrefix: DEFAULT_API_PREFIX, vaultId: "default", serverFingerprint: "", autoCheckIntervalMinutes: 30, syncPolicy: "server-authoritative", aiProvider: { provider: "", model: "", endpoint: "" } };
function mergeSettings(input) {
  var _a;
  return { ...DEFAULT_SETTINGS, ...input != null ? input : {}, aiProvider: { ...DEFAULT_SETTINGS.aiProvider, ...(_a = input == null ? void 0 : input.aiProvider) != null ? _a : {} } };
}
function validateRelativePath(value, field = "path") {
  if (!value || value.startsWith("/") || value.includes("\\") || value.split("/").some((x) => !x || x === "." || x === "..")) throw new Error(`${field} must be a safe relative path`);
  return value;
}
function validateApiPrefix(value) {
  if (!value.startsWith("/") || value.includes("\\") || value.includes("..") || value.includes("?") || value.includes("#")) throw new Error("api_prefix must be a safe URL path");
  return value.replace(/\/$/, "") || DEFAULT_API_PREFIX;
}
function validateServerUrl(value, requireHttps = false) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch (e) {
    throw new Error("server_url must be a valid URL");
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback && !requireHttps)) throw new Error("server_url must use HTTPS (HTTP is allowed only for local development)");
  if (parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error("server_url must not contain credentials or query data");
  return value.replace(/\/$/, "");
}
function validateSetupConfig(input) {
  if (!input || typeof input !== "object") throw new Error("setup config must be an object");
  const v = input;
  if (v.protocol_version !== PROTOCOL_VERSION || typeof v.server_url !== "string" || typeof v.vault_id !== "string" || !v.vault_id.trim()) throw new Error("invalid setup configuration");
  validateServerUrl(v.server_url, true);
  if (v.api_prefix) validateApiPrefix(v.api_prefix);
  if (v.server_fingerprint !== void 0) validateServerFingerprint(v.server_fingerprint);
  if (v.setup_token !== void 0 && (!v.setup_token || typeof v.setup_token !== "string")) throw new Error("invalid setup token");
  if (v.sync_policy && v.sync_policy !== "manual" && v.sync_policy !== "pull-when-clean" && v.sync_policy !== "server-authoritative") throw new Error("invalid sync policy");
  if (v.auto_check_interval_minutes !== void 0 && (!Number.isInteger(v.auto_check_interval_minutes) || v.auto_check_interval_minutes < 0 || v.auto_check_interval_minutes > 1440)) throw new Error("invalid check interval");
  return v;
}
function joinUrl(base, prefix, path) {
  return `${base}${prefix}${path}`;
}
function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function base64ToBytes(value) {
  if (typeof value !== "string" || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error("Corrupted file transfer");
  let binary;
  try {
    binary = atob(value);
  } catch (e) {
    throw new Error("Corrupted file transfer");
  }
  const result = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) result[i] = binary.charCodeAt(i);
  if (bytesToBase64(result) !== value) throw new Error("Corrupted file transfer");
  return result;
}
function userFacingServerError(status, payload) {
  var _a;
  const code = payload && typeof payload === "object" && "error" in payload && ((_a = payload.error) == null ? void 0 : _a.code);
  switch (code) {
    case "invalid_request":
    case "invalid_json":
    case "unsupported_protocol":
      return "\u8BF7\u6C42\u683C\u5F0F\u6216\u534F\u8BAE\u65E0\u6548\uFF0C\u8BF7\u68C0\u67E5\u540C\u6B65\u8BBE\u7F6E\u3002";
    case "unauthorized":
    case "admin_required":
      return "\u4F1A\u8BDD\u5DF2\u8FC7\u671F\u6216\u672A\u6388\u6743\uFF0C\u8BF7\u91CD\u65B0\u914D\u5BF9\u3002";
    case "path_collision":
    case "file_collision":
      return "\u6587\u4EF6/\u76EE\u5F55\u8DEF\u5F84\u51B2\u7A81\uFF0C\u8BF7\u68C0\u67E5\u5E76\u91CD\u5EFA\u63D0\u4EA4\u3002";
    case "stale_revision":
    case "conflict":
      return "\u670D\u52A1\u5668\u7248\u672C\u5DF2\u53D8\u5316\uFF0C\u8BF7\u5237\u65B0\u540E review \u51B2\u7A81\u3002";
    case "file_not_found":
    case "not_found":
      return "\u670D\u52A1\u5668\u6587\u4EF6\u4E0D\u5B58\u5728\uFF0C\u8BF7\u5237\u65B0\u3002";
    case "rate_limited":
      return "\u8BF7\u6C42\u8FC7\u4E8E\u9891\u7E41\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BD5\u3002";
    case "vault_unreadable":
      return "\u670D\u52A1\u5668\u65E0\u6CD5\u8BFB\u53D6\u5176 Vault \u4E2D\u7684\u6587\u4EF6\uFF08\u670D\u52A1\u5668\u7AEF\u6743\u9650\u95EE\u9898\uFF09\uFF0C\u8BF7\u8054\u7CFB\u7BA1\u7406\u5458\u4FEE\u590D\uFF1B\u4F60\u7684\u914D\u5BF9\u4E0E\u51ED\u636E\u4E0D\u53D7\u5F71\u54CD\u3002";
    case "upload_rollback_failed":
      return "\u4E0A\u4F20\u5931\u8D25\u4E14\u670D\u52A1\u5668\u6587\u4EF6\u672A\u80FD\u5B8C\u6574\u6062\u590D\uFF0C\u5DF2\u505C\u6B62\u7EE7\u7EED\uFF1B\u8BF7\u7BA1\u7406\u5458\u6838\u67E5\u670D\u52A1\u5668\u6570\u636E\u3002";
    case "identity_mismatch":
      return "\u670D\u52A1\u5668\u8EAB\u4EFD\u4E0E\u8BBE\u7F6E\u4E0D\u4E00\u81F4\uFF0C\u8BF7\u68C0\u67E5 Vault ID \u4E0E\u6307\u7EB9\u3002";
    case "request_too_large":
    case "file_too_large":
      return "\u8BE5\u6587\u4EF6\u6216\u8BF7\u6C42\u8D85\u8FC7\u670D\u52A1\u5668\u5355\u6B21\u4E0A\u9650\uFF08\u9ED8\u8BA4\u8BF7\u6C42\u4F53 32 MiB\u3001\u5355\u6587\u4EF6 16 MiB\uFF09\uFF1A\u8BF7\u62C6\u5206\u6587\u4EF6\uFF0C\u6216\u628A\u5927\u9644\u4EF6\u653E\u5728\u540C\u6B65\u76EE\u5F55\u4E4B\u5916\u3002\u51ED\u636E\u4E0E\u672C\u5730\u6587\u4EF6\u672A\u53D7\u5F71\u54CD\u3002";
    case "internal_error":
      return "\u670D\u52A1\u5668\u5185\u90E8\u9519\u8BEF\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BD5\uFF1B\u8FD9\u4E0D\u4F1A\u4F7F\u914D\u5BF9\u5931\u6548\u3002";
  }
  if (status === 401 || status === 403) return "\u4F1A\u8BDD\u5DF2\u8FC7\u671F\u6216\u672A\u6388\u6743\uFF0C\u8BF7\u91CD\u65B0\u914D\u5BF9\u3002";
  if (status === 404) return "\u670D\u52A1\u5668\u8D44\u6E90\u4E0D\u5B58\u5728\uFF0C\u8BF7\u5237\u65B0\u3002";
  if (status === 408 || status === 429 || status >= 500) return "\u670D\u52A1\u5668\u6682\u65F6\u4E0D\u53EF\u7528\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BD5\u3002";
  if (status >= 400 && status < 500) return "\u8BF7\u6C42\u672A\u88AB\u63A5\u53D7\uFF0C\u8BF7\u68C0\u67E5\u5E76\u91CD\u5EFA\u63D0\u4EA4\u3002";
  return "\u670D\u52A1\u5668\u8FDE\u63A5\u5931\u8D25\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BD5\u3002";
}
function safeError(error) {
  var _a;
  if (!(error instanceof Error)) return "Operation failed. Check diagnostics, connection and pairing; retry after resolving the problem";
  if (error.intermediary) return "The server answered HTTP 401 without an authentication error code; a proxy, edge rule or server fault rejected the request. Saved credentials were kept.";
  if (error.safeMessage) return error.message;
  const reason = (_a = error.diagnostic) == null ? void 0 : _a.reason;
  if (reason && reason in LOCAL_REASONS) return LOCAL_REASONS[reason];
  const message = error.message;
  const safe = /^(Set a server URL first|unsupported protocol version|Server identity does not match settings|Server connection failed|Authentication rejected\..*|Session expired or unavailable\. Test and pair again\.|Server returned an invalid session\. Test and pair again\.|Pairing cancelled: settings changed\.|Unable to save pairing\.)$/i;
  return safe.test(message) ? message : "Operation failed. Check diagnostics, connection and pairing; retry after resolving the problem";
}
var LOCAL_REASONS = {
  missing_credentials: "No usable credentials in PluginData. Open Advanced settings \u2192 Test and pair.",
  credentials_rejected: "The server rejected the saved credentials. Open Advanced settings \u2192 Test and pair.",
  invalid_binding: "Saved credentials belong to different or unverified settings. Check settings, then Test and pair.",
  persistence_failure: "Credential storage could not be verified. Check plugin storage permissions/free space, then retry saving or pairing.",
  invalid_settings: "Set a server URL first and check API prefix, Vault ID and fingerprint in Advanced settings.",
  invalid_response: "The server response could not be parsed. An edge rule, proxy or gateway may have answered instead of the server, or the request was too large. Saved credentials were kept; check Diagnostics.",
  local_operation_failed: "Local sync processing failed. Check vault access and retry."
};
function localFailure(stage, reason, requestSent = false) {
  return Object.assign(new Error(LOCAL_REASONS[reason]), { diagnostic: { stage, reason, retryCount: 0, retryable: false, requestSent } });
}
var SAFE_CODES = /* @__PURE__ */ new Set(["invalid_request", "invalid_json", "unsupported_protocol", "unauthorized", "admin_required", "path_collision", "file_collision", "file_directory_collision", "stale_revision", "conflict", "file_not_found", "not_found", "rate_limited", "retryable_server_error", "invalid_submission", "session_expired", "already_submitted", "invalid_response", "vault_unreadable", "internal_error", "request_too_large", "file_too_large", "upload_rollback_failed", "identity_mismatch", "request_timeout", "server_busy"]);
function normalizeDiagnostics(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((item) => {
    if (!item || typeof item !== "object") return false;
    const d = item;
    return (d.reason === void 0 || Object.prototype.hasOwnProperty.call(LOCAL_REASONS, d.reason)) && typeof d.stage === "string" && d.stage.length <= 64 && (d.status === void 0 || Number.isInteger(d.status) && d.status >= 100 && d.status <= 599) && (d.code === void 0 || typeof d.code === "string" && SAFE_CODES.has(d.code)) && (d.requestId === void 0 || typeof d.requestId === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(d.requestId)) && (d.requestSent === void 0 || typeof d.requestSent === "boolean") && (d.intermediary === void 0 || typeof d.intermediary === "boolean") && typeof d.retryCount === "number" && Number.isInteger(d.retryCount) && d.retryCount >= 0 && typeof d.retryable === "boolean";
  }).slice(-20);
}
function requestStage(path) {
  if (path === "/health") return "health";
  if (path === "/server-info") return "server-info";
  if (path === "/enrollments") return "create-enrollment";
  if (path.endsWith("/poll")) return "poll";
  if (path.endsWith("/manifest")) return "manifest";
  if (path.includes("/files/") || path.endsWith("/read")) return "file";
  if (path.endsWith("/upload")) return "upload";
  if (path === "/submissions") return "submit";
  return path === "/enrollments/session" ? "session" : path === "/submissions/list" ? "submissions" : "setup";
}
var MAX_CHANGE_BYTES = 6 * 1024 * 1024;
function oversizedChangeError(encodedLength) {
  const megabytes = (encodedLength / (1024 * 1024)).toFixed(1);
  return Object.assign(
    new Error(`This file needs a ${megabytes} MB submission, above the ~6 MB limit the server accepts for one change. Nothing was uploaded and nothing was deleted locally; split the file or keep large attachments outside the synced vault.`),
    { safeMessage: true, diagnostic: { stage: "submit", reason: "oversized_change", retryCount: 0, retryable: false, requestSent: false } }
  );
}
function waitMs(ms) {
  return new Promise((resolve) => globalThis.setTimeout(resolve, ms));
}
var AUTHENTICATION_CODES = /* @__PURE__ */ new Set(["unauthorized", "session_expired"]);
function authenticationRefusal(payload) {
  var _a;
  const code = (_a = payload == null ? void 0 : payload.error) == null ? void 0 : _a.code;
  return typeof code === "string" && AUTHENTICATION_CODES.has(code);
}
var RequestUrlTransport = class {
  constructor(settings, session, enrollment, deviceToken = "", saveSession, recordDiagnostic, discardEnrollment, unauthorized, onRequest) {
    this.settings = settings;
    this.session = session;
    this.enrollment = enrollment;
    this.deviceToken = deviceToken;
    this.saveSession = saveSession;
    this.recordDiagnostic = recordDiagnostic;
    this.discardEnrollment = discardEnrollment;
    this.unauthorized = unauthorized;
    this.onRequest = onRequest;
    __publicField(this, "renewal");
    __publicField(this, "rejected", false);
  }
  async recover() {
    if (!validEnrollment(this.enrollment) && shouldRenewSession(this.session, this.deviceToken)) await this.renewSession();
  }
  renewSession() {
    if (!this.renewal) this.renewal = this.performRenewal().finally(() => {
      this.renewal = void 0;
    });
    return this.renewal;
  }
  async performRenewal() {
    var _a, _b, _c, _d, _e;
    if (!this.deviceToken) throw new Error("Session expired or unavailable. Test and pair again.");
    let renewed;
    try {
      renewed = await this.request("POST", "/enrollments/session", { device_token: this.deviceToken });
    } catch (error) {
      if (error.status === 401 && error.authority) {
        this.rejected = true;
        await ((_a = this.unauthorized) == null ? void 0 : _a.call(this));
        const rejected = localFailure("session", "credentials_rejected");
        (_b = this.recordDiagnostic) == null ? void 0 : _b.call(this, { stage: "session", status: 401, code: "unauthorized", retryCount: 0, retryable: false });
        throw rejected;
      }
      throw error;
    }
    if (!validSession(renewed)) {
      (_c = this.recordDiagnostic) == null ? void 0 : _c.call(this, { stage: "session", code: "invalid_response", retryCount: 0, retryable: false });
      throw new Error("Server returned an invalid session. Test and pair again.");
    }
    try {
      await ((_d = this.saveSession) == null ? void 0 : _d.call(this, renewed));
    } catch (e) {
      this.session = void 0;
      const error = localFailure("storage", "persistence_failure");
      (_e = this.recordDiagnostic) == null ? void 0 : _e.call(this, error.diagnostic);
      throw error;
    }
    this.session = renewed;
  }
  async request(method, path, body, authenticated = false, retried = false) {
    var _a, _b, _c, _d;
    const originalPath = path, originalBody = body;
    const stage = requestStage(path);
    const local = (reason) => {
      var _a2;
      const error = localFailure(stage, reason);
      (_a2 = this.recordDiagnostic) == null ? void 0 : _a2.call(this, error.diagnostic);
      return error;
    };
    if (authenticated && this.rejected) throw local("missing_credentials");
    const failure = (message, status, payload2, headers) => {
      var _a2, _b2, _c2;
      let code, requestId;
      try {
        const candidate = (_a2 = payload2 == null ? void 0 : payload2.error) == null ? void 0 : _a2.code;
        if (typeof candidate === "string" && SAFE_CODES.has(candidate)) code = candidate;
        const id = (_b2 = Object.entries(headers != null ? headers : {}).find(([key]) => key.toLowerCase() === "x-request-id")) == null ? void 0 : _b2[1];
        if (id && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) requestId = id;
      } catch (e) {
      }
      const intermediary = status === 401 && !authenticationRefusal(payload2);
      const diagnostic = { stage, status, code, requestId, retryCount: retried ? 1 : 0, retryable: status === void 0 || status === 408 || status === 429 || status >= 500, intermediary };
      (_c2 = this.recordDiagnostic) == null ? void 0 : _c2.call(this, diagnostic);
      return Object.assign(new Error(message), { status, code, diagnostic, authority: authenticationRefusal(payload2), intermediary });
    };
    if (authenticated) {
      if (this.enrollment && !validEnrollment(this.enrollment)) {
        this.enrollment = void 0;
        await ((_a = this.discardEnrollment) == null ? void 0 : _a.call(this));
      }
      if (this.enrollment) {
        const vault = `/vaults/${encodeURIComponent(this.settings.vaultId)}`;
        const readPath = body == null ? void 0 : body.path;
        const operation = path === `${vault}/manifest` ? { type: "manifest" } : path.startsWith(`${vault}/files/`) ? { type: "read-file", path: decodeURIComponent(path.slice(`${vault}/files/`.length)) } : path === `${vault}/read` && typeof readPath === "string" ? { type: "read-file", path: readPath } : path === `${vault}/upload` ? { type: "upload", files: body == null ? void 0 : body.files } : path === "/submissions/list" ? { type: "list-submissions" } : { type: "submit", submission: body };
        path = `/enrollments/${encodeURIComponent(this.enrollment.request_id)}/poll`;
        body = { protocol_version: PROTOCOL_VERSION, vault_id: this.settings.vaultId, server_fingerprint: this.settings.serverFingerprint, poll_secret: this.enrollment.poll_secret, operation };
      } else {
        if (shouldRenewSession(this.session, this.deviceToken)) await this.renewSession();
        if (!validSession(this.session)) throw local("missing_credentials");
        body = { ...body, ticket: this.session.ticket };
      }
    }
    const params = {
      url: joinUrl(validateServerUrl(this.settings.serverUrl), validateApiPrefix(this.settings.apiPrefix), path),
      method,
      throw: false,
      headers: body === void 0 ? {} : { "Content-Type": "application/json" }
    };
    if (body !== void 0) params.body = JSON.stringify(body);
    let response;
    try {
      (_b = this.onRequest) == null ? void 0 : _b.call(this);
      response = await (0, import_obsidian.requestUrl)(params);
    } catch (e) {
      throw failure("Server connection failed");
    }
    let payload;
    try {
      payload = response.json;
    } catch (e) {
      if (response.status !== 401) throw failure("Invalid server response", response.status, void 0, response.headers);
    }
    if (authenticated && response.status === 401) {
      if (!authenticationRefusal(payload)) {
        const kept = failure("Rejected with HTTP 401 without an authentication error code; a proxy or edge rule is involved, or the server has a fault. Credentials were kept.", response.status, payload, response.headers);
        throw kept;
      }
      const error = failure("Authentication rejected. Test and pair again if renewal is unauthorized.", response.status, payload, response.headers);
      this.session = void 0;
      if (this.enrollment) {
        this.enrollment = void 0;
        await ((_c = this.discardEnrollment) == null ? void 0 : _c.call(this));
      }
      if (!retried && this.deviceToken) {
        await this.renewSession();
        return this.request(method, originalPath, originalBody, authenticated, true);
      }
      this.rejected = true;
      await ((_d = this.unauthorized) == null ? void 0 : _d.call(this));
      throw error;
    }
    if (response.status < 200 || response.status >= 300) {
      let message;
      try {
        message = userFacingServerError(response.status, payload);
      } catch (e) {
        message = userFacingServerError(response.status, void 0);
      }
      const rejected = failure(message, response.status, payload, response.headers);
      rejected.safeMessage = true;
      throw rejected;
    }
    return payload;
  }
  createEnrollment(identity) {
    return this.request("POST", "/enrollments", identity);
  }
  pollEnrollment(id, identity, secret) {
    return this.request("POST", `/enrollments/${encodeURIComponent(id)}/poll`, { ...identity, poll_secret: secret });
  }
  health() {
    return this.request("GET", "/health");
  }
  serverInfo() {
    return this.request("GET", "/server-info");
  }
  manifest() {
    return this.request("POST", `/vaults/${encodeURIComponent(this.settings.vaultId)}/manifest`, void 0, true);
  }
  readFile(path) {
    return this.request("POST", `/vaults/${encodeURIComponent(this.settings.vaultId)}/read`, { path: validateRelativePath(path) }, true);
  }
  upload(files) {
    const encoded = files.map((file) => ({ path: validateRelativePath(file.path), content_base64: file.contentBase64, sha256: file.sha256, expected_server_sha256: file.expectedServerSha256 }));
    return this.request("POST", `/vaults/${encodeURIComponent(this.settings.vaultId)}/upload`, { files: encoded }, true);
  }
  submit(value) {
    return this.request("POST", "/submissions", { protocol_version: PROTOCOL_VERSION, submission_id: value.submissionId, base_revision_id: value.baseRevisionId, changes: value.changes, created_at: value.createdAt }, true);
  }
  submissions() {
    return this.request("POST", "/submissions/list", void 0, true);
  }
  async redeemSetup(setupToken) {
    return this.request("POST", "/setup-links/redeem", { setup_token: setupToken });
  }
};
var ServerAuthoritySyncPlugin = class extends import_obsidian.Plugin {
  constructor() {
    super(...arguments);
    __publicField(this, "errors", []);
    __publicField(this, "diagnosticSequence", 0);
    __publicField(this, "credentialBinding");
    __publicField(this, "recovery");
    __publicField(this, "recordDiagnostic", (diagnostic) => {
      this.errors = [...this.errors.slice(-19), diagnostic];
      this.diagnosticSequence++;
      this.updateStatus();
    });
    __publicField(this, "pairing", false);
    __publicField(this, "syncing", false);
    __publicField(this, "unloaded", false);
    __publicField(this, "submitting", false);
    __publicField(this, "uploading", false);
    __publicField(this, "pairingStatus", { kind: "not-paired" });
    __publicField(this, "settings", mergeSettings());
    __publicField(this, "deviceToken", "");
    __publicField(this, "session");
    __publicField(this, "enrollment");
    __publicField(this, "syncState", emptySyncState());
    __publicField(this, "statusBar");
    __publicField(this, "internalWrites", /* @__PURE__ */ new Set());
    __publicField(this, "excludedRetries", /* @__PURE__ */ new Set());
    __publicField(this, "localDirty", false);
    __publicField(this, "statusListener");
    __publicField(this, "changeVersions", /* @__PURE__ */ new Map());
    __publicField(this, "dirtyPaths", /* @__PURE__ */ new Set());
    __publicField(this, "storageFailed", false);
    __publicField(this, "requestsSent", 0);
    __publicField(this, "writes", Promise.resolve());
    __publicField(this, "lastVerified", "");
  }
  binding() {
    return JSON.stringify([this.settings.serverUrl, this.settings.apiPrefix, this.settings.vaultId, this.settings.serverFingerprint]);
  }
  /** The only source of a user-visible pairing label; derived from credentials that actually exist. */
  derivedStatus() {
    const state = credentialState({ credentialBinding: this.credentialBinding, device_token: this.deviceToken, session: this.session, enrollment: this.enrollment }, this.binding());
    return { kind: state === "enrollment" || state === "session" ? "ready" : state === "renewable" ? "recovering" : state === "invalid-binding" ? "binding-mismatch" : "not-paired" };
  }
  clearCredentials() {
    this.deviceToken = "";
    this.session = void 0;
    this.enrollment = void 0;
    this.credentialBinding = void 0;
  }
  diagnosticSummary() {
    var _a, _b, _c, _d, _e, _f, _g;
    const d = this.errors[this.errors.length - 1];
    if (!d) return "No request failures recorded.";
    if (d.intermediary) return `Plugin ${(_b = (_a = this.manifest) == null ? void 0 : _a.version) != null ? _b : "unknown"} \xB7 Stage: ${d.stage} \xB7 HTTP: ${(_c = d.status) != null ? _c : "401"} without an authentication error code: something other than an authentication decision rejected the request, so it was not treated as an authentication failure. Credentials were kept; check the reverse proxy, edge rule or a server fault for this route.`;
    const recovery = d.status === 401 ? " Authentication rejected; automatic recovery was attempted. If still unpaired, Test and pair." : d.retryable ? " Check connection and retry." : " Check settings and retry.";
    const local = (text) => d.requestSent === true ? `A response was received for this stage, then local processing failed: ${text}` : d.requestSent === false ? `No HTTP request was made for this stage: ${text}` : `Local failure during this stage: ${text}`;
    const detail = d.reason ? local(LOCAL_REASONS[d.reason]) : d.status === void 0 ? d.code === "invalid_response" ? "The server answered, but the response was not usable and no HTTP status was recorded." : "No HTTP response was recorded for this stage: the connection failed before a response arrived." : `HTTP: ${d.status} \xB7 Code: ${(_d = d.code) != null ? _d : "not supplied"} \xB7 Request ID: ${(_e = d.requestId) != null ? _e : "not supplied"}.${recovery}`;
    return `Plugin ${(_g = (_f = this.manifest) == null ? void 0 : _f.version) != null ? _g : "unknown"} \xB7 Stage: ${d.stage} \xB7 ${detail}`;
  }
  diagnosticsText() {
    var _a, _b;
    return JSON.stringify({ pluginVersion: (_b = (_a = this.manifest) == null ? void 0 : _a.version) != null ? _b : "unknown", errors: this.errors }, null, 2);
  }
  async copyDiagnostics() {
    try {
      await globalThis.navigator.clipboard.writeText(this.diagnosticsText());
      new import_obsidian.Notice("Diagnostics copied.");
    } catch (e) {
      new ConfigurationExportModal(this.app, this.diagnosticsText()).open();
    }
  }
  async resetPairingState() {
    this.clearCredentials();
    this.pairingStatus = { kind: "not-paired" };
    try {
      await this.saveSettings();
    } catch (error) {
      new import_obsidian.Notice(safeError(error));
    }
    this.updateStatus();
  }
  async onload() {
    let data = null;
    try {
      data = await this.loadData();
    } catch (e) {
      this.storageFailed = true;
    }
    this.errors = normalizeDiagnostics(data == null ? void 0 : data.errors);
    this.settings = mergeSettings(data == null ? void 0 : data.settings);
    this.deviceToken = validCredential(data == null ? void 0 : data.device_token) ? data.device_token : "";
    this.session = sessionStructure(data == null ? void 0 : data.session) ? data.session : void 0;
    this.enrollment = enrollmentStructure(data == null ? void 0 : data.enrollment) ? data.enrollment : void 0;
    this.credentialBinding = data == null ? void 0 : data.credentialBinding;
    this.syncState = normalizeSyncState(data == null ? void 0 : data.sync);
    const state = credentialState(data != null ? data : {}, this.binding());
    this.pairingStatus = this.derivedStatus();
    if (this.storageFailed) {
      this.pairingStatus = { kind: "save-failed" };
      this.recordDiagnostic(localFailure("storage", "persistence_failure").diagnostic);
    } else if (state === "invalid-binding") {
      this.settings.syncPolicy = "manual";
      this.recordDiagnostic(localFailure("load", "invalid_binding").diagnostic);
      await this.saveSettings().catch(() => void 0);
    } else if (state === "missing" && data) {
      this.recordDiagnostic(localFailure("load", "missing_credentials").diagnostic);
      await this.saveSettings().catch(() => void 0);
    }
    this.statusBar = this.addStatusBarItem();
    this.updateStatus();
    this.addSettingTab(new AuthoritySettingTab(this.app, this));
    this.addRibbonIcon("refresh-cw", "Sync with server", () => void this.syncWithServer()).setAttr("aria-label", "Sync with server");
    this.addRibbonIcon("upload", "Upload selected local files", () => this.openLocalUploadPicker()).setAttr("aria-label", "Upload selected local files");
    this.addCommand({ id: "sync-with-server", name: "Sync with server", callback: () => void this.syncWithServer() });
    this.addCommand({ id: "open-conflicts", name: "Open conflicts", callback: () => void this.openConflicts() });
    this.addCommand({ id: "test-server-connection", name: "Test server connection", callback: () => void this.testConnection() });
    this.addCommand({ id: "check-server-version", name: "Check server version", callback: () => void this.checkServerVersion() });
    this.addCommand({ id: "export-non-sensitive-configuration", name: "Export non-sensitive configuration", callback: () => void this.exportConfiguration() });
    this.addCommand({ id: "import-one-time-setup-configuration", name: "Import one-time setup configuration", callback: () => void this.importSetupConfiguration() });
    this.registerObsidianProtocolHandler("server-authority-sync", (params) => void this.importSetupUri(params));
    this.registerEvent(this.app.vault.on("create", (file) => this.markVaultChanged(file)));
    this.registerEvent(this.app.vault.on("modify", (file) => this.markVaultChanged(file)));
    this.registerEvent(this.app.vault.on("delete", (file) => this.markVaultChanged(file)));
    this.registerEvent(this.app.vault.on("rename", (file) => this.markVaultChanged(file)));
    this.registerInterval(window.setInterval(() => {
      if (this.settings.autoCheckIntervalMinutes > 0) void this.checkServerVersion(true).then((connected) => {
        if (connected) return this.autoPull();
      }).catch(() => this.updateStatus(true));
    }, Math.max(1, this.settings.autoCheckIntervalMinutes) * 6e4));
    if (state === "renewable") {
      this.recovery = this.transport().recover().catch(() => {
      });
    }
  }
  onunload() {
    this.unloaded = true;
  }
  async testAndPair() {
    if (this.pairing) {
      new import_obsidian.Notice(pairingStatusLabel(this.pairingStatus));
      return;
    }
    this.pairing = true;
    const previous = { deviceToken: this.deviceToken, session: this.session, enrollment: this.enrollment, credentialBinding: this.credentialBinding };
    let reported = false, adopted = false;
    const snapshot = { ...this.settings };
    const active = () => !this.unloaded && ["serverUrl", "apiPrefix", "vaultId", "serverFingerprint"].every((key) => this.settings[key] === snapshot[key]);
    const setPairing = async (status) => {
      this.pairingStatus = status;
      await this.saveSettings();
      this.updateStatus();
    };
    try {
      await setPairing(transitionPairingStatus(this.pairingStatus, "testing"));
      await pairDevice(new RequestUrlTransport(snapshot, void 0, void 0, "", void 0, this.recordDiagnostic), { protocol_version: "1", vault_id: snapshot.vaultId, server_fingerprint: snapshot.serverFingerprint }, async (credentials, enrollment) => {
        await setPairing(transitionPairingStatus(this.pairingStatus, "approved"));
        await setPairing({ kind: "saving" });
        if (!active()) throw new Error("Pairing cancelled: settings changed.");
        this.deviceToken = credentials.device_token;
        this.session = { ticket: credentials.ticket, expires_at: credentials.expires_at };
        this.enrollment = enrollment;
        this.credentialBinding = this.binding();
        try {
          await this.saveSettings();
        } catch (e) {
          throw new Error("Unable to save pairing.");
        }
        adopted = true;
        if (!active()) throw new Error("Pairing cancelled: settings changed.");
      }, async () => {
        this.pairingStatus = transitionPairingStatus(this.pairingStatus, "waiting");
        await this.saveSettings();
        this.updateStatus();
        new import_obsidian.Notice(pairingStatusLabel(this.pairingStatus), 15e3);
      }, void 0, active, async () => {
        await setPairing({ kind: "creating" });
      });
      await setPairing(transitionPairingStatus(this.pairingStatus, "saved"));
    } catch (error) {
      if (!adopted) {
        this.deviceToken = previous.deviceToken;
        this.session = previous.session;
        this.enrollment = previous.enrollment;
        this.credentialBinding = previous.credentialBinding;
      }
      const diagnostic = error == null ? void 0 : error.diagnostic;
      const message = error instanceof Error ? error.message.toLowerCase() : "";
      const event = !active() ? "settings-changed" : (diagnostic == null ? void 0 : diagnostic.reason) === "persistence_failure" || message.includes("unable to save") ? "save-failed" : (diagnostic == null ? void 0 : diagnostic.reason) === "invalid_settings" || (diagnostic == null ? void 0 : diagnostic.reason) === "invalid_binding" ? "server-rejected" : message.includes("connection") ? "connection-failed" : message.includes("cancel") || message.includes("expired") ? "expired" : "server-rejected";
      const restored = !!(this.deviceToken || this.session || this.enrollment);
      this.pairingStatus = this.storageFailed ? { kind: "save-failed" } : restored ? this.derivedStatus() : transitionPairingStatus(this.pairingStatus, event);
      await this.saveSettings().catch(() => void 0);
      if (!this.unloaded) {
        reported = true;
        new import_obsidian.Notice(`Pairing attempt failed: ${safeError(error)}${restored ? " Existing credentials were kept." : ""}`, 15e3);
      }
    } finally {
      this.pairing = false;
      this.updateStatus();
      if (!this.unloaded && !reported) new import_obsidian.Notice(pairingStatusLabel(this.pairingStatus), 1e4);
    }
  }
  statusText() {
    return `${pairingStatusLabel(this.pairingStatus)} \xB7 ${this.syncing ? "Syncing" : this.uploading ? "Uploading" : this.submitting ? "Processing" : this.localDirty ? "Local changes; upload selected paths" : "Idle"} \xB7 ${this.syncState.conflicts.length} blocked paths`;
  }
  updateStatus(offline = false) {
    var _a;
    const suffix = offline ? "offline" : this.localDirty ? "local changes; upload selected paths" : this.syncState.conflicts.length ? "blocked paths" : "clean";
    if (this.statusBar) this.statusBar.setText(`Authority: ${suffix} \xB7 ${pairingStatusLabel(this.pairingStatus)}`);
    (_a = this.statusListener) == null ? void 0 : _a.call(this);
  }
  pluginRoot() {
    return `${this.app.vault.configDir || ".obsidian"}/plugins/server-authority-sync`;
  }
  isLocalPluginPath(path) {
    const root = this.pluginRoot();
    return path === root || path.startsWith(root + "/") || path === CACHE_ROOT || path.startsWith(CACHE_ROOT + "/");
  }
  markVaultChanged(file) {
    var _a;
    this.changeVersions.set(file.path, ((_a = this.changeVersions.get(file.path)) != null ? _a : 0) + 1);
    if (this.internalWrites.delete(file.path)) return;
    if (!this.isLocalPluginPath(file.path)) {
      this.dirtyPaths.add(file.path);
      this.localDirty = true;
      this.updateStatus();
    }
  }
  credentialSignature() {
    var _a, _b, _c;
    return JSON.stringify([(_a = this.credentialBinding) != null ? _a : null, this.deviceToken, (_b = this.session) != null ? _b : null, (_c = this.enrollment) != null ? _c : null]);
  }
  /** Serialize whole PluginData snapshots; verify credential-changing writes through Obsidian's own storage API. */
  persist() {
    const operation = this.writes.catch(() => void 0).then(async () => {
      var _a, _b, _c, _d, _e, _f, _g, _h, _i, _j;
      const data = JSON.parse(JSON.stringify({ settings: this.settings, credentialBinding: this.credentialBinding, device_token: this.deviceToken, session: this.session, enrollment: this.enrollment, pairingStatus: this.pairingStatus, sync: this.syncState, errors: this.errors }));
      const signature = this.credentialSignature();
      const verify = signature !== this.lastVerified && typeof this.loadData === "function";
      for (let attempt = 0; ; attempt++) {
        try {
          await this.saveData(data);
          if (verify) {
            const read = await this.loadData();
            if (!read || ((_a = read.credentialBinding) != null ? _a : null) !== ((_b = data.credentialBinding) != null ? _b : null) || ((_c = read.device_token) != null ? _c : "") !== ((_d = data.device_token) != null ? _d : "") || JSON.stringify((_e = read.session) != null ? _e : null) !== JSON.stringify((_f = data.session) != null ? _f : null) || JSON.stringify((_g = read.enrollment) != null ? _g : null) !== JSON.stringify((_h = data.enrollment) != null ? _h : null) || (data.device_token ? !validCredential(read.device_token) : false) || (data.session ? !sessionStructure(read.session) : false) || (data.enrollment ? !enrollmentStructure(read.enrollment) : false) || JSON.stringify((_i = read.settings) != null ? _i : null) !== JSON.stringify((_j = data.settings) != null ? _j : null)) throw new Error("credential read-back mismatch");
          }
          this.storageFailed = false;
          this.lastVerified = signature;
          if (this.pairingStatus.kind === "save-failed" && (this.deviceToken || this.session || this.enrollment)) {
            this.pairingStatus = this.derivedStatus();
            this.updateStatus();
          }
          return;
        } catch (e) {
          if (attempt > 0) {
            this.storageFailed = true;
            const error = localFailure("storage", "persistence_failure");
            this.recordDiagnostic(error.diagnostic);
            throw error;
          }
        }
      }
    });
    this.writes = operation;
    return operation;
  }
  async saveSettings() {
    this.settings = mergeSettings(this.settings);
    await this.persist();
  }
  async saveSync() {
    await this.persist();
    this.updateStatus();
  }
  transport() {
    if (this.storageFailed) {
      this.pairingStatus = { kind: "save-failed" };
      this.updateStatus();
      void this.persist().catch(() => void 0);
      throw localFailure("storage", "persistence_failure");
    }
    const bound = !!this.credentialBinding && this.credentialBinding === this.binding();
    const hasCredentials = !!(this.deviceToken || this.session || this.enrollment);
    if (hasCredentials && !bound) {
      this.pairingStatus = { kind: "binding-mismatch" };
      const error = localFailure("settings", "invalid_binding");
      this.recordDiagnostic(error.diagnostic);
      throw error;
    }
    try {
      validateServerUrl(this.settings.serverUrl);
      validateApiPrefix(this.settings.apiPrefix);
      if (typeof this.settings.vaultId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(this.settings.vaultId)) throw new Error();
      if (this.settings.serverFingerprint) validateServerFingerprint(this.settings.serverFingerprint);
    } catch (e) {
      const error = localFailure("settings", "invalid_settings");
      this.recordDiagnostic(error.diagnostic);
      throw error;
    }
    const binding = this.binding();
    const checkBinding = () => {
      if (binding !== this.binding() || this.unloaded) throw localFailure("credentials", "invalid_binding");
    };
    return new RequestUrlTransport({ ...this.settings }, this.session, this.enrollment, this.deviceToken, async (session) => {
      checkBinding();
      this.session = session;
      if (typeof this.saveData === "function") await this.saveSettings();
      checkBinding();
      this.pairingStatus = { kind: "ready" };
      this.updateStatus();
    }, this.recordDiagnostic, async () => {
      checkBinding();
      this.enrollment = void 0;
      if (typeof this.saveData === "function") await this.saveSettings();
    }, async () => {
      checkBinding();
      this.clearCredentials();
      this.pairingStatus = { kind: "not-paired" };
      if (typeof this.saveData === "function") await this.saveSettings();
      this.updateStatus();
    }, () => {
      this.requestsSent += 1;
    });
  }
  /**
   * Entry points use this instead of `transport()` so a sync started while the start-up renewal is
   * still in flight waits for it and then reuses the renewed ticket, instead of renewing a second
   * time and spending another session ticket.
   */
  async currentTransport() {
    if (this.recovery) {
      const pending = this.recovery;
      await pending.catch(() => void 0);
    }
    return this.transport();
  }
  included(file) {
    return !this.isLocalPluginPath(file.path) && !file.path.startsWith(`${this.app.vault.configDir || ".obsidian"}/workspace`) && !file.path.startsWith(`${this.app.vault.configDir || ".obsidian"}/cache/`) && !file.path.endsWith("/.authority.sqlite3") && file.path !== ".authority.sqlite3";
  }
  isUploadCandidate(file) {
    return this.included(file);
  }
  async localHashes() {
    var _a;
    const result = {};
    for (const file of this.app.vault.getFiles().filter((f) => this.included(f))) {
      let stat;
      try {
        stat = ((_a = this.app.vault.adapter) == null ? void 0 : _a.stat) ? await this.app.vault.adapter.stat(file.path) : void 0;
      } catch (e) {
        stat = void 0;
      }
      const cached = this.syncState.files[file.path];
      if (!this.dirtyPaths.has(file.path) && (cached == null ? void 0 : cached.localHash) && stat && stat.type !== "folder" && cached.localSize === stat.size && cached.localMtime === stat.mtime) result[file.path] = cached.localHash;
      else result[file.path] = await this.hash(await this.app.vault.readBinary(file));
      this.dirtyPaths.delete(file.path);
    }
    return result;
  }
  async hash(data) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
    return [...new Uint8Array(digest)].map((x) => x.toString(16).padStart(2, "0")).join("");
  }
  async ensureFolder(path) {
    const parts = path.split("/");
    parts.pop();
    let current = "";
    for (const part of parts) {
      current = current ? `${current}/${part}` : part;
      const indexed = this.app.vault.getAbstractFileByPath(current);
      if (indexed instanceof import_obsidian.TFile) return { ok: false, reason: `${current}: path is a file` };
      const stat = await this.app.vault.adapter.stat(current);
      if ((stat == null ? void 0 : stat.type) === "file") return { ok: false, reason: `${current}: path is a file` };
      if ((stat == null ? void 0 : stat.type) === "folder") continue;
      try {
        await this.app.vault.adapter.mkdir(current);
      } catch (error) {
        const after = await this.app.vault.adapter.stat(current);
        if ((after == null ? void 0 : after.type) === "folder") continue;
        if ((after == null ? void 0 : after.type) === "file") return { ok: false, reason: `${current}: path is a file` };
        throw new Error(`${current}: cannot create folder: ${safeError(error)}`);
      }
      const created = await this.app.vault.adapter.stat(current);
      if ((created == null ? void 0 : created.type) === "file") return { ok: false, reason: `${current}: path is a file` };
      if (!created || created.type !== "folder") throw new Error(`${current}: folder was not created`);
    }
    return { ok: true };
  }
  async writeFile(path, bytes, planner = "pull", expectedLocalHash) {
    var _a, _b;
    const changeVersion = (_a = this.changeVersions.get(path)) != null ? _a : 0;
    const folders = await this.ensureFolder(path);
    if (!folders.ok) return { status: "conflict", reason: folders.reason };
    const existing = this.app.vault.getAbstractFileByPath(path);
    const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    const incomingHash = await this.hash(buffer);
    const existingKind = existing instanceof import_obsidian.TFile ? "file" : existing ? "folder" : "none";
    const localHash = existing instanceof import_obsidian.TFile ? await this.hash(await this.app.vault.readBinary(existing)) : null;
    const decision = planLocalWrite({ planner, existing: existingKind, localHash, incomingHash, expectedLocalHash });
    if (decision.action === "abort") throw new Error(decision.reason);
    if (decision.action === "conflict") return { status: "conflict", reason: decision.reason };
    if (decision.action === "skip") return { status: "skipped" };
    this.internalWrites.add(path);
    try {
      if (decision.action === "modify" && existing instanceof import_obsidian.TFile) {
        if (expectedLocalHash !== void 0 && ((_b = this.changeVersions.get(path)) != null ? _b : 0) !== changeVersion) throw new Error("Local file changed during automatic pull");
        await this.app.vault.modifyBinary(existing, buffer);
      } else {
        try {
          await this.app.vault.createBinary(path, buffer);
        } catch (error) {
          const message = error instanceof Error ? error.message.toLowerCase() : "";
          for (let attempt = 0; attempt < 4; attempt++) {
            let raced2 = this.app.vault.getAbstractFileByPath(path);
            if (!raced2) {
              await waitMs(50 * (attempt + 1));
              raced2 = this.app.vault.getAbstractFileByPath(path);
            }
            const racedKind = raced2 instanceof import_obsidian.TFile ? "file" : raced2 ? "folder" : "none";
            const racedHash = raced2 instanceof import_obsidian.TFile ? await this.hash(await this.app.vault.readBinary(raced2)) : null;
            const reconciliation = reconcileCreateRace({ existing: racedKind, existingHash: racedHash, incomingHash });
            if (reconciliation.action === "reconciled") return { status: "skipped" };
            if (reconciliation.action === "conflict") return { status: "conflict", reason: reconciliation.reason };
            if (!message.includes("already exists")) throw error;
            try {
              await this.app.vault.createBinary(path, buffer);
              return { status: "written" };
            } catch (retryError) {
              if (!(retryError instanceof Error && retryError.message.toLowerCase().includes("already exists"))) throw retryError;
            }
          }
          const raced = this.app.vault.getAbstractFileByPath(path);
          if (raced instanceof import_obsidian.TFile) {
            const racedHash = await this.hash(await this.app.vault.readBinary(raced));
            if (racedHash === incomingHash) return { status: "skipped" };
          }
          if (message.includes("already exists")) return { status: "conflict", reason: "File exists outside the vault index; refresh and review before retrying" };
          throw error;
        }
      }
      return { status: "written" };
    } catch (error) {
      this.internalWrites.delete(path);
      throw error;
    } finally {
      globalThis.setTimeout(() => this.internalWrites.delete(path), 1e3);
    }
  }
  async autoPull() {
    const eligible = () => this.settings.syncPolicy === "pull-when-clean" && this.pairingStatus.kind === "ready" && !this.pairing && !this.syncing && !this.submitting && !this.uploading && !this.unloaded && !this.syncState.pendingSubmissions.length && !this.syncState.conflicts.length;
    if (!eligible()) return;
    const local = await this.localHashes();
    if (!isLocalClean(this.syncState, local)) return;
    if (eligible()) await this.syncWithServer(true);
  }
  async syncWithServer(pullOnly = false) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _i;
    if (this.syncing || this.submitting || this.pairing) {
      new import_obsidian.Notice("Sync already in progress.");
      return;
    }
    this.syncing = true;
    const diagnosticsBefore = this.diagnosticSequence;
    const requestsBefore = this.requestsSent;
    try {
      const transport = await this.currentTransport();
      const manifest = await transport.manifest();
      if (manifest.protocol_version !== PROTOCOL_VERSION || !manifest.revision_id) throw new Error("unsupported or invalid manifest");
      const validatedManifest = validateSyncManifest(manifest);
      const manifestComplete = validatedManifest.complete;
      const local = await this.localHashes();
      if (pullOnly && !isLocalClean(this.syncState, local)) return;
      const server = /* @__PURE__ */ Object.create(null);
      for (const file of manifest.files) {
        const path = validateRelativePath(file.path);
        if (!this.included({ path })) throw new Error("Server manifest contains a protected local path");
        server[path] = file;
      }
      const blockedPaths = /* @__PURE__ */ new Set();
      for (const entry of (_a = manifest.blocked) != null ? _a : []) {
        if (!entry || typeof entry.path !== "string") continue;
        let path;
        try {
          path = validateRelativePath(entry.path);
        } catch (e) {
          continue;
        }
        if (!this.included({ path })) continue;
        blockedPaths.add(path);
        delete server[path];
      }
      const retryExcluded = new Set(this.excludedRetries);
      this.excludedRetries.clear();
      const decisions = planSync(this.syncState, local, server, {}, {}, blockedPaths, { allowLocalSubmissions: false, allowLocalDeletes: manifestComplete, manifestComplete, retryExcluded });
      const reviews = [];
      let pulled = 0;
      let deleted = 0;
      let alreadyCurrent = 0;
      const failures = [];
      for (const decision of decisions) {
        try {
          if (decision.kind === "pull") {
            const file = await transport.readFile(decision.path);
            if (validateRelativePath(file.path) !== decision.path) throw new Error("Corrupted file transfer");
            const bytes = base64ToBytes(file.content_base64);
            const manifestFile = manifest.files.find((entry) => entry.path === decision.path);
            if (manifestFile && typeof manifestFile.size === "number" && manifestFile.size !== bytes.byteLength) throw new Error("Corrupted file transfer");
            if (await this.hash(bytes.buffer) !== decision.serverHash) throw new Error("Corrupted file transfer");
            if (decision.reason === "server-authoritative-overwrite" && local[decision.path] !== null && local[decision.path] !== void 0) await this.cacheLocalBeforeOverwrite(decision.path, manifest.revision_id, decision.serverHash, local[decision.path]);
            const result = await this.writeFile(decision.path, bytes, "pull", (_b = local[decision.path]) != null ? _b : null);
            if (result.status === "conflict") reviews.push(`${decision.path}: ${(_c = result.reason) != null ? _c : "path collision; manual review required"}`);
            else {
              this.syncState.files[decision.path] = { baseHash: decision.serverHash, localHash: decision.serverHash };
              local[decision.path] = decision.serverHash;
              this.dirtyPaths.delete(decision.path);
              delete this.syncState.excludedFiles[decision.path];
              if (result.status === "written") pulled++;
              else alreadyCurrent++;
            }
          } else if (decision.kind === "delete-local") {
            if (await this.cacheLocalBeforeDeletion(decision.path, manifest.revision_id, decision.localHash)) {
              deleted++;
              delete local[decision.path];
              delete this.syncState.files[decision.path];
            }
          } else if (decision.kind === "submit" && !pullOnly) {
            const pending = await this.pendingFor(decision.path, decision.operation, manifest.revision_id);
            if (pending) this.syncState.pendingSubmissions.push(pending);
          } else if (decision.kind === "excluded") {
            this.syncState.excludedFiles[decision.path] = { serverHash: decision.serverHash, size: decision.size, reason: "file-too-large" };
            reviews.push(`${decision.path}: ${decision.reason}`);
          } else if (decision.kind === "review") reviews.push(`${decision.path}: ${decision.reason}`);
          else if (decision.kind === "clean") {
            this.syncState.files[decision.path] = { ...this.syncState.files[decision.path], baseHash: decision.hash, localHash: decision.hash };
            alreadyCurrent++;
          } else if (decision.kind === "conflict") {
            reviews.push(`${decision.path}: ${(_d = decision.reason) != null ? _d : "manual review required"}`);
            await this.cacheConflict(transport, manifest.revision_id, decision);
          }
        } catch (error) {
          const diagnostic = error == null ? void 0 : error.diagnostic;
          failures.push({ path: decision.path, message: safeError(error), status: (_e = diagnostic == null ? void 0 : diagnostic.status) != null ? _e : error == null ? void 0 : error.status, retryable: (_f = diagnostic == null ? void 0 : diagnostic.retryable) != null ? _f : false, diagnostic });
        }
      }
      for (const file of this.app.vault.getFiles().filter((f) => this.included(f))) {
        let stat;
        try {
          stat = ((_g = this.app.vault.adapter) == null ? void 0 : _g.stat) ? await this.app.vault.adapter.stat(file.path) : void 0;
        } catch (e) {
          stat = void 0;
        }
        if (stat && stat.type !== "folder" && this.syncState.files[file.path]) {
          const knownHash = (_h = local[file.path]) != null ? _h : this.syncState.files[file.path].baseHash;
          this.syncState.files[file.path] = { ...this.syncState.files[file.path], localHash: knownHash, localSize: stat.size, localMtime: stat.mtime };
        }
      }
      try {
        this.localDirty = !isLocalClean(this.syncState, await this.localHashes());
      } catch (e) {
        this.localDirty = true;
      }
      if (!failures.length) this.syncState.serverRevision = manifest.revision_id;
      await this.saveSync();
      const active = this.app.workspace.getActiveFile();
      const activeConflict = active && this.syncState.conflicts.some((c) => c.path === active.path);
      if (activeConflict) new import_obsidian.Notice("\u5F53\u524D\u7B14\u8BB0\u5B58\u5728\u672A\u89E3\u51B3\u51B2\u7A81\uFF1B\u672C\u5730\u5185\u5BB9\u672A\u88AB\u8986\u76D6\u3002");
      new import_obsidian.Notice(syncNotice(decisions, reviews, failures, manifest.files.length, { pulled, deleted, alreadyCurrent }));
    } catch (error) {
      const diagnostic = error == null ? void 0 : error.diagnostic;
      const pairingRequired = (diagnostic == null ? void 0 : diagnostic.reason) === "missing_credentials" || (diagnostic == null ? void 0 : diagnostic.reason) === "credentials_rejected" || this.pairingStatus.kind === "not-paired" && ((_i = this.errors.at(-1)) == null ? void 0 : _i.status) === 401;
      const answered = this.requestsSent > requestsBefore;
      if (this.diagnosticSequence === diagnosticsBefore) {
        const recorded = diagnostic != null ? diagnostic : localFailure("sync", "local_operation_failed", answered).diagnostic;
        if (recorded.reason && answered && recorded.requestSent === void 0) recorded.requestSent = true;
        this.recordDiagnostic(recorded);
      }
      try {
        await this.saveSync();
      } catch (e) {
      }
      this.updateStatus(true);
      const heading = pairingRequired ? "Pairing required. Open Settings \u2192 Server Authority Sync \u2192 Advanced settings \u2192 Device pairing \u2192 Test and pair." : (diagnostic == null ? void 0 : diagnostic.reason) === "persistence_failure" ? "Sync blocked: plugin state could not be stored or verified." : `Sync failed: ${safeError(error)}.`;
      new import_obsidian.Notice(`${heading} ${this.diagnosticSummary()} State was retained.`, 15e3);
    } finally {
      this.syncing = false;
    }
  }
  async pendingFor(path, operation, baseRevisionId) {
    if (this.syncState.pendingSubmissions.some((s) => s.changes.some((c) => c.path === path))) return null;
    const change = { path, operation };
    if (operation === "write") {
      const file = this.app.vault.getAbstractFileByPath(path);
      if (!(file instanceof import_obsidian.TFile)) return null;
      const bytes = new Uint8Array(await this.app.vault.readBinary(file));
      change.contentBase64 = bytesToBase64(bytes);
      change.sha256 = await this.hash(bytes.buffer);
      if (change.contentBase64.length > MAX_CHANGE_BYTES) throw oversizedChangeError(change.contentBase64.length);
    }
    return createPendingSubmission(baseRevisionId, [change]);
  }
  async persistOverwriteBackup(record) {
    var _a, _b;
    for (let attempt = 0; attempt < 2; attempt++) {
      await this.saveSync();
      let data = null;
      try {
        data = await this.loadData();
      } catch (e) {
      }
      const saved = (_b = (_a = data == null ? void 0 : data.sync) == null ? void 0 : _a.overwriteBackups) == null ? void 0 : _b.find((item) => item.cachePath === record.cachePath);
      if (saved && saved.path === record.path && saved.localHash === record.localHash && saved.serverHash === record.serverHash && saved.serverRevisionId === record.serverRevisionId && saved.cacheHash === record.cacheHash && saved.createdAt === record.createdAt) return;
    }
    this.storageFailed = true;
    this.pairingStatus = { kind: "save-failed" };
    this.updateStatus();
    const error = localFailure("storage", "persistence_failure");
    this.recordDiagnostic(error.diagnostic);
    throw error;
  }
  async cacheLocalBeforeOverwrite(path, revision, serverHash, expectedLocalHash) {
    var _a;
    const local = this.app.vault.getAbstractFileByPath(path);
    if (!(local instanceof import_obsidian.TFile)) throw new Error("Local file disappeared before its overwrite backup");
    const bytes = new Uint8Array(await this.app.vault.readBinary(local));
    const localHash = await this.hash(bytes.buffer);
    if (localHash !== expectedLocalHash) throw new Error("Local file changed before its overwrite backup");
    const cachePath = `${this.pluginRoot()}/overwrites/${encodeURIComponent(path)}-${encodeURIComponent(revision)}-${localHash}.bin`;
    const saved = await this.writeFile(cachePath, bytes, "cache");
    if (saved.status === "conflict") throw new Error((_a = saved.reason) != null ? _a : "Overwrite backup could not be stored safely");
    const cachedFile = this.app.vault.getAbstractFileByPath(cachePath);
    if (!(cachedFile instanceof import_obsidian.TFile)) throw new Error("Overwrite backup is not readable");
    const cachedBytes = new Uint8Array(await this.app.vault.readBinary(cachedFile));
    const cacheHash = await this.hash(cachedBytes.buffer);
    if (cacheHash !== localHash) throw new Error("Overwrite backup verification failed");
    const record = { path, localHash, serverHash, serverRevisionId: revision, cachePath, cacheHash, createdAt: (/* @__PURE__ */ new Date()).toISOString() };
    const existing = this.syncState.overwriteBackups.findIndex((item) => item.cachePath === cachePath);
    if (existing >= 0) this.syncState.overwriteBackups[existing] = record;
    else this.syncState.overwriteBackups.push(record);
    await this.persistOverwriteBackup(record);
  }
  async persistDeletionBackup(record) {
    var _a, _b;
    for (let attempt = 0; attempt < 2; attempt++) {
      await this.saveSync();
      let data = null;
      try {
        data = await this.loadData();
      } catch (e) {
      }
      const saved = (_b = (_a = data == null ? void 0 : data.sync) == null ? void 0 : _a.deletionBackups) == null ? void 0 : _b.find((item) => item.cachePath === record.cachePath);
      if (saved && saved.path === record.path && saved.localHash === record.localHash && saved.serverRevisionId === record.serverRevisionId && saved.cacheHash === record.cacheHash && saved.createdAt === record.createdAt) return;
    }
    this.storageFailed = true;
    this.pairingStatus = { kind: "save-failed" };
    this.updateStatus();
    const error = localFailure("storage", "persistence_failure");
    this.recordDiagnostic(error.diagnostic);
    throw error;
  }
  async cacheLocalBeforeDeletion(path, revision, expectedLocalHash) {
    var _a, _b;
    const local = this.app.vault.getAbstractFileByPath(path);
    if (!(local instanceof import_obsidian.TFile)) throw new Error("Local file disappeared before its deletion backup");
    const bytes = new Uint8Array(await this.app.vault.readBinary(local));
    const localHash = await this.hash(bytes.buffer);
    if (localHash !== expectedLocalHash) throw new Error("Local file changed before its deletion backup");
    const cachePath = `${this.pluginRoot()}/deletions/${encodeURIComponent(path)}-${encodeURIComponent(revision)}-${localHash}.bin`;
    const saved = await this.writeFile(cachePath, bytes, "cache");
    if (saved.status === "conflict") throw new Error((_a = saved.reason) != null ? _a : "Local deletion backup could not be stored safely");
    const cachedFile = this.app.vault.getAbstractFileByPath(cachePath);
    if (!(cachedFile instanceof import_obsidian.TFile)) throw new Error("Local deletion backup is not readable");
    const cachedBytes = new Uint8Array(await this.app.vault.readBinary(cachedFile));
    const cacheHash = await this.hash(cachedBytes.buffer);
    if (cacheHash !== localHash) throw new Error("Local deletion backup verification failed");
    const record = { path, localHash, serverRevisionId: revision, cachePath, cacheHash, createdAt: (/* @__PURE__ */ new Date()).toISOString() };
    const deletionBackups = (_b = this.syncState.deletionBackups) != null ? _b : this.syncState.deletionBackups = [];
    const existing = deletionBackups.findIndex((item) => item.cachePath === cachePath);
    if (existing >= 0) deletionBackups[existing] = record;
    else deletionBackups.push(record);
    await this.persistDeletionBackup(record);
    const current = this.app.vault.getAbstractFileByPath(path);
    if (!(current instanceof import_obsidian.TFile)) throw new Error("Local file disappeared before deletion");
    const currentBytes = new Uint8Array(await this.app.vault.readBinary(current));
    if (await this.hash(currentBytes.buffer) !== localHash) throw new Error("Local file changed; deletion cancelled");
    await this.app.vault.delete(current);
    return true;
  }
  async openOverwriteBackup(record) {
    try {
      const cachedFile = this.app.vault.getAbstractFileByPath(record.cachePath);
      if (!(cachedFile instanceof import_obsidian.TFile)) throw new Error("Preserved local copy is missing");
      const bytes = new Uint8Array(await this.app.vault.readBinary(cachedFile));
      const hash = await this.hash(bytes.buffer);
      if (hash !== record.cacheHash || hash !== record.localHash) throw new Error("Preserved local copy verification failed");
      await this.app.workspace.openLinkText(record.cachePath, "", false);
    } catch (error) {
      new import_obsidian.Notice(`${record.path}: preserved local copy could not be opened; ${safeError(error)}.`);
    }
  }
  async verifyOverwriteBackup(record) {
    try {
      const cachedFile = this.app.vault.getAbstractFileByPath(record.cachePath);
      if (!(cachedFile instanceof import_obsidian.TFile)) throw new Error("Preserved local copy is missing");
      const bytes = new Uint8Array(await this.app.vault.readBinary(cachedFile));
      const hash = await this.hash(bytes.buffer);
      if (hash !== record.cacheHash || hash !== record.localHash) throw new Error("Preserved local copy verification failed");
      new import_obsidian.Notice(`${record.path}: preserved local copy verified.`);
    } catch (error) {
      new import_obsidian.Notice(`${record.path}: preserved local copy verification failed; ${safeError(error)}.`);
    }
  }
  /** Redirect legacy selection callers through the explicit upload confirmation. */
  async selectLocalChanges(paths) {
    this.reviewLocalUpload(paths);
  }
  uploadConfirmationFor(paths) {
    var _a;
    const server = /* @__PURE__ */ Object.create(null);
    for (const path of Object.keys(this.syncState.files)) {
      const hash = this.syncState.files[path].baseHash;
      if (hash) server[path] = { path, sha256: hash, size: (_a = this.syncState.files[path].localSize) != null ? _a : 0 };
    }
    return uploadConfirmation(paths, server);
  }
  reviewLocalUpload(paths) {
    const unique = [...new Set(paths.map((path) => validateRelativePath(path)))];
    if (!unique.length) {
      new import_obsidian.Notice("No local paths selected.");
      return;
    }
    if (!this.syncState.serverRevision) {
      new import_obsidian.Notice("Sync with server before uploading so expected server hashes are current.");
      return;
    }
    new UploadConfirmationModal(this.app, this, unique).open();
  }
  async uploadSelected(paths) {
    var _a, _b;
    const unique = [...new Set(paths.map((path) => validateRelativePath(path)))];
    if (!unique.length) return void 0;
    if (!this.syncState.serverRevision) throw new Error("Sync with server before uploading so expected server hashes are current.");
    if (this.uploading || this.syncing || this.submitting || this.pairing) return void 0;
    this.uploading = true;
    this.updateStatus();
    try {
      const files = [];
      for (const path of unique) {
        const file = this.app.vault.getAbstractFileByPath(path);
        if (!(file instanceof import_obsidian.TFile) || !this.included(file)) throw new Error(`${path}: local file is no longer available for upload`);
        const bytes = new Uint8Array(await this.app.vault.readBinary(file));
        if (bytes.byteLength > MAX_SYNC_FILE_BYTES) throw new Error(`${path}: file is larger than the 16 MiB per-file server limit; it was not uploaded`);
        const sha256 = await this.hash(bytes.buffer);
        files.push({ path, contentBase64: bytesToBase64(bytes), sha256, expectedServerSha256: (_b = (_a = this.syncState.files[path]) == null ? void 0 : _a.baseHash) != null ? _b : null });
      }
      const result = await (await this.currentTransport()).upload(files);
      for (const file of files) this.syncState.files[file.path] = { baseHash: file.sha256, localHash: file.sha256, localSize: atob(file.contentBase64).length };
      if (result.revision_id) this.syncState.serverRevision = result.revision_id;
      this.localDirty = !isLocalClean(this.syncState, await this.localHashes());
      await this.saveSync();
      new import_obsidian.Notice(`Upload complete: ${result.added} added, ${result.overwritten} overwritten. Server revision advanced.`);
      return result;
    } catch (error) {
      new import_obsidian.Notice(`Upload failed: ${safeError(error)}. No local deletion was performed; state was retained.`);
      throw error;
    } finally {
      this.uploading = false;
      this.updateStatus();
    }
  }
  async cacheConflict(transport, revision, decision) {
    var _a, _b, _c, _d;
    const existing = this.syncState.conflicts.find((c) => c.path === decision.path && c.serverRevisionId === revision);
    if (existing == null ? void 0 : existing.serverCachePath) return;
    let cachePath = "";
    let cacheHash = null;
    const candidate = `${this.pluginRoot()}/conflicts/${encodeURIComponent(decision.path)}-${encodeURIComponent(revision)}.bin`;
    try {
      let bytes;
      if (decision.serverHash) {
        const file = await transport.readFile(decision.path);
        bytes = base64ToBytes(file.content_base64);
        if (file.path !== decision.path || await this.hash(bytes.buffer) !== decision.serverHash) throw new Error("Corrupted conflict transfer");
      } else {
        const local = this.app.vault.getAbstractFileByPath(decision.path);
        if (!(local instanceof import_obsidian.TFile)) throw new Error("local deletion review has no bytes to cache");
        bytes = new Uint8Array(await this.app.vault.readBinary(local));
        if (await this.hash(bytes.buffer) !== decision.localHash) throw new Error("Local deletion review changed before backup");
      }
      const result = await this.writeFile(candidate, bytes, "cache");
      if (result.status !== "conflict") {
        cachePath = candidate;
        cacheHash = await this.hash(bytes.buffer);
      }
    } catch (error) {
      this.recordDiagnostic({ stage: "conflict-cache", code: "invalid_response", retryCount: 0, retryable: true });
    }
    const record = { conflictId: (_a = existing == null ? void 0 : existing.conflictId) != null ? _a : crypto.randomUUID(), path: decision.path, paths: [decision.path], baseHash: decision.baseHash, localHash: decision.localHash, serverHash: decision.serverHash, serverRevisionId: revision, serverCachePath: cachePath || (existing == null ? void 0 : existing.serverCachePath) || "", cacheHash: (_b = cacheHash != null ? cacheHash : existing == null ? void 0 : existing.cacheHash) != null ? _b : null, createdAt: (_c = existing == null ? void 0 : existing.createdAt) != null ? _c : (/* @__PURE__ */ new Date()).toISOString(), reason: (_d = decision.reason) != null ? _d : "same-path concurrent change", scope: "same-path", resolution: existing == null ? void 0 : existing.resolution };
    if (existing) Object.assign(existing, record);
    else this.syncState.conflicts.push(record);
  }
  async deleteServerDeletion(conflictId) {
    const record = this.syncState.conflicts.find((item) => item.conflictId === conflictId);
    if (!record || record.resolution || record.serverHash !== null || record.reason !== "server-deletion-retained-locally" || !record.serverCachePath || !record.localHash) {
      new import_obsidian.Notice("Local deletion is not available: a verified recovery cache is required.");
      return;
    }
    try {
      const cached = new Uint8Array(await this.app.vault.readBinary({ path: record.serverCachePath }));
      const cachedHash = await this.hash(cached.buffer);
      if (cachedHash !== record.localHash || record.cacheHash && cachedHash !== record.cacheHash) throw new Error("Recovery cache verification failed");
      const local = this.app.vault.getAbstractFileByPath(record.path);
      if (!(local instanceof import_obsidian.TFile)) throw new Error("Local file is already absent");
      const current = new Uint8Array(await this.app.vault.readBinary(local));
      if (await this.hash(current.buffer) !== record.localHash) throw new Error("Local file changed; deletion cancelled");
      await this.app.vault.delete(local);
      delete this.syncState.files[record.path];
      record.resolution = "deleted";
      await this.saveSync();
      new import_obsidian.Notice(`${record.path}: local copy deleted; recovery cache retained.`);
    } catch (error) {
      new import_obsidian.Notice(`${record.path}: deletion cancelled; ${safeError(error)}.`);
    }
  }
  async retryExcludedFile(path) {
    path = validateRelativePath(path);
    if (!this.syncState.excludedFiles[path]) {
      new import_obsidian.Notice(`${path}: no excluded large-file record is available.`);
      return;
    }
    this.excludedRetries.add(path);
    await this.syncWithServer();
  }
  async submitPendingChanges() {
    var _a;
    if (this.submitting || this.syncing || this.pairing) return;
    this.submitting = true;
    const counts = { sent: 0, conflicts: 0, retryable: 0, nonRetryable: 0, skipped: 0 };
    try {
      const transport = await this.currentTransport();
      for (const item of [...this.syncState.pendingSubmissions]) {
        if (item.submitted || item.blocked) {
          counts.skipped++;
          continue;
        }
        try {
          const result = await transport.submit(item);
          if (result.kind === "conflict") {
            item.blocked = true;
            item.lastError = "same-path server change; refresh and review affected paths";
            item.diagnostic = "stale_revision/path_conflict";
            counts.conflicts++;
          } else {
            item.submitted = true;
            item.lastError = void 0;
            counts.sent++;
          }
        } catch (error) {
          const message = safeError(error);
          const details = error && typeof error === "object" ? error : {};
          const classification = classifySubmitResult(details);
          item.lastError = message;
          item.diagnostic = (_a = details.code) != null ? _a : classification;
          if (classification === "conflict-review-required") {
            item.blocked = true;
            counts.conflicts++;
          } else if (classification === "non-retryable-blocked") {
            item.blocked = true;
            counts.nonRetryable++;
          } else {
            item.retryCount++;
            counts.retryable++;
          }
        }
        await this.saveSync();
      }
      await this.saveSync();
      new import_obsidian.Notice(`Sent to server/pending review: ${counts.sent}; conflicts: ${counts.conflicts}; retryable failures: ${counts.retryable}; non-retryable failures: ${counts.nonRetryable}; skipped/already submitted: ${counts.skipped}.`, 12e3);
    } catch (error) {
      this.updateStatus(true);
      new import_obsidian.Notice(`Submit failed: ${safeError(error)}. State was retained.`);
    } finally {
      this.submitting = false;
    }
  }
  async openConflicts() {
    if (!this.syncState.conflicts.length && !this.syncState.overwriteBackups.length) {
      new import_obsidian.Notice("No conflicts or preserved local copies.");
      return;
    }
    new ConflictModal(this.app, this).open();
  }
  openLocalUploadPicker() {
    new LocalUploadPickerModal(this.app, this).open();
  }
  async openPendingSubmissions() {
    if (!pendingDisplayRows(this.syncState.pendingSubmissions).length) {
      new import_obsidian.Notice("No pending submissions.");
      return;
    }
    new PendingSubmissionsModal(this.app, this).open();
  }
  syncStateForUi() {
    return this.syncState.conflicts;
  }
  overwriteBackupsForUi() {
    return this.syncState.overwriteBackups;
  }
  syncStateForUiExcluded() {
    return this.syncState.excludedFiles;
  }
  pendingForUi() {
    return this.syncState.pendingSubmissions;
  }
  async refreshPendingSubmissions() {
    var _a;
    try {
      const result = await (await this.currentTransport()).submissions();
      const remote = new Map(((_a = result.submissions) != null ? _a : []).map((item) => [item.submission_id, item.status]));
      this.syncState.pendingSubmissions = this.syncState.pendingSubmissions.filter((item) => {
        const status = remote.get(item.submissionId);
        if (status === "approved" || status === "rejected") return false;
        if (status === "pending") item.submitted = true;
        return true;
      });
      await this.saveSync();
      new import_obsidian.Notice("Pending submissions refreshed.");
    } catch (error) {
      new import_obsidian.Notice(`Refresh failed: ${safeError(error)}`);
    }
  }
  async retryFailedSubmissions() {
    for (const item of this.syncState.pendingSubmissions) if (!item.blocked && item.lastError) item.lastError = void 0;
    await this.saveSync();
    await this.submitPendingChanges();
  }
  reviewBlockedSubmissions() {
    new import_obsidian.Notice("Review required: resolve blocked paths or conflicts before resubmitting.", 1e4);
  }
  async discardPending(submissionId) {
    this.syncState.pendingSubmissions = this.syncState.pendingSubmissions.filter((item) => item.submissionId !== submissionId || item.submitted);
    await this.saveSync();
  }
  async openConflictCache(record) {
    if (record.serverCachePath) await this.app.workspace.openLinkText(record.serverCachePath, "", false);
  }
  async resolveConflict(conflictId) {
    this.syncState.conflicts = this.syncState.conflicts.filter((conflict) => conflict.conflictId !== conflictId);
    await this.saveSync();
  }
  async testConnection() {
    try {
      const result = await (await this.currentTransport()).health();
      if (result.protocol_version !== PROTOCOL_VERSION) throw new Error("unsupported protocol version");
      this.updateStatus();
      new import_obsidian.Notice("Server connection succeeded.");
    } catch (error) {
      this.updateStatus(true);
      new import_obsidian.Notice(`Connection failed: ${safeError(error)}`);
    }
  }
  async checkServerVersion(silent = false) {
    try {
      const info = await (await this.currentTransport()).serverInfo();
      if (info.protocol_version !== PROTOCOL_VERSION || info.vault_id && info.vault_id !== this.settings.vaultId || !serverFingerprintMatches(this.settings.serverFingerprint, info.server_fingerprint)) throw new Error("server identity does not match settings");
      this.updateStatus();
      if (!silent) new import_obsidian.Notice(`Server protocol version: ${info.protocol_version}.`);
      return true;
    } catch (error) {
      this.updateStatus(true);
      if (!silent) new import_obsidian.Notice(`Version check failed: ${safeError(error)}`);
      return false;
    }
  }
  exportableConfiguration() {
    return nonSensitiveLinkConfiguration({ serverUrl: (() => {
      try {
        return validateServerUrl(this.settings.serverUrl);
      } catch (e) {
        return "";
      }
    })(), apiPrefix: this.settings.apiPrefix, vaultId: this.settings.vaultId, serverFingerprint: this.settings.serverFingerprint });
  }
  async exportConfiguration() {
    var _a;
    const text = JSON.stringify(this.exportableConfiguration(), null, 2);
    try {
      const clipboard = (_a = globalThis.navigator) == null ? void 0 : _a.clipboard;
      if (!clipboard) throw new Error("clipboard unavailable");
      await clipboard.writeText(text);
      new import_obsidian.Notice("Non-sensitive configuration copied to the clipboard.");
    } catch (e) {
      new ConfigurationExportModal(this.app, text).open();
    }
  }
  async applySetup(config) {
    var _a, _b, _c;
    const next = mergeSettings({ serverUrl: config.server_url, apiPrefix: config.api_prefix ? validateApiPrefix(config.api_prefix) : DEFAULT_API_PREFIX, vaultId: config.vault_id, serverFingerprint: (_a = config.server_fingerprint) != null ? _a : "", syncPolicy: "manual", autoCheckIntervalMinutes: (_b = config.auto_check_interval_minutes) != null ? _b : 30, aiProvider: { ...DEFAULT_SETTINGS.aiProvider, ...(_c = config.ai_provider) != null ? _c : {} } });
    const credentials = config.setup_token ? await new RequestUrlTransport(next).redeemSetup(config.setup_token) : void 0;
    if (credentials && (!validSession(credentials) || !credentials.device_token)) throw new Error("Invalid pairing session");
    this.settings = next;
    if (credentials) {
      this.clearCredentials();
      this.deviceToken = credentials.device_token;
      this.session = { ticket: credentials.ticket, expires_at: credentials.expires_at };
      this.credentialBinding = this.binding();
      this.pairingStatus = { kind: "saving" };
    } else {
      this.pairingStatus = this.derivedStatus();
    }
    await this.saveSettings();
    if (credentials) {
      this.pairingStatus = { kind: "ready" };
      await this.saveSettings();
    }
  }
  async importSetupUri(params) {
    try {
      await this.applySetup(validateSetupUriParameters(params));
      new import_obsidian.Notice("One-time setup imported.");
    } catch (error) {
      new import_obsidian.Notice(`Setup URI rejected: ${safeError(error)}`);
    }
  }
  async importSetupConfiguration() {
    new SetupImportModal(this.app, (input) => this.importSetupText(input)).open();
  }
  async importSetupText(input) {
    var _a, _b, _c, _d, _e;
    if (!input) return;
    try {
      if (input.startsWith("obsidian://")) {
        const url = new URL(input);
        await this.applySetup(validateSetupUriParameters({ action: "setup", protocol_version: (_a = url.searchParams.get("protocol_version")) != null ? _a : void 0, server_url: (_b = url.searchParams.get("server_url")) != null ? _b : void 0, api_prefix: (_c = url.searchParams.get("api_prefix")) != null ? _c : void 0, vault_id: (_d = url.searchParams.get("vault_id")) != null ? _d : void 0, setup_token: (_e = url.searchParams.get("setup_token")) != null ? _e : void 0 }));
      } else await this.applySetup(validateSetupConfig(JSON.parse(input)));
      new import_obsidian.Notice("Setup/configuration imported. Test and pair if this was a non-sensitive link.");
    } catch (error) {
      new import_obsidian.Notice(`Setup/configuration rejected: ${safeError(error)}`);
    }
  }
};
var AuthoritySettingTab = class extends import_obsidian.PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }
  hide() {
    this.plugin.statusListener = void 0;
  }
  display() {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.createEl("h2", { text: "Server authority sync" });
    const status = new import_obsidian.Setting(containerEl).setName("Current status").setDesc(this.plugin.statusText());
    status.addButton((b) => b.setButtonText(this.plugin.syncing ? "Syncing\u2026" : "Sync with server").setDisabled(this.plugin.syncing).onClick(async () => {
      b.setDisabled(true);
      try {
        await this.plugin.syncWithServer();
      } finally {
        b.setDisabled(false);
        this.display();
      }
    }));
    status.addButton((b) => b.setButtonText("Upload local files").setDisabled(this.plugin.uploading).onClick(() => this.plugin.openLocalUploadPicker()));
    applyActionRowLayout(status.controlEl);
    const common = new import_obsidian.Setting(containerEl).setName("Common actions").setDesc("Use these commands for normal synchronization. Server and pairing settings are under Advanced settings.");
    common.addButton((b) => b.setButtonText("Copy diagnostics").onClick(() => void this.plugin.copyDiagnostics()));
    const diagnostic = new import_obsidian.Setting(containerEl).setName("Diagnostics").setDesc(this.plugin.diagnosticSummary());
    this.plugin.statusListener = () => {
      status.setDesc(this.plugin.statusText());
      diagnostic.setDesc(this.plugin.diagnosticSummary());
    };
    common.addButton((b) => b.setButtonText("Open conflicts").onClick(() => void this.plugin.openConflicts()));
    common.addButton((b) => b.setButtonText("Upload local files").onClick(() => this.plugin.openLocalUploadPicker()));
    for (const path of Object.keys(this.plugin.syncStateForUiExcluded())) common.addButton((b) => b.setButtonText(`Retry excluded ${path}`).onClick(async () => {
      b.setDisabled(true);
      try {
        await this.plugin.retryExcludedFile(path);
        this.display();
      } finally {
        b.setDisabled(false);
      }
    }));
    applyActionRowLayout(common.controlEl);
    const advanced = containerEl.createEl("details", { cls: "server-authority-advanced-settings" });
    advanced.createEl("summary", { text: "Advanced settings (server, pairing, automation, AI)" });
    const advancedEl = advanced.createEl("div");
    const saved = async (save) => {
      try {
        await save();
      } catch (error) {
        new import_obsidian.Notice(safeError(error));
      }
    };
    const text = (name, value, save, desc) => new import_obsidian.Setting(advancedEl).setName(name).setDesc(desc != null ? desc : "").addText((t) => t.setValue(value).onChange(async (value2) => {
      await saved(() => save(value2.trim()));
    }));
    text("Server URL", this.plugin.settings.serverUrl, async (value) => {
      this.plugin.settings.serverUrl = value;
      await this.plugin.saveSettings();
    }, "HTTPS is required except for localhost development.");
    text("API prefix", this.plugin.settings.apiPrefix, async (value) => {
      try {
        this.plugin.settings.apiPrefix = validateApiPrefix(value);
        await this.plugin.saveSettings();
      } catch (error) {
        new import_obsidian.Notice(safeError(error));
      }
    });
    text("Vault ID", this.plugin.settings.vaultId, async (value) => {
      this.plugin.settings.vaultId = value;
      await this.plugin.saveSettings();
    });
    text("Server fingerprint", this.plugin.settings.serverFingerprint, async (value) => {
      this.plugin.settings.serverFingerprint = value;
      await this.plugin.saveSettings();
    }, "Required for automatic pairing. Obtain the exact public fingerprint from your administrator.");
    const pairing = new import_obsidian.Setting(advancedEl).setName("Device pairing").setDesc(`${pairingStatusLabel(this.plugin.pairingStatus)}. Credentials are stored only in plugin data.`).addButton((b) => b.setButtonText(this.plugin.pairing ? "Pairing\u2026" : "Test and pair").setDisabled(this.plugin.pairing).onClick(async () => {
      b.setDisabled(true);
      await this.plugin.testAndPair();
      this.display();
    }));
    applyActionRowLayout(pairing.controlEl);
    new import_obsidian.Setting(advancedEl).setName("Automatic check interval (minutes)").addText((t) => t.setValue(String(this.plugin.settings.autoCheckIntervalMinutes)).onChange(async (value) => {
      const number = Number(value);
      if (Number.isInteger(number) && number >= 0 && number <= 1440) {
        this.plugin.settings.autoCheckIntervalMinutes = number;
        await saved(() => this.plugin.saveSettings());
      }
    }));
    new import_obsidian.Setting(advancedEl).setName("Sync policy").setDesc("Server downloads are authoritative by default. Obsidian APIs cannot enforce OS-level read-only or immutable locking.").addDropdown((d) => d.addOption("server-authoritative", "Server authoritative (read-only by policy)").addOption("manual", "Manual").addOption("pull-when-clean", "Pull when clean").setValue(this.plugin.settings.syncPolicy).onChange(async (value) => {
      this.plugin.settings.syncPolicy = value;
      await saved(() => this.plugin.saveSettings());
    }));
    advancedEl.createEl("h3", { text: "AI provider (optional, no credentials)" });
    text("Provider", this.plugin.settings.aiProvider.provider, async (value) => {
      this.plugin.settings.aiProvider.provider = value;
      await this.plugin.saveSettings();
    });
    text("Model", this.plugin.settings.aiProvider.model, async (value) => {
      this.plugin.settings.aiProvider.model = value;
      await this.plugin.saveSettings();
    });
    text("Endpoint", this.plugin.settings.aiProvider.endpoint, async (value) => {
      this.plugin.settings.aiProvider.endpoint = value;
      await this.plugin.saveSettings();
    });
    const actions = new import_obsidian.Setting(advancedEl).setName("Advanced actions").addButton((b) => b.setButtonText("Copy configuration link").onClick(() => void this.plugin.exportConfiguration())).addButton((b) => b.setButtonText("Paste setup/config link").onClick(() => void this.plugin.importSetupConfiguration())).addButton((b) => b.setButtonText("Reset pairing state").setDisabled(this.plugin.pairing).onClick(async () => {
      await this.plugin.resetPairingState();
      this.display();
    })).addButton((b) => b.setButtonText("Copy diagnostics").onClick(() => void this.plugin.copyDiagnostics()));
    applyActionRowLayout(actions.controlEl);
  }
};
var ConflictModal = class extends import_obsidian.Modal {
  constructor(app, plugin) {
    super(app);
    this.plugin = plugin;
  }
  onOpen() {
    this.render();
  }
  render() {
    var _a, _b;
    this.titleEl.setText("Sync reviews and preserved copies");
    this.contentEl.empty();
    const backups = this.plugin.overwriteBackupsForUi();
    if (backups.length) {
      this.contentEl.createEl("h2", { text: "Preserved local copies" });
      this.contentEl.createEl("p", { text: "These local files were verified and preserved before server-authoritative updates." });
      for (const backup of backups) {
        const section = this.contentEl.createDiv({ cls: "server-authority-overwrite-backup" });
        section.createEl("h3", { text: backup.path });
        section.createEl("p", { text: `Preserved hash: ${backup.localHash}
Server hash: ${backup.serverHash}
Server revision: ${backup.serverRevisionId}` });
        const actions = new import_obsidian.Setting(section).addButton((button) => button.setButtonText("Open preserved local copy").onClick(() => void this.plugin.openOverwriteBackup(backup))).addButton((button) => button.setButtonText("Verify preserved local copy").onClick(() => void this.plugin.verifyOverwriteBackup(backup)));
        applyActionRowLayout(actions.controlEl);
      }
    }
    const rows = conflictDisplayRows(this.plugin.syncStateForUi());
    if (!rows.length) {
      if (!backups.length) this.contentEl.createEl("p", { text: "No conflicts or preserved local copies." });
      return;
    }
    this.contentEl.createEl("p", { text: "Server deletion reviews retain local bytes. Delete a local copy only after the recovery cache is verified." });
    for (const row of rows) {
      const section = this.contentEl.createDiv({ cls: "server-authority-conflict" });
      section.createEl("h3", { text: row.path });
      section.createEl("p", { text: `Reason: ${(_a = row.reason) != null ? _a : "same-path concurrent change"}
Scope: ${(_b = row.scope) != null ? _b : "same-path"}
Base: ${row.baseLabel}
Local: ${row.localLabel}
Server: ${row.serverLabel}
Server revision: ${row.serverRevisionId}${row.resolution ? `
Resolution: ${row.resolution}; recovery cache retained` : ""}` });
      const actions = new import_obsidian.Setting(section).addButton((button) => button.setButtonText("Open server cache").setDisabled(!row.serverCachePath).onClick(() => void this.plugin.openConflictCache(row)));
      if (row.reason === "server-deletion-retained-locally" && row.serverCachePath && !row.resolution) actions.addButton((button) => button.setButtonText("Verify backup and delete local copy").onClick(async () => {
        button.setDisabled(true);
        await this.plugin.deleteServerDeletion(row.conflictId);
        this.render();
      }));
      if (!row.resolution && row.reason !== "server-deletion-retained-locally") actions.addButton((button) => button.setButtonText("Mark handled").onClick(async () => {
        await this.plugin.resolveConflict(row.conflictId);
        this.render();
      }));
      applyActionRowLayout(actions.controlEl);
    }
  }
};
var LocalUploadPickerModal = class extends import_obsidian.Modal {
  constructor(app, plugin) {
    super(app);
    this.plugin = plugin;
  }
  onOpen() {
    this.titleEl.setText("Select local uploads");
    this.contentEl.empty();
    const selected = /* @__PURE__ */ new Set();
    const files = this.plugin.app.vault.getFiles().filter((file) => this.plugin.isUploadCandidate(file));
    if (!files.length) {
      this.contentEl.createEl("p", { text: "No local files are available for explicit upload selection." });
      return;
    }
    this.contentEl.createEl("p", { text: "Select exact paths. Review upload opens a separate confirmation modal; canceling it sends no write request." });
    for (const file of files) new import_obsidian.Setting(this.contentEl).setName(file.path).addButton((button) => button.setButtonText(`Select ${file.path}`).onClick(() => {
      if (selected.has(file.path)) {
        selected.delete(file.path);
        button.setButtonText(`Select ${file.path}`);
      } else {
        selected.add(file.path);
        button.setButtonText(`Selected ${file.path}`);
      }
    }));
    new import_obsidian.Setting(this.contentEl).addButton((button) => button.setButtonText("Review upload").onClick(() => this.plugin.reviewLocalUpload([...selected])));
  }
};
var UploadConfirmationModal = class extends import_obsidian.Modal {
  constructor(app, plugin, paths) {
    super(app);
    this.plugin = plugin;
    this.paths = paths;
  }
  onOpen() {
    this.titleEl.setText("Confirm direct upload");
    this.contentEl.empty();
    const summary = this.plugin.uploadConfirmationFor(this.paths);
    this.contentEl.createEl("p", { text: `${summary.additions} added, ${summary.overwrites} overwritten.` });
    const list = this.contentEl.createEl("ul");
    for (const path of summary.paths) list.createEl("li", { text: path });
    const actions = new import_obsidian.Setting(this.contentEl).addButton((button) => button.setButtonText("Cancel").onClick(() => this.close())).addButton((button) => button.setButtonText("Confirm upload").onClick(async () => {
      button.setDisabled(true);
      try {
        await this.plugin.uploadSelected(this.paths);
        this.close();
      } catch (e) {
      } finally {
        button.setDisabled(false);
      }
    }));
    applyActionRowLayout(actions.controlEl);
  }
};
var PendingSubmissionsModal = class extends import_obsidian.Modal {
  constructor(app, plugin) {
    super(app);
    this.plugin = plugin;
  }
  onOpen() {
    this.render();
  }
  render() {
    var _a;
    this.titleEl.setText("Pending submissions");
    this.contentEl.empty();
    const rows = pendingDisplayRows(this.plugin.pendingForUi());
    if (!rows.length) {
      this.contentEl.createEl("p", { text: "No pending submissions." });
      return;
    }
    for (const row of rows) {
      const section = this.contentEl.createDiv();
      section.createEl("h3", { text: row.paths.join(", ") });
      section.createEl("p", { text: `Revision: ${row.baseRevisionId}
Retries: ${row.retryCount}
Status: ${row.status}` });
      if (!((_a = this.plugin.pendingForUi().find((item) => item.submissionId === row.submissionId)) == null ? void 0 : _a.submitted)) new import_obsidian.Setting(section).addButton((button) => button.setButtonText("Withdraw local draft").onClick(async () => {
        await this.plugin.discardPending(row.submissionId);
        this.render();
      }));
    }
    const actions = new import_obsidian.Setting(this.contentEl).addButton((button) => button.setButtonText("Refresh").onClick(async () => {
      button.setDisabled(true);
      try {
        await this.plugin.refreshPendingSubmissions();
        this.render();
      } finally {
        button.setDisabled(false);
      }
    })).addButton((button) => button.setButtonText("Retry failed").setDisabled(this.plugin.submitting).onClick(async () => {
      button.setDisabled(true);
      try {
        await this.plugin.retryFailedSubmissions();
        this.render();
      } finally {
        button.setDisabled(false);
      }
    })).addButton((button) => button.setButtonText("Review/resolve blocked").onClick(() => this.plugin.reviewBlockedSubmissions()));
    actions.addButton((button) => {
      button.setButtonText(this.plugin.submitting ? "Submitting\u2026" : "Submit all").setDisabled(this.plugin.submitting || !rows.some((row) => {
        var _a2;
        return !((_a2 = this.plugin.pendingForUi().find((item) => item.submissionId === row.submissionId)) == null ? void 0 : _a2.blocked);
      })).onClick(async () => {
        button.setDisabled(true);
        try {
          await this.plugin.submitPendingChanges();
          this.render();
        } finally {
          button.setDisabled(false);
        }
      });
    });
    applyActionRowLayout(actions.controlEl);
  }
};
var ConfigurationExportModal = class extends import_obsidian.Modal {
  constructor(app, value) {
    super(app);
    this.value = value;
  }
  onOpen() {
    this.titleEl.setText("Export non-sensitive configuration");
    this.contentEl.createEl("p", { text: "Clipboard access is unavailable. Select and copy this configuration manually. It contains no token." });
    const area = this.contentEl.createEl("textarea");
    area.value = this.value;
    area.setAttr("readonly", "true");
    area.style.width = "100%";
    area.style.minHeight = "240px";
    area.focus();
    area.select();
    const actions = new import_obsidian.Setting(this.contentEl).addButton((button) => button.setButtonText("Close").onClick(() => this.close()));
    applyActionRowLayout(actions.controlEl);
  }
};
var SetupImportModal = class extends import_obsidian.Modal {
  constructor(app, apply) {
    super(app);
    this.apply = apply;
  }
  onOpen() {
    this.titleEl.setText("Import setup configuration");
    const input = this.contentEl.createEl("textarea", { attr: { "aria-label": "Setup configuration", placeholder: "Paste setup JSON or setup URI" } });
    input.style.width = "100%";
    new import_obsidian.Setting(this.contentEl).addButton((button) => button.setButtonText("Import").onClick(async () => {
      button.setDisabled(true);
      try {
        await this.apply(input.value);
        input.value = "";
        this.close();
      } finally {
        button.setDisabled(false);
      }
    }));
  }
};
