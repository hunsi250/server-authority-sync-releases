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
  return pending.filter((item) => !item.submitted).map((item) => {
    var _a;
    return {
      submissionId: item.submissionId,
      paths: item.changes.map((change) => change.path),
      baseRevisionId: item.baseRevisionId,
      retryCount: item.retryCount,
      status: item.blocked ? `blocked: ${(_a = item.lastError) != null ? _a : "review required; refresh or rebuild this submission"}` : item.lastError ? `error: ${item.lastError}` : item.retryCount ? "retry pending" : "pending"
    };
  });
}
function createPendingSubmission(baseRevisionId, changes) {
  if (!baseRevisionId) throw new Error("base revision is required");
  return { submissionId: crypto.randomUUID(), baseRevisionId, changes, createdAt: (/* @__PURE__ */ new Date()).toISOString(), retryCount: 0 };
}
function emptySyncState() {
  return { version: SYNC_STATE_VERSION, serverRevision: null, files: {}, pendingSubmissions: [], conflicts: [] };
}
function normalizeSyncState(value) {
  var _a;
  if (!value || typeof value !== "object") return emptySyncState();
  const input = value;
  const files = {};
  for (const [path, entry] of Object.entries((_a = input.files) != null ? _a : {})) {
    if (entry && (typeof entry.baseHash === "string" || entry.baseHash === null)) files[path] = { baseHash: entry.baseHash };
  }
  return { version: SYNC_STATE_VERSION, serverRevision: typeof input.serverRevision === "string" ? input.serverRevision : null, files, pendingSubmissions: Array.isArray(input.pendingSubmissions) ? input.pendingSubmissions : [], conflicts: Array.isArray(input.conflicts) ? input.conflicts : [] };
}
function planSync(state, local, server, localKinds = {}, serverKinds = {}) {
  const paths = /* @__PURE__ */ new Set([...Object.keys(state.files), ...Object.keys(local), ...Object.keys(server), ...Object.keys(localKinds), ...Object.keys(serverKinds)]);
  const localAdded = Object.keys(local).filter((path) => !state.files[path]);
  const deletedBasePaths = Object.keys(state.files).filter((path) => !Object.prototype.hasOwnProperty.call(local, path) && !Object.prototype.hasOwnProperty.call(server, path));
  const serverAdded = Object.keys(server).filter((path) => !state.files[path]);
  const renameLike = deletedBasePaths.length > 0 && deletedBasePaths.length === localAdded.length && serverAdded.length === 0;
  return [...paths].sort().map((path) => {
    var _a, _b, _c, _d, _e, _f;
    const base = (_b = (_a = state.files[path]) == null ? void 0 : _a.baseHash) != null ? _b : null;
    const localHash = Object.prototype.hasOwnProperty.call(local, path) ? local[path] : null;
    const serverHash = (_d = (_c = server[path]) == null ? void 0 : _c.sha256) != null ? _d : null;
    const localKind = (_e = localKinds[path]) != null ? _e : localHash !== null ? "file" : void 0;
    const serverKind = (_f = serverKinds[path]) != null ? _f : serverHash !== null ? "file" : void 0;
    const collision = localKind && serverKind && localKind !== serverKind;
    const ancestorCollision = [.../* @__PURE__ */ new Set([...Object.keys(localKinds), ...Object.keys(serverKinds)])].some((parent) => {
      var _a2;
      return path.startsWith(parent + "/") && ((_a2 = localKinds[parent]) != null ? _a2 : serverKinds[parent]) === "file";
    });
    if (collision || ancestorCollision) return { kind: "conflict", path, baseHash: base, localHash, serverHash, reason: "file-directory-collision" };
    if (serverHash === null && localHash !== null && base === localHash && state.files[path]) return { kind: "conflict", path, baseHash: base, localHash, serverHash, reason: renameLike ? "rename-like-delete-review" : "server-deletion-retained-locally" };
    if (serverHash === null && localHash === null && state.files[path] && renameLike) return { kind: "conflict", path, baseHash: base, localHash, serverHash, reason: "rename-like-delete-review" };
    if (!state.files[path] && serverHash !== null && localHash === null) return { kind: "pull", path, serverHash };
    if (localHash === null && serverHash === null) return { kind: "clean", path, hash: null };
    if (localHash === serverHash) return { kind: "clean", path, hash: localHash };
    if (serverHash !== null && localHash !== serverHash && (localHash === null || base === null || serverHash !== base)) return { kind: "pull", path, serverHash, reason: "server-authoritative-overwrite" };
    if (!state.files[path] && serverHash === null && localHash !== null) {
      if (renameLike) return { kind: "conflict", path, baseHash: base, localHash, serverHash, reason: "rename-like-add-review" };
      return { kind: "submit", path, localHash, operation: "write", reason: "local-addition-pending" };
    }
    if (localHash === base) return { kind: "pull", path, serverHash };
    if (serverHash === base) return { kind: "submit", path, localHash, operation: localHash === null ? "delete" : "write", reason: localHash === null ? "local-deletion-review" : void 0 };
    if (!state.files[path] && serverHash !== null && localHash !== null) return { kind: "conflict", path, baseHash: base, localHash, serverHash, reason: "simultaneous-add-review" };
    return { kind: "conflict", path, baseHash: base, localHash, serverHash, reason: "simultaneous-edit-review" };
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
function validSession(value) {
  const session = value;
  return !!session && typeof session.ticket === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(session.ticket) && Date.parse(session.expires_at) > Date.now();
}
async function pairDevice(transport, identity, save, pending, wait = () => new Promise((resolve) => setTimeout(resolve, 2e3)), active = () => true) {
  validateServerFingerprint(identity.server_fingerprint);
  const health = await transport.health();
  const info = await transport.serverInfo();
  if (!health.ok || health.protocol_version !== "1" || identity.protocol_version !== "1" || Object.entries(identity).some(([k, v]) => info[k] !== v)) throw new Error("Server identity does not match settings.");
  if (!active()) throw new Error("Pairing cancelled.");
  const enrollment = await transport.createEnrollment(identity);
  const expires = Math.min(Date.parse(enrollment.expires_at), Date.now() + 3e5);
  if (!enrollment.request_id || !enrollment.poll_secret || !Number.isFinite(expires)) throw new Error("Invalid enrollment response.");
  pending(enrollment.request_id);
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
var PAIRING_KINDS = /* @__PURE__ */ new Set(["not-paired", "testing", "waiting", "approved", "ready", "expired", "settings-changed", "server-rejected", "connection-failed", "save-failed"]);
function normalizePairingStatus(value) {
  if (!value || typeof value !== "object") return { kind: "not-paired" };
  const input = value;
  const kind = typeof input.kind === "string" && PAIRING_KINDS.has(input.kind) ? input.kind : "not-paired";
  return { kind, ...typeof input.reason === "string" && input.reason ? { reason: input.reason.slice(0, 120) } : {} };
}
function pairingStatusLabel(status) {
  const labels = { "not-paired": "Not paired", testing: "Checking server identity", waiting: "Waiting for administrator approval", approved: "Pairing approved; saving credentials", ready: "Paired and ready", expired: "Pairing expired", "settings-changed": "Pairing stopped: settings changed", "server-rejected": "Pairing failed: server rejected the request", "connection-failed": "Pairing failed: connection failure", "save-failed": "Pairing failed: credentials could not be saved" };
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
  var _a, _b, _c, _d;
  const decisions = (_a = input.decisions) != null ? _a : [];
  const reviewTexts = (_b = input.reviews) != null ? _b : [];
  const errors = (_c = input.errors) != null ? _c : [];
  const pulls = decisions.filter((d) => d.kind === "pull");
  const clean = decisions.filter((d) => d.kind === "clean");
  const pending = decisions.filter((d) => d.kind === "submit");
  const conflicts = decisions.filter((d) => d.kind === "conflict");
  const reviewPaths = [.../* @__PURE__ */ new Set([...reviewTexts.map((text) => text.split(":", 1)[0]), ...conflicts.map((d) => d.path)])];
  const retryableFailures = errors.filter((error) => {
    var _a2;
    return typeof error === "object" && error !== null && (error.retryable || [408, 429, 500, 502, 503, 504].includes((_a2 = error.status) != null ? _a2 : 0));
  }).length;
  const nonRetryableFailures = errors.length - retryableFailures;
  const pendingAdditions = pending.filter((d) => d.reason === "local-addition-pending" || d.reason === "local-addition-review").length;
  const kind = errors.length && !pulls.length && !pending.length && !reviewPaths.length ? "failed" : reviewPaths.length || errors.length ? "review" : pulls.length || pending.length ? "complete" : "no-op";
  return { kind, manifestFiles: (_d = input.manifestFiles) != null ? _d : decisions.length, pulled: pulls.length, skipped: clean.length, pendingAdditions, reviews: reviewPaths.length, retryableFailures, nonRetryableFailures, paths: pulls.map((d) => d.path), reviewPaths, errors };
}
function syncNotice(decisions, reviews = [], errors = [], manifestFiles = decisions.length) {
  const outcome = classifySyncOutcome({ decisions, reviews, errors, manifestFiles });
  if (outcome.kind === "no-op") return "All files are up to date. No synchronization needed.";
  const summary = `Sync complete: ${outcome.manifestFiles} manifest file(s); ${outcome.pulled} pulled/updated, ${outcome.skipped} already up to date, ${outcome.pendingAdditions} pending addition(s) awaiting review, ${outcome.reviews} needs review.`;
  const failures = errors.length ? ` Retryable failures: ${outcome.retryableFailures}; non-retryable failures: ${outcome.nonRetryableFailures}.` : "";
  const detail = outcome.reviewPaths.length ? ` Review paths: ${outcome.reviewPaths.slice(0, 3).join("; ")}.` : "";
  if (outcome.kind === "failed") return `Sync failed: ${outcome.nonRetryableFailures + outcome.retryableFailures} transport or file error(s). State was retained.`;
  return summary + failures + detail;
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
var DEFAULT_SETTINGS = { serverUrl: "", apiPrefix: DEFAULT_API_PREFIX, vaultId: "default", serverFingerprint: "", autoCheckIntervalMinutes: 30, syncPolicy: "pull-when-clean", aiProvider: { provider: "", model: "", endpoint: "" } };
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
  if (v.sync_policy && v.sync_policy !== "manual" && v.sync_policy !== "pull-when-clean") throw new Error("invalid sync policy");
  if (v.auto_check_interval_minutes !== void 0 && (!Number.isInteger(v.auto_check_interval_minutes) || v.auto_check_interval_minutes < 0 || v.auto_check_interval_minutes > 1440)) throw new Error("invalid check interval");
  return v;
}
function segmentPath(path) {
  return validateRelativePath(path).split("/").map(encodeURIComponent).join("/");
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
  }
  if (status === 401 || status === 403) return "\u4F1A\u8BDD\u5DF2\u8FC7\u671F\u6216\u672A\u6388\u6743\uFF0C\u8BF7\u91CD\u65B0\u914D\u5BF9\u3002";
  if (status === 404) return "\u670D\u52A1\u5668\u8D44\u6E90\u4E0D\u5B58\u5728\uFF0C\u8BF7\u5237\u65B0\u3002";
  if (status === 408 || status === 429 || status >= 500) return "\u670D\u52A1\u5668\u6682\u65F6\u4E0D\u53EF\u7528\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BD5\u3002";
  if (status >= 400 && status < 500) return "\u8BF7\u6C42\u672A\u88AB\u63A5\u53D7\uFF0C\u8BF7\u68C0\u67E5\u5E76\u91CD\u5EFA\u63D0\u4EA4\u3002";
  return "\u670D\u52A1\u5668\u8FDE\u63A5\u5931\u8D25\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BD5\u3002";
}
function safeError(error) {
  return error instanceof Error ? error.message.slice(0, 160) : "server request failed";
}
function waitMs(ms) {
  return new Promise((resolve) => globalThis.setTimeout(resolve, ms));
}
var RequestUrlTransport = class {
  constructor(settings, session, enrollment) {
    this.settings = settings;
    this.session = session;
    this.enrollment = enrollment;
  }
  async request(method, path, body, authenticated = false) {
    var _a;
    if (authenticated) {
      if (this.enrollment) {
        if (!this.enrollment.request_id || !this.enrollment.poll_secret || !(Date.parse(this.enrollment.expires_at) > Date.now())) throw new Error("Enrollment session expired. Test and pair again.");
        const vault = `/vaults/${encodeURIComponent(this.settings.vaultId)}`;
        const operation = path === `${vault}/manifest` ? { type: "manifest" } : path.startsWith(`${vault}/files/`) ? { type: "read-file", path: decodeURIComponent(path.slice(`${vault}/files/`.length)) } : path === "/submissions/list" ? { type: "list-submissions" } : { type: "submit", submission: body };
        path = `/enrollments/${encodeURIComponent(this.enrollment.request_id)}/poll`;
        body = { protocol_version: PROTOCOL_VERSION, vault_id: this.settings.vaultId, server_fingerprint: this.settings.serverFingerprint, poll_secret: this.enrollment.poll_secret, operation };
      } else {
        if (!validSession(this.session)) throw new Error("Session expired or unavailable. Test and pair again.");
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
      response = await (0, import_obsidian.requestUrl)(params);
    } catch (e) {
      throw new Error("Server connection failed");
    }
    if (authenticated && response.status === 401) {
      this.session = void 0;
      if (this.enrollment) this.enrollment = { ...this.enrollment, expires_at: "" };
      throw new Error("Session expired or revoked. Test and pair again.");
    }
    if (response.status < 200 || response.status >= 300) {
      const error = new Error(userFacingServerError(response.status, response.json));
      error.status = response.status;
      const payload = response.json;
      if (((_a = payload == null ? void 0 : payload.error) == null ? void 0 : _a.code) && typeof payload.error.code === "string") error.code = payload.error.code;
      throw error;
    }
    try {
      return response.json;
    } catch (e) {
      throw new Error("Invalid server response");
    }
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
    return this.request("POST", `/vaults/${encodeURIComponent(this.settings.vaultId)}/files/${segmentPath(path)}`, void 0, true);
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
    __publicField(this, "pairing", false);
    __publicField(this, "syncing", false);
    __publicField(this, "unloaded", false);
    __publicField(this, "submitting", false);
    __publicField(this, "pairingStatus", { kind: "not-paired" });
    __publicField(this, "settings", DEFAULT_SETTINGS);
    __publicField(this, "deviceToken", "");
    __publicField(this, "session");
    __publicField(this, "enrollment");
    __publicField(this, "syncState", emptySyncState());
    __publicField(this, "statusBar");
    __publicField(this, "internalWrites", /* @__PURE__ */ new Set());
  }
  async onload() {
    const data = await this.loadData();
    this.settings = mergeSettings(data == null ? void 0 : data.settings);
    this.deviceToken = typeof (data == null ? void 0 : data.device_token) === "string" ? data.device_token : "";
    this.session = validSession(data == null ? void 0 : data.session) ? data.session : void 0;
    this.enrollment = data == null ? void 0 : data.enrollment;
    this.pairingStatus = normalizePairingStatus(data == null ? void 0 : data.pairingStatus);
    if (this.session && this.pairingStatus.kind === "not-paired") this.pairingStatus = { kind: "ready" };
    this.syncState = normalizeSyncState(data == null ? void 0 : data.sync);
    this.statusBar = this.addStatusBarItem();
    this.updateStatus();
    this.addSettingTab(new AuthoritySettingTab(this.app, this));
    this.addCommand({ id: "sync-with-server", name: "Sync with server", callback: () => void this.syncWithServer() });
    this.addCommand({ id: "submit-pending-changes", name: "Submit pending changes", callback: () => void this.submitPendingChanges() });
    this.addCommand({ id: "open-conflicts", name: "Open conflicts", callback: () => void this.openConflicts() });
    this.addCommand({ id: "open-pending-submissions", name: "Open pending submissions", callback: () => void this.openPendingSubmissions() });
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
      if (this.settings.autoCheckIntervalMinutes > 0) void this.checkServerVersion(true);
    }, Math.max(1, this.settings.autoCheckIntervalMinutes) * 6e4));
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
    const snapshot = { ...this.settings };
    const active = () => !this.unloaded && ["serverUrl", "apiPrefix", "vaultId", "serverFingerprint"].every((key) => this.settings[key] === snapshot[key]);
    const setPairing = async (status) => {
      this.pairingStatus = status;
      await this.saveSettings();
      this.updateStatus();
    };
    try {
      await setPairing(transitionPairingStatus(this.pairingStatus, "testing"));
      await pairDevice(new RequestUrlTransport(snapshot), { protocol_version: "1", vault_id: snapshot.vaultId, server_fingerprint: snapshot.serverFingerprint }, async (credentials, enrollment) => {
        await setPairing(transitionPairingStatus(this.pairingStatus, "approved"));
        const previous = this.deviceToken;
        const previousSession = this.session;
        const previousEnrollment = this.enrollment;
        this.deviceToken = credentials.device_token;
        this.session = { ticket: credentials.ticket, expires_at: credentials.expires_at };
        this.enrollment = enrollment;
        try {
          await this.saveSettings();
        } catch (e) {
          this.deviceToken = previous;
          this.session = previousSession;
          this.enrollment = previousEnrollment;
          this.pairingStatus = transitionPairingStatus(this.pairingStatus, "save-failed");
          await this.saveSettings().catch(() => void 0);
          throw new Error("Unable to save pairing.");
        }
      }, () => {
        this.pairingStatus = transitionPairingStatus(this.pairingStatus, "waiting");
        void this.saveSettings();
        this.updateStatus();
        new import_obsidian.Notice(pairingStatusLabel(this.pairingStatus), 15e3);
      }, void 0, active);
      await setPairing(transitionPairingStatus(this.pairingStatus, "saved"));
    } catch (error) {
      const message = safeError(error).toLowerCase();
      const event = !active() ? "settings-changed" : message.includes("connection") ? "connection-failed" : message.includes("reject") || message.includes("identity") ? "server-rejected" : message.includes("expired") || message.includes("cancel") ? "expired" : message.includes("save") ? "save-failed" : "server-rejected";
      this.pairingStatus = transitionPairingStatus(this.pairingStatus, event);
      await this.saveSettings().catch(() => void 0);
    } finally {
      this.pairing = false;
      this.updateStatus();
      if (!this.unloaded) new import_obsidian.Notice(pairingStatusLabel(this.pairingStatus), 1e4);
    }
  }
  updateStatus(offline = false) {
    const suffix = offline ? "offline" : this.syncState.conflicts.length ? "conflicts" : this.syncState.pendingSubmissions.length ? "pending" : "clean";
    if (this.statusBar) this.statusBar.setText(`Authority: ${suffix} \xB7 ${pairingStatusLabel(this.pairingStatus)}`);
  }
  markVaultChanged(file) {
    if (this.internalWrites.delete(file.path)) return;
    if (!file.path.startsWith(CACHE_ROOT + "/")) this.updateStatus();
  }
  async saveSettings() {
    this.settings = mergeSettings(this.settings);
    await this.saveData({ settings: this.settings, device_token: this.deviceToken, session: this.session, enrollment: this.enrollment, pairingStatus: this.pairingStatus, sync: this.syncState });
  }
  async saveSync() {
    await this.saveData({ settings: this.settings, device_token: this.deviceToken, session: this.session, enrollment: this.enrollment, pairingStatus: this.pairingStatus, sync: this.syncState });
    this.updateStatus();
  }
  transport() {
    if (!this.settings.serverUrl) throw new Error("Set a server URL first");
    return new RequestUrlTransport(this.settings, this.session, this.enrollment);
  }
  included(file) {
    return !file.path.startsWith(`${this.app.vault.configDir || ".obsidian"}/plugins/server-authority-sync/`) && !file.path.startsWith(".obsidian/workspace") && !file.path.startsWith(".obsidian/cache/") && !file.path.startsWith(CACHE_ROOT + "/") && !file.path.endsWith("/.authority.sqlite3") && file.path !== ".authority.sqlite3";
  }
  async localHashes() {
    const result = {};
    for (const file of this.app.vault.getFiles().filter((f) => this.included(f))) result[file.path] = await this.hash(await this.app.vault.readBinary(file));
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
  async writeFile(path, bytes, planner = "pull") {
    const folders = await this.ensureFolder(path);
    if (!folders.ok) return { status: "conflict", reason: folders.reason };
    const existing = this.app.vault.getAbstractFileByPath(path);
    const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    const incomingHash = await this.hash(buffer);
    const existingKind = existing instanceof import_obsidian.TFile ? "file" : existing ? "folder" : "none";
    const localHash = existing instanceof import_obsidian.TFile ? await this.hash(await this.app.vault.readBinary(existing)) : null;
    const decision = planLocalWrite({ planner, existing: existingKind, localHash, incomingHash });
    if (decision.action === "conflict") return { status: "conflict", reason: decision.reason };
    if (decision.action === "skip") return { status: "skipped" };
    this.internalWrites.add(path);
    try {
      if (decision.action === "modify" && existing instanceof import_obsidian.TFile) await this.app.vault.modifyBinary(existing, buffer);
      else {
        try {
          await this.app.vault.createBinary(path, buffer);
        } catch (error) {
          const message = safeError(error).toLowerCase();
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
              if (!safeError(retryError).toLowerCase().includes("already exists")) throw retryError;
            }
          }
          const raced = this.app.vault.getAbstractFileByPath(path);
          if (raced instanceof import_obsidian.TFile) {
            const racedHash = await this.hash(await this.app.vault.readBinary(raced));
            if (racedHash === incomingHash) return { status: "skipped" };
          }
          if (message.includes("already exists")) {
            await this.app.vault.adapter.writeBinary(path, buffer);
            return { status: "written" };
          }
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
  async syncWithServer() {
    var _a, _b;
    if (this.syncing) {
      new import_obsidian.Notice("Sync already in progress.");
      return;
    }
    this.syncing = true;
    try {
      const transport = this.transport();
      const manifest = await transport.manifest();
      if (manifest.protocol_version !== PROTOCOL_VERSION) throw new Error("unsupported protocol version");
      const local = await this.localHashes();
      const server = {};
      for (const file of manifest.files) server[validateRelativePath(file.path)] = file;
      const decisions = planSync(this.syncState, local, server);
      const reviews = [];
      for (const decision of decisions) {
        try {
          if (decision.kind === "pull") {
            const file = await transport.readFile(decision.path);
            if (validateRelativePath(file.path) !== decision.path) throw new Error("Corrupted file transfer");
            const bytes = base64ToBytes(file.content_base64);
            if (await this.hash(bytes.buffer) !== decision.serverHash) throw new Error("Corrupted file transfer");
            if (decision.reason === "server-authoritative-overwrite") await this.cacheLocalBeforeOverwrite(decision.path, manifest.revision_id);
            const result = await this.writeFile(decision.path, bytes);
            if (result.status === "conflict") reviews.push(`${decision.path}: ${(_a = result.reason) != null ? _a : "path collision; manual review required"}`);
            else this.syncState.files[decision.path] = { baseHash: decision.serverHash };
          } else if (decision.kind === "submit") {
            const pending = await this.pendingFor(decision.path, decision.operation, manifest.revision_id);
            if (pending) this.syncState.pendingSubmissions.push(pending);
          } else if (decision.kind === "clean") this.syncState.files[decision.path] = { baseHash: decision.hash };
          else if (decision.kind === "conflict") {
            reviews.push(`${decision.path}: ${(_b = decision.reason) != null ? _b : "manual review required"}`);
            await this.cacheConflict(transport, manifest.revision_id, decision);
          }
        } catch (error) {
          throw new Error(`${decision.path}: ${safeError(error)}`);
        }
        await this.saveSync();
      }
      this.syncState.serverRevision = manifest.revision_id;
      await this.saveSync();
      const active = this.app.workspace.getActiveFile();
      const activeConflict = active && this.syncState.conflicts.some((c) => c.path === active.path);
      if (activeConflict) new import_obsidian.Notice("\u5F53\u524D\u7B14\u8BB0\u5B58\u5728\u672A\u89E3\u51B3\u51B2\u7A81\uFF1B\u672C\u5730\u5185\u5BB9\u672A\u88AB\u8986\u76D6\u3002");
      new import_obsidian.Notice(syncNotice(decisions, reviews, [], manifest.files.length));
    } catch (error) {
      try {
        await this.saveSync();
      } catch (e) {
      }
      this.updateStatus(true);
      new import_obsidian.Notice(`Sync failed: ${safeError(error)}. State was retained.`);
    } finally {
      this.syncing = false;
      this.updateStatus();
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
    }
    return createPendingSubmission(baseRevisionId, [change]);
  }
  async cacheLocalBeforeOverwrite(path, revision) {
    const existing = this.app.vault.getAbstractFileByPath(path);
    if (!(existing instanceof import_obsidian.TFile)) return;
    try {
      const bytes = new Uint8Array(await this.app.vault.readBinary(existing));
      const localHash = await this.hash(bytes.buffer);
      const pluginRoot = `${this.app.vault.configDir || ".obsidian"}/plugins/server-authority-sync`;
      const cachePath = `${pluginRoot}/overwrites/${encodeURIComponent(path)}-${encodeURIComponent(revision)}-${localHash}.bin`;
      const folderResult = await this.ensureFolder(cachePath);
      if (!folderResult.ok) {
        console.warn(`[Server Authority Sync] overwrite backup skipped: ${folderResult.reason}`);
        return;
      }
      await this.app.vault.adapter.writeBinary(cachePath, bytes.buffer);
    } catch (error) {
      console.warn(`[Server Authority Sync] overwrite backup skipped: ${safeError(error)}`);
    }
  }
  async cacheConflict(transport, revision, decision) {
    var _a;
    if (this.syncState.conflicts.some((c) => c.path === decision.path && c.serverRevisionId === revision)) return;
    let cachePath = "";
    if (decision.serverHash) {
      const file = await transport.readFile(decision.path);
      cachePath = `${CACHE_ROOT}/conflicts/${encodeURIComponent(decision.path)}-${encodeURIComponent(revision)}.bin`;
      await this.writeFile(cachePath, base64ToBytes(file.content_base64));
    }
    const record = { conflictId: crypto.randomUUID(), path: decision.path, paths: [decision.path], baseHash: decision.baseHash, localHash: decision.localHash, serverHash: decision.serverHash, serverRevisionId: revision, serverCachePath: cachePath, createdAt: (/* @__PURE__ */ new Date()).toISOString(), reason: (_a = decision.reason) != null ? _a : "same-path concurrent change", scope: "same-path" };
    this.syncState.conflicts.push(record);
  }
  async submitPendingChanges() {
    var _a;
    if (this.submitting) return;
    this.submitting = true;
    const counts = { sent: 0, conflicts: 0, retryable: 0, nonRetryable: 0, skipped: 0 };
    try {
      const transport = this.transport();
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
      this.syncState.pendingSubmissions = this.syncState.pendingSubmissions.filter((item) => !item.submitted);
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
    if (!this.syncState.conflicts.length) {
      new import_obsidian.Notice("No conflicts.");
      return;
    }
    new ConflictModal(this.app, this).open();
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
  pendingForUi() {
    return this.syncState.pendingSubmissions;
  }
  async refreshPendingSubmissions() {
    var _a;
    try {
      const result = await this.transport().submissions();
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
  async openConflictCache(record) {
    if (record.serverCachePath) await this.app.workspace.openLinkText(record.serverCachePath, "", false);
  }
  async resolveConflict(conflictId) {
    this.syncState.conflicts = this.syncState.conflicts.filter((conflict) => conflict.conflictId !== conflictId);
    await this.saveSync();
  }
  async testConnection() {
    try {
      const result = await this.transport().health();
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
      const info = await this.transport().serverInfo();
      if (info.protocol_version !== PROTOCOL_VERSION || info.vault_id && info.vault_id !== this.settings.vaultId || !serverFingerprintMatches(this.settings.serverFingerprint, info.server_fingerprint)) throw new Error("server identity does not match settings");
      this.updateStatus();
      if (!silent) new import_obsidian.Notice(`Server protocol version: ${info.protocol_version}.`);
    } catch (error) {
      this.updateStatus(true);
      if (!silent) new import_obsidian.Notice(`Version check failed: ${safeError(error)}`);
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
    var _a, _b, _c, _d;
    const next = mergeSettings({ serverUrl: config.server_url, apiPrefix: config.api_prefix ? validateApiPrefix(config.api_prefix) : DEFAULT_API_PREFIX, vaultId: config.vault_id, serverFingerprint: (_a = config.server_fingerprint) != null ? _a : "", syncPolicy: (_b = config.sync_policy) != null ? _b : "manual", autoCheckIntervalMinutes: (_c = config.auto_check_interval_minutes) != null ? _c : 30, aiProvider: { ...DEFAULT_SETTINGS.aiProvider, ...(_d = config.ai_provider) != null ? _d : {} } });
    const credentials = config.setup_token ? await new RequestUrlTransport(next).redeemSetup(config.setup_token) : void 0;
    if (credentials && (!validSession(credentials) || !credentials.device_token)) throw new Error("Invalid pairing session");
    this.settings = next;
    this.enrollment = void 0;
    if (credentials) {
      this.deviceToken = credentials.device_token;
      this.session = { ticket: credentials.ticket, expires_at: credentials.expires_at };
    }
    await this.saveSettings();
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
    var _a, _b, _c, _d, _e;
    const input = window.prompt("Paste the setup/config link or JSON:");
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
  display() {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.createEl("h2", { text: "Server authority sync" });
    const text = (name, value, save, desc) => new import_obsidian.Setting(containerEl).setName(name).setDesc(desc != null ? desc : "").addText((t) => t.setValue(value).onChange(async (value2) => {
      await save(value2.trim());
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
    const pairing = new import_obsidian.Setting(containerEl).setName("Device pairing").setDesc(`${pairingStatusLabel(this.plugin.pairingStatus)}. Credentials are stored only in plugin data.`).addButton((b) => b.setButtonText(this.plugin.pairing ? "Pairing\u2026" : "Test and pair").setDisabled(this.plugin.pairing).onClick(async () => {
      b.setDisabled(true);
      await this.plugin.testAndPair();
      this.display();
    }));
    applyActionRowLayout(pairing.controlEl);
    new import_obsidian.Setting(containerEl).setName("Automatic check interval (minutes)").addText((t) => t.setValue(String(this.plugin.settings.autoCheckIntervalMinutes)).onChange(async (value) => {
      const number = Number(value);
      if (Number.isInteger(number) && number >= 0 && number <= 1440) {
        this.plugin.settings.autoCheckIntervalMinutes = number;
        await this.plugin.saveSettings();
      }
    }));
    new import_obsidian.Setting(containerEl).setName("Sync policy").addDropdown((d) => d.addOption("manual", "Manual").addOption("pull-when-clean", "Pull when clean").setValue(this.plugin.settings.syncPolicy).onChange(async (value) => {
      this.plugin.settings.syncPolicy = value;
      await this.plugin.saveSettings();
    }));
    containerEl.createEl("h3", { text: "AI provider (optional, no credentials)" });
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
    const actions = new import_obsidian.Setting(containerEl).setName("Actions").addButton((b) => b.setButtonText(this.plugin.syncing ? "Syncing\u2026" : "Sync with server").setDisabled(this.plugin.syncing).onClick(async () => {
      b.setDisabled(true);
      await this.plugin.syncWithServer();
      this.display();
    })).addButton((b) => b.setButtonText("Copy configuration link").onClick(() => void this.plugin.exportConfiguration())).addButton((b) => b.setButtonText("Paste setup/config link").onClick(() => void this.plugin.importSetupConfiguration())).addButton((b) => b.setButtonText("Open conflicts").onClick(() => void this.plugin.openConflicts())).addButton((b) => b.setButtonText("Pending submissions").onClick(() => void this.plugin.openPendingSubmissions()));
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
    this.titleEl.setText("Conflicts");
    this.contentEl.empty();
    const rows = conflictDisplayRows(this.plugin.syncStateForUi());
    if (!rows.length) {
      this.contentEl.createEl("p", { text: "No conflicts." });
      return;
    }
    this.contentEl.createEl("p", { text: "Only the same file changed on both sides is a conflict; changes to other files do not conflict." });
    for (const row of rows) {
      const section = this.contentEl.createDiv({ cls: "server-authority-conflict" });
      section.createEl("h3", { text: row.path });
      section.createEl("p", { text: `Reason: ${(_a = row.reason) != null ? _a : "same-path concurrent change"}
Scope: ${(_b = row.scope) != null ? _b : "same-path"}
Base: ${row.baseLabel}
Local: ${row.localLabel}
Server: ${row.serverLabel}
Server revision: ${row.serverRevisionId}` });
      const actions = new import_obsidian.Setting(section).addButton((button) => button.setButtonText("Open server cache").setDisabled(!row.serverCachePath).onClick(() => void this.plugin.openConflictCache(row))).addButton((button) => button.setButtonText("Mark handled").onClick(async () => {
        await this.plugin.resolveConflict(row.conflictId);
        this.render();
      }));
      applyActionRowLayout(actions.controlEl);
    }
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
        var _a;
        return !((_a = this.plugin.pendingForUi().find((item) => item.submissionId === row.submissionId)) == null ? void 0 : _a.blocked);
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
