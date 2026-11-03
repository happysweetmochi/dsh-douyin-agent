import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { hasStableConversationIdentity } from './contact-authorization.mjs';
import { renderedUserShareContact } from './share-identity.mjs';
import { resolveRuntimePaths } from './runtime-paths.mjs';

export const PROACTIVE_DEFAULTS = Object.freeze({
  enabled: false,
  allowlistEnabled: true,
  shareDailyLimit: 3,
  messageDailyLimit: 5,
  minIntervalMs: 60_000,
});

const shanghaiDay = value => new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(value));
const hash = value => createHash('sha256').update(String(value)).digest('hex');
const kinds = new Set(['share', 'message']);
const entryKinds = new Set(['conversation', 'douyin-id', 'sec-uid', 'profile']);

export function redactSendDetail(value) {
  return String(value || '主动发送没有完成。').split('\n')[0]
    .replace(/\bBearer\s+\S+/gi, '[凭据已隐藏]')
    .replace(/\b(?:cookie|set-cookie|authorization|token|api[-_]?key)\b\s*[:=]\s*\S+/gi, '[凭据已隐藏]')
    .replace(/\bsk-[A-Za-z0-9_-]+/g, '[凭据已隐藏]')
    .replace(/https?:\/\/[^\s，。；]+/gi, '[地址]')
    .slice(0, 300);
}

export function normalizeAllowlistToken(raw) {
  const value = typeof raw === 'string' ? raw.trim() : '';
  if (!value || value.length > 500 || /[\u0000-\u001f]/.test(value)) throw new TypeError('允许发送的对象不能为空、过长或含控制字符。');
  if (/^conv:[a-f0-9]{64}$/.test(value)) return { kind: 'conversation', value };
  if (/^https:\/\//i.test(value)) {
    let url;
    try { url = new URL(value); } catch { throw new TypeError('主页链接格式不正确。'); }
    const id = /^\/user\/([^/?#]+)\/?$/.exec(url.pathname)?.[1];
    if (url.protocol !== 'https:' || url.hostname !== 'www.douyin.com' || url.port || url.username || url.password || url.search || url.hash || !id) throw new TypeError('主页链接必须是不带参数的 https://www.douyin.com/user/…');
    let sec;
    try { sec = decodeURIComponent(id); } catch { throw new TypeError('主页链接里的身份无法读取。'); }
    if (!/^MS4[A-Za-z0-9_-]{8,180}$/.test(sec) && !/^[A-Za-z0-9_.]{2,24}$/.test(sec)) throw new TypeError('主页链接里的身份格式不正确。');
    return { kind: 'profile', value: `https://www.douyin.com/user/${sec}`, secUid: sec.startsWith('MS4') ? sec : null, douyinId: sec.startsWith('MS4') ? null : sec.toLowerCase() };
  }
  if (/^MS4[A-Za-z0-9_-]{8,180}$/.test(value)) return { kind: 'sec-uid', value };
  if (/^[A-Za-z0-9_.]{2,24}$/.test(value)) return { kind: 'douyin-id', value: value.toLowerCase() };
  throw new TypeError('对象须是会话 ID、抖音号、sec_uid 或抖音主页链接。');
}

export function parseShareVideo({ url, videoId } = {}) {
  let fromUrl = null;
  if (url !== undefined && url !== '') {
    if (typeof url !== 'string' || url.length > 1000) throw new TypeError('作品链接不正确。');
    const match = /^https:\/\/(?:www\.)?douyin\.com\/video\/(\d+)\/?(?:\?[^#]*)?(?:#.*)?$/.exec(url);
    if (!match) throw new TypeError('作品链接必须是抖音公开 video 链接。');
    fromUrl = match[1];
  }
  if (videoId !== undefined && videoId !== '') {
    if (typeof videoId !== 'string' || !/^\d{1,30}$/.test(videoId)) throw new TypeError('作品 ID 必须是数字。');
    if (fromUrl && fromUrl !== videoId) throw new TypeError('链接与作品 ID 不一致。');
  }
  const id = (typeof videoId === 'string' && videoId) || fromUrl || null;
  return { videoId: id, url: id ? `https://www.douyin.com/video/${id}` : undefined, payloadKey: id ? `video:${id}` : null };
}

export function parseMessageText(text) {
  if (typeof text !== 'string') throw new TypeError('私信正文必须是文字。');
  const value = text.replace(/\u0000/g, '').trim();
  if (!value || [...value].length > 1000) throw new TypeError('私信正文须为 1 到 1000 字。');
  return value;
}

export function parseMessageTarget(args = {}) {
  const present = ['recipientId', 'douyinId', 'profileUrl', 'secUid'].filter(key => args[key] !== undefined && args[key] !== '');
  if (present.length !== 1) throw new TypeError('主动私信需要且只能指定一种收件人：会话 ID、抖音号、主页链接或 sec_uid。');
  const key = present[0];
  if (key === 'recipientId') {
    const token = normalizeAllowlistToken(args.recipientId);
    if (token.kind !== 'conversation') throw new TypeError('会话 ID 格式不正确。');
    return { conversationId: token.value };
  }
  if (key === 'douyinId') {
    const token = normalizeAllowlistToken(args.douyinId);
    if (token.kind !== 'douyin-id') throw new TypeError('抖音号格式不正确。');
    return { douyinId: token.value };
  }
  if (key === 'secUid') {
    const token = normalizeAllowlistToken(args.secUid);
    if (token.kind !== 'sec-uid') throw new TypeError('sec_uid 格式不正确。');
    return { secUid: token.value };
  }
  const token = normalizeAllowlistToken(args.profileUrl);
  if (token.kind !== 'profile') throw new TypeError('主页链接格式不正确。');
  return { profileUrl: token.value, secUid: token.secUid, douyinId: token.douyinId };
}

export function parseShareRecipient(value) {
  const token = normalizeAllowlistToken(value);
  if (token.kind === 'conversation') return { conversationId: token.value };
  if (token.kind === 'douyin-id') return { douyinId: token.value };
  if (token.kind === 'sec-uid') return { secUid: token.value };
  return { profileUrl: token.value, secUid: token.secUid, douyinId: token.douyinId };
}

export function identityKeys(target = {}, contact = null) {
  const keys = new Set();
  if (target.conversationId) keys.add(`conversation:${target.conversationId}`);
  if (target.secUid) keys.add(`sec-uid:${target.secUid}`);
  if (target.profileUrl) keys.add(`profile:${target.profileUrl}`);
  if (target.douyinId) keys.add(`douyin-id:${String(target.douyinId).toLowerCase()}`);
  const profile = typeof contact?.profileUrl === 'string' ? contact.profileUrl : '';
  const profileSec = /^https:\/\/www\.douyin\.com\/user\/([^/?#]+)\/?$/.exec(profile)?.[1] || null;
  const sec = contact?.secUid || profileSec;
  if (sec && /^MS4[A-Za-z0-9_-]{8,180}$/.test(sec)) {
    keys.add(`sec-uid:${sec}`);
    try { keys.add(`conversation:${renderedUserShareContact(sec).id}`); } catch { /* 非面板身份 */ }
  }
  if (contact?.id && /^conv:[a-f0-9]{64}$/.test(contact.id)) keys.add(`conversation:${contact.id}`);
  if (contact?.panelOnly && contact.secUid) keys.add(`sec-uid:${contact.secUid}`);
  return [...keys];
}

function allowlistHits(policy, target) {
  if (policy.allowlistEnabled !== true) return true;
  const keys = new Set(identityKeys(target));
  return policy.allowlist.some(entry => {
    if (entry.kind === 'conversation') return keys.has(`conversation:${entry.value}`);
    if (entry.kind === 'sec-uid') return keys.has(`sec-uid:${entry.value}`) || (entry.value && target.profileUrl?.endsWith(`/${entry.value}`));
    if (entry.kind === 'profile') return keys.has(`profile:${entry.value}`) || (entry.secUid && keys.has(`sec-uid:${entry.secUid}`)) || (entry.douyinId && keys.has(`douyin-id:${entry.douyinId}`));
    if (entry.kind === 'douyin-id') return keys.has(`douyin-id:${entry.value}`);
    return false;
  });
}

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export function readProfileIdentityDom() {
  const visible = element => {
    const r = element.getBoundingClientRect(), s = getComputedStyle(element);
    return r.width > 0 && r.height > 0 && r.bottom > 0 && r.right > 0 && r.top < innerHeight && r.left < innerWidth && s.display !== 'none' && s.visibility !== 'hidden';
  };
  let secUid = null;
  try {
    const url = new URL(location.href);
    if (url.protocol === 'https:' && url.hostname === 'www.douyin.com' && !url.username && !url.password) {
      const id = /^\/user\/([^/?#]+)\/?$/.exec(url.pathname)?.[1];
      if (id) secUid = decodeURIComponent(id);
    }
  } catch { secUid = null; }
  const scopes = [...document.querySelectorAll('[data-e2e="user-info"],[data-e2e="user-detail"]')].filter(visible);
  const scope = scopes.length === 1 ? scopes[0] : scopes.length === 0 ? (document.querySelector('main') || document.body) : null;
  const douyinIds = [];
  if (scope) for (const match of (scope.innerText || '').matchAll(/抖音号\s*[:：]\s*([A-Za-z0-9_.]{2,24})/g)) douyinIds.push(match[1]);
  const buttons = [...document.querySelectorAll('button,[role="button"]')].filter(element => visible(element) && (element.getAttribute('aria-label') || element.innerText || '').replace(/\s+/g, '') === '私信');
  const body = (document.body?.innerText || '').replace(/\s+/g, ' ').slice(0, 4000);
  return {
    secUid, douyinIds: [...new Set(douyinIds)], messageButtonCount: scope ? buttons.length : -1, ambiguousProfile: scopes.length > 1,
    loginRequired: /扫码登录|验证码登录|登录后即可|手机扫码登录/.test(body),
    verificationRequired: /请完成下方验证|请完成验证|安全验证|拖动滑块/.test(body),
  };
}

export function readUserSearchDom(douyinId) {
  const wanted = String(douyinId || '').toLowerCase();
  const matches = [];
  for (const link of document.querySelectorAll('a[href*="/user/"]')) {
    let url;
    try { url = new URL(link.href, location.href); } catch { continue; }
    if (url.protocol !== 'https:' || url.hostname !== 'www.douyin.com' || url.username || url.password) continue;
    const raw = /^\/user\/([^/?#]+)\/?$/.exec(url.pathname)?.[1];
    if (!raw) continue;
    let secUid;
    try { secUid = decodeURIComponent(raw); } catch { continue; }
    const card = link.closest('[data-e2e="search-user-item"],[data-e2e="search-card"],li,article') || link.parentElement;
    const text = (card?.innerText || '');
    const ids = [...text.matchAll(/抖音号\s*[:：]\s*([A-Za-z0-9_.]{2,24})/g)].map(item => item[1].toLowerCase());
    if (ids.includes(wanted)) matches.push({ secUid, href: `https://www.douyin.com/user/${secUid}` });
  }
  return { matches: [...new Map(matches.map(item => [item.secUid, item])).values()] };
}

export function markUniqueMessageButton() {
  const visible = element => {
    const r = element.getBoundingClientRect(), s = getComputedStyle(element);
    return r.width > 0 && r.height > 0 && r.bottom > 0 && r.right > 0 && r.top < innerHeight && r.left < innerWidth && s.display !== 'none' && s.visibility !== 'hidden';
  };
  const buttons = [...document.querySelectorAll('button,[role="button"]')].filter(element => visible(element) && (element.getAttribute('aria-label') || element.innerText || '').replace(/\s+/g, '') === '私信');
  if (buttons.length !== 1) return buttons.length;
  buttons[0].setAttribute('data-proactive-message', 'ready');
  return 1;
}

function failure(message, code, status = 409) {
  return Object.assign(new Error(message), { code, status });
}

export class ProactiveSendPolicy {
  constructor({ stateDir = resolveRuntimePaths().stateDir, now = Date.now } = {}) {
    if (typeof stateDir !== 'string' || !path.isAbsolute(stateDir)) throw new TypeError('主动发送状态目录必须是绝对路径。');
    if (typeof now !== 'function') throw new TypeError('主动发送时钟不正确。');
    this.stateDir = stateDir;
    this.now = now;
    this.file = path.join(stateDir, 'proactive-send.json');
    this.logFile = path.join(stateDir, 'proactive-send-log.json');
    this.guardFile = path.join(stateDir, 'proactive-send.guard');
  }
  lock() {
    fs.mkdirSync(this.stateDir, { recursive: true });
    const token = randomUUID();
    for (let attempt = 0; attempt < 40; attempt += 1) {
      try {
        const descriptor = fs.openSync(this.guardFile, 'wx', 0o600);
        try { fs.writeFileSync(descriptor, JSON.stringify({ pid: process.pid, token })); } finally { fs.closeSync(descriptor); }
        return () => {
          try {
            const current = JSON.parse(fs.readFileSync(this.guardFile, 'utf8'));
            if (current?.token === token) fs.unlinkSync(this.guardFile);
          } catch { /* 锁已由持有者释放 */ }
        };
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        sleepSync(25);
      }
    }
    throw failure('另一项主动发送正在记账，未继续。', 'PROACTIVE_BUSY');
  }
  read() {
    let value;
    try {
      const stat = fs.lstatSync(this.file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1_048_576) throw failure('主动发送配置无法核对，未重置。', 'PROACTIVE_POLICY_INVALID');
      value = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      if (error.code === 'PROACTIVE_POLICY_INVALID') throw error;
      throw failure('主动发送配置无法核对，未重置。', 'PROACTIVE_POLICY_INVALID');
    }
    this.#assertStore(value);
    return value;
  }
  #assertStore(value) {
    const policy = value?.policy;
    const usage = value?.usage;
    const uncertain = value?.uncertain;
    if (!value || value.version !== 1 || !policy || policy.enabled !== true && policy.enabled !== false || policy.allowlistEnabled !== true && policy.allowlistEnabled !== false) throw failure('主动发送配置无法核对，未重置。', 'PROACTIVE_POLICY_INVALID');
    if (!Number.isSafeInteger(policy.shareDailyLimit) || policy.shareDailyLimit < 1 || policy.shareDailyLimit > 20) throw failure('主动发送配置无法核对，未重置。', 'PROACTIVE_POLICY_INVALID');
    if (!Number.isSafeInteger(policy.messageDailyLimit) || policy.messageDailyLimit < 1 || policy.messageDailyLimit > 20) throw failure('主动发送配置无法核对，未重置。', 'PROACTIVE_POLICY_INVALID');
    if (!Number.isSafeInteger(policy.minIntervalMs) || policy.minIntervalMs < 10_000 || policy.minIntervalMs > 3_600_000) throw failure('主动发送配置无法核对，未重置。', 'PROACTIVE_POLICY_INVALID');
    if (!Array.isArray(policy.allowlist) || policy.allowlist.length > 50 || policy.allowlist.some(item => !item || !entryKinds.has(item.kind) || typeof item.value !== 'string')) throw failure('主动发送配置无法核对，未重置。', 'PROACTIVE_POLICY_INVALID');
    if (new Set(policy.allowlist.map(item => `${item.kind}\0${item.value}`)).size !== policy.allowlist.length) throw failure('主动发送配置无法核对，未重置。', 'PROACTIVE_POLICY_INVALID');
    if (!usage || !/^\d{4}-\d{2}-\d{2}$/.test(usage.date || '') || !Number.isSafeInteger(usage.share) || usage.share < 0 || !Number.isSafeInteger(usage.message) || usage.message < 0) throw failure('主动发送配置无法核对，未重置。', 'PROACTIVE_POLICY_INVALID');
    if (usage.lastSentAt !== null && !Number.isFinite(Date.parse(usage.lastSentAt))) throw failure('主动发送配置无法核对，未重置。', 'PROACTIVE_POLICY_INVALID');
    if (!Array.isArray(uncertain) || uncertain.length > 200 || uncertain.some(item => !item || !kinds.has(item.kind) || !Array.isArray(item.keys) || item.keys.length < 1 || item.keys.length > 8 || item.keys.some(key => typeof key !== 'string' || key.length > 240) || typeof item.payloadKey !== 'string' || item.payloadKey.length > 80 || !Number.isFinite(Date.parse(item.at)))) throw failure('主动发送配置无法核对，未重置。', 'PROACTIVE_POLICY_INVALID');
  }
  blank(now = this.now()) {
    return {
      version: 1,
      policy: { ...PROACTIVE_DEFAULTS, allowlist: [] },
      usage: { date: shanghaiDay(now), share: 0, message: 0, lastSentAt: null },
      uncertain: [],
    };
  }
  load() {
    return this.read() ?? this.blank();
  }
  write(value) {
    this.#assertStore(value);
    const temporary = `${this.file}.${process.pid}.${randomUUID()}.tmp`;
    const descriptor = fs.openSync(temporary, 'wx', 0o600);
    try { fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`); fs.fsyncSync(descriptor); }
    finally { fs.closeSync(descriptor); }
    try { fs.renameSync(temporary, this.file); }
    finally { if (fs.existsSync(temporary)) fs.unlinkSync(temporary); }
  }
  configure(input, { explicit } = {}) {
    if (explicit !== true) throw failure('修改主动发送需要设置页的明确保存。', 'PROACTIVE_EXPLICIT', 400);
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw failure('主动发送设置必须是对象。', 'PROACTIVE_INPUT', 400);
    const allowed = ['enabled', 'allowlistEnabled', 'shareDailyLimit', 'messageDailyLimit', 'minIntervalMs', 'allowlist'];
    if (Object.keys(input).some(key => !allowed.includes(key))) throw failure('主动发送只接受总开关、名单开关、次数、间隔和对象名单。', 'PROACTIVE_INPUT', 400);
    const release = this.lock();
    try {
      const current = this.load();
      const policy = { ...current.policy, allowlist: current.policy.allowlist.map(item => ({ ...item })) };
      if (input.enabled !== undefined) {
        if (typeof input.enabled !== 'boolean') throw failure('总开关必须是布尔值。', 'PROACTIVE_INPUT', 400);
        policy.enabled = input.enabled;
      }
      if (input.allowlistEnabled !== undefined) {
        if (typeof input.allowlistEnabled !== 'boolean') throw failure('名单开关必须是布尔值。', 'PROACTIVE_INPUT', 400);
        policy.allowlistEnabled = input.allowlistEnabled;
      }
      if (input.shareDailyLimit !== undefined) {
        if (!Number.isSafeInteger(input.shareDailyLimit) || input.shareDailyLimit < 1 || input.shareDailyLimit > 20) throw failure('每日主动分享次数须为 1 到 20。', 'PROACTIVE_INPUT', 400);
        policy.shareDailyLimit = input.shareDailyLimit;
      }
      if (input.messageDailyLimit !== undefined) {
        if (!Number.isSafeInteger(input.messageDailyLimit) || input.messageDailyLimit < 1 || input.messageDailyLimit > 20) throw failure('每日主动私信次数须为 1 到 20。', 'PROACTIVE_INPUT', 400);
        policy.messageDailyLimit = input.messageDailyLimit;
      }
      if (input.minIntervalMs !== undefined) {
        if (!Number.isSafeInteger(input.minIntervalMs) || input.minIntervalMs < 10_000 || input.minIntervalMs > 3_600_000) throw failure('发送间隔须为 10 秒到 1 小时。', 'PROACTIVE_INPUT', 400);
        policy.minIntervalMs = input.minIntervalMs;
      }
      if (input.allowlist !== undefined) {
        if (!Array.isArray(input.allowlist) || input.allowlist.length > 50 || input.allowlist.some(item => typeof item !== 'string')) throw failure('允许发送的对象须是最多 50 条字符串。', 'PROACTIVE_INPUT', 400);
        const normalized = input.allowlist.map(item => {
          const token = normalizeAllowlistToken(item);
          return { kind: token.kind, value: token.value, ...(token.secUid ? { secUid: token.secUid } : {}), ...(token.douyinId ? { douyinId: token.douyinId } : {}) };
        });
        if (new Set(normalized.map(item => `${item.kind}\0${item.value}`)).size !== normalized.length) throw failure('允许发送的对象有重复。', 'PROACTIVE_INPUT', 400);
        policy.allowlist = normalized;
      }
      const next = { ...current, policy };
      this.write(next);
      return this.snapshot(next);
    } finally { release(); }
  }
  usageNow(store, now = this.now()) {
    const day = shanghaiDay(now);
    if (store.usage.date === day) return { ...store.usage };
    return { date: day, share: 0, message: 0, lastSentAt: store.usage.lastSentAt };
  }
  blocked(store, kind, keys, payloadKey) {
    if (!payloadKey) return false;
    return store.uncertain.some(item => item.kind === kind && item.payloadKey === payloadKey && item.keys.some(key => keys.includes(key)));
  }
  preview(kind, target, payloadKey) {
    const store = this.load();
    const keys = identityKeys(target);
    if (store.policy.enabled !== true) return { ok: false, code: 'PROACTIVE_DISABLED', reason: '主动发送总开关关闭，未发送。请先在设置里打开。' };
    if (!allowlistHits(store.policy, target)) return { ok: false, code: 'PROACTIVE_ALLOWLIST', reason: '对象不在允许发送的名单里，未发送。' };
    if (this.blocked(store, kind, keys, payloadKey)) return { ok: false, code: 'PROACTIVE_UNCERTAIN', reason: '同一对象的上一次发送结果未确认，未再次发送。' };
    const usage = this.usageNow(store);
    const limit = kind === 'share' ? store.policy.shareDailyLimit : store.policy.messageDailyLimit;
    if (usage[kind] >= limit) return { ok: false, code: 'PROACTIVE_DAILY_LIMIT', reason: kind === 'share' ? '今日主动分享次数已用完，未发送。' : '今日主动私信次数已用完，未发送。' };
    if (usage.lastSentAt && this.now() - Date.parse(usage.lastSentAt) < store.policy.minIntervalMs) return { ok: false, code: 'PROACTIVE_INTERVAL', reason: '距离上一次主动发送太近，未发送。' };
    return { ok: true, keys };
  }
  reserve(kind) {
    const release = this.lock();
    let held = true;
    const give = value => { if (held) { held = false; release(); } return value; };
    try {
      const store = this.load();
      const usage = this.usageNow(store);
      const limit = kind === 'share' ? store.policy.shareDailyLimit : store.policy.messageDailyLimit;
      if (store.policy.enabled !== true) return give({ ok: false, code: 'PROACTIVE_DISABLED', reason: '主动发送总开关关闭，未发送。' });
      if (usage[kind] >= limit) return give({ ok: false, code: 'PROACTIVE_DAILY_LIMIT', reason: kind === 'share' ? '今日主动分享次数已用完，未发送。' : '今日主动私信次数已用完，未发送。' });
      if (usage.lastSentAt && this.now() - Date.parse(usage.lastSentAt) < store.policy.minIntervalMs) return give({ ok: false, code: 'PROACTIVE_INTERVAL', reason: '距离上一次主动发送太近，未发送。' });
      const previous = { ...usage };
      const nextUsage = { ...usage, [kind]: usage[kind] + 1, lastSentAt: new Date(this.now()).toISOString() };
      this.write({ ...store, usage: nextUsage });
      held = false;
      return { ok: true, previous, release };
    } catch (error) { if (held) release(); throw error; }
  }
  restore(previous) {
    const release = this.lock();
    try {
      const store = this.load();
      this.write({ ...store, usage: previous });
    } finally { release(); }
  }
  rememberUncertain(kind, keys, payloadKey) {
    if (!payloadKey || !keys.length) return;
    const release = this.lock();
    try {
      const store = this.load();
      if (this.blocked(store, kind, keys, payloadKey)) return;
      const uncertain = [...store.uncertain, { kind, keys, payloadKey, at: new Date(this.now()).toISOString() }].slice(-200);
      this.write({ ...store, uncertain });
    } finally { release(); }
  }
  resolve(input, { explicit } = {}) {
    if (explicit !== true) throw failure('核对主动发送需要本人明确提交。', 'PROACTIVE_EXPLICIT', 400);
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw failure('核对内容不正确。', 'PROACTIVE_INPUT', 400);
    if (Object.keys(input).some(key => !['kind', 'targetKey', 'payloadKey', 'outcome'].includes(key))) throw failure('核对只接受类型、对象、内容标记和结果。', 'PROACTIVE_INPUT', 400);
    if (!kinds.has(input.kind) || !['confirmed', 'not-sent'].includes(input.outcome) || typeof input.targetKey !== 'string' || typeof input.payloadKey !== 'string') throw failure('核对结果必须是已确认或未发出。', 'PROACTIVE_INPUT', 400);
    const release = this.lock();
    try {
      const store = this.load();
      const matched = store.uncertain.filter(item => item.kind === input.kind && item.payloadKey === input.payloadKey && item.keys.includes(input.targetKey));
      if (matched.length !== 1) throw failure('没有找到这一条待核对记录，未改动。', 'PROACTIVE_NOT_FOUND', 404);
      const uncertain = store.uncertain.filter(item => item !== matched[0]);
      this.write({ ...store, uncertain });
      this.append({ at: new Date(this.now()).toISOString(), kind: input.kind, target: input.targetKey, result: input.outcome === 'confirmed' ? 'resolved-confirmed' : 'resolved-not-sent', code: 'PROACTIVE_RESOLVE' });
      return this.snapshot(this.load());
    } finally { release(); }
  }
  append(entry) {
    const clean = {
      at: entry.at,
      kind: entry.kind,
      target: String(entry.target || '').slice(0, 180),
      result: entry.result,
      code: entry.code || '',
    };
    if (!Number.isFinite(Date.parse(clean.at)) || !kinds.has(clean.kind) || !clean.target || !/^[a-z-]+$/.test(clean.result)) throw failure('主动发送日志字段不正确。', 'PROACTIVE_LOG');
    const text = JSON.stringify(clean);
    if (/cookie|set-cookie|authorization|bearer |sk-/i.test(text) && !text.includes('[凭据已隐藏]')) throw failure('主动发送日志含凭据，未写入。', 'PROACTIVE_LOG');
    let value = { version: 1, entries: [] };
    try {
      if (fs.existsSync(this.logFile)) {
        const stat = fs.lstatSync(this.logFile);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1_048_576) throw failure('主动发送日志无法核对，未清空。', 'PROACTIVE_LOG_INVALID');
        value = JSON.parse(fs.readFileSync(this.logFile, 'utf8'));
        if (!value || value.version !== 1 || !Array.isArray(value.entries)) throw failure('主动发送日志无法核对，未清空。', 'PROACTIVE_LOG_INVALID');
      }
    } catch (error) {
      if (error.code === 'PROACTIVE_LOG_INVALID') throw error;
      if (error.code !== 'ENOENT') throw failure('主动发送日志无法核对，未清空。', 'PROACTIVE_LOG_INVALID');
    }
    value.entries = [...value.entries, clean].slice(-400);
    const temporary = `${this.logFile}.${process.pid}.${randomUUID()}.tmp`;
    const descriptor = fs.openSync(temporary, 'wx', 0o600);
    try { fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`); fs.fsyncSync(descriptor); }
    finally { fs.closeSync(descriptor); }
    try { fs.renameSync(temporary, this.logFile); }
    finally { if (fs.existsSync(temporary)) fs.unlinkSync(temporary); }
  }
  recent() {
    try {
      if (!fs.existsSync(this.logFile)) return [];
      const stat = fs.lstatSync(this.logFile);
      if (!stat.isFile() || stat.isSymbolicLink()) return [];
      const value = JSON.parse(fs.readFileSync(this.logFile, 'utf8'));
      if (!value || value.version !== 1 || !Array.isArray(value.entries)) return [];
      return value.entries.slice(-20).map(item => ({ at: item.at, kind: item.kind, target: item.target, result: item.result, code: item.code || '' }));
    } catch { return []; }
  }
  snapshot(store = this.load()) {
    const usage = this.usageNow(store);
    return {
      protocol: 'proactive-send-v1',
      policy: {
        enabled: store.policy.enabled,
        allowlistEnabled: store.policy.allowlistEnabled,
        shareDailyLimit: store.policy.shareDailyLimit,
        messageDailyLimit: store.policy.messageDailyLimit,
        minIntervalMs: store.policy.minIntervalMs,
        allowlist: store.policy.allowlist.map(item => ({ kind: item.kind, value: item.value })),
      },
      daily: { date: usage.date, share: usage.share, message: usage.message, shareLimit: store.policy.shareDailyLimit, messageLimit: store.policy.messageDailyLimit, lastSentAt: usage.lastSentAt },
      uncertain: store.uncertain.map(item => ({ kind: item.kind, targetKey: item.keys[0], keys: [...item.keys], payloadKey: item.payloadKey, at: item.at })),
      recent: this.recent(),
    };
  }
  state() { return this.snapshot(); }
}

function publicResult(kind, target, fields) {
  return { confirmed: false, deliveryUncertain: false, sent: false, kind, target: String(target || '').slice(0, 180), ...fields, reason: redactSendDetail(fields.reason) };
}

function secFromProfile(url) {
  const id = /^https:\/\/www\.douyin\.com\/user\/([^/?#]+)\/?$/.exec(url || '')?.[1] || '';
  return /^MS4[A-Za-z0-9_-]{8,180}$/.test(id) ? id : null;
}

function samePerson(contact, requested, secUid) {
  if (!contact || contact.identityConflict === true || contact.isGroup === true) return false;
  if (requested.conversationId) return contact.id === requested.conversationId;
  const profileSec = secFromProfile(contact.profileUrl);
  if (secUid && profileSec) return profileSec === secUid;
  if (requested.secUid && profileSec) return profileSec === requested.secUid;
  if (requested.profileUrl && contact.profileUrl === requested.profileUrl) return true;
  return false;
}

async function openProfile(page, requested) {
  if (requested.douyinId && !requested.secUid && !requested.profileUrl) {
    await page.goto(`https://www.douyin.com/search/${encodeURIComponent(requested.douyinId)}?type=user`, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    const found = await page.evaluate(readUserSearchDom, requested.douyinId);
    if (!found || found.matches?.length !== 1) throw Object.assign(new Error('没有唯一匹配该抖音号的主页，未继续。'), { code: 'PROACTIVE_AMBIGUOUS' });
    await page.goto(found.matches[0].href, { waitUntil: 'domcontentloaded', timeout: 30_000 });
  } else {
    const sec = requested.secUid || secFromProfile(requested.profileUrl);
    if (!sec && requested.profileUrl) await page.goto(requested.profileUrl, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    else if (sec) await page.goto(`https://www.douyin.com/user/${encodeURIComponent(sec)}`, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    else throw Object.assign(new Error('没有可打开的主页，未继续。'), { code: 'PROACTIVE_NOT_FOUND' });
  }
  const profile = await page.evaluate(readProfileIdentityDom);
  if (!profile || profile.loginRequired || profile.verificationRequired) throw Object.assign(new Error('主页需要登录或验证，未继续。'), { code: 'PROACTIVE_LOGIN' });
  if (profile.ambiguousProfile) throw Object.assign(new Error('主页身份不唯一，未继续。'), { code: 'PROACTIVE_AMBIGUOUS' });
  if (requested.secUid && profile.secUid !== requested.secUid) throw Object.assign(new Error('打开的主页与指定 sec_uid 不一致，未继续。'), { code: 'PROACTIVE_IDENTITY' });
  if (requested.profileUrl && profile.secUid && secFromProfile(requested.profileUrl) && profile.secUid !== secFromProfile(requested.profileUrl)) throw Object.assign(new Error('打开的主页与指定链接不一致，未继续。'), { code: 'PROACTIVE_IDENTITY' });
  if (requested.douyinId) {
    const ids = (profile.douyinIds || []).map(item => item.toLowerCase());
    if (ids.length !== 1 || ids[0] !== requested.douyinId) throw Object.assign(new Error('主页上的抖音号与指定对象不一致，未继续。'), { code: 'PROACTIVE_IDENTITY' });
  }
  if (!profile.secUid || !/^MS4[A-Za-z0-9_-]{8,180}$/.test(profile.secUid)) throw Object.assign(new Error('主页没有可核对的 sec_uid，未继续。'), { code: 'PROACTIVE_IDENTITY' });
  return profile;
}

export function createBrowserProactivePorts({ getForwarder, getChat, getPolicy } = {}) {
  if (typeof getForwarder !== 'function' || typeof getChat !== 'function') throw new TypeError('主动发送需要转发和私信入口。');
  const currentPolicy = () => (typeof getPolicy === 'function' ? getPolicy() : { enabled: false, allowlistEnabled: true, allowlist: [] });
  const contactStillAllowed = contact => {
    const policy = currentPolicy();
    if (policy?.enabled !== true) return false;
    return allowlistHits(policy, { conversationId: contact?.id, secUid: contact?.secUid || secFromProfile(contact?.profileUrl), profileUrl: contact?.profileUrl });
  };
  return {
    async resolveShareContact(requested, { signal } = {}) {
      const chat = await getChat();
      const list = await chat.browser.listContacts({ signal, verifyFollowing: false });
      if (list?.blocked || list?.loginRequired || list?.verificationRequired) throw Object.assign(new Error('联系人核对需要登录或验证，未分享。'), { code: 'PROACTIVE_LOGIN' });
      const found = (list?.contacts || []).filter(item => samePerson(item, requested, requested.secUid || secFromProfile(requested.profileUrl)));
      if (found.length > 1) throw Object.assign(new Error('匹配到多个会话，未分享。'), { code: 'PROACTIVE_AMBIGUOUS' });
      if (found.length === 1) {
        const contact = chat.browser.contacts.get(found[0].id);
        if (!contact || !hasStableConversationIdentity(contact)) throw Object.assign(new Error('会话缺少稳定身份，未分享。'), { code: 'PROACTIVE_IDENTITY' });
        return contact;
      }
      if (requested.conversationId) throw Object.assign(new Error('没有找到这个会话，未分享。'), { code: 'PROACTIVE_NOT_FOUND' });
      const forwarder = await getForwarder();
      const profile = await forwarder.controller.withPage(page => openProfile(page, requested), { signal });
      return renderedUserShareContact(profile.secUid);
    },
    async share(contact, video, { signal } = {}) {
      const forwarder = await getForwarder();
      const input = { recipientId: contact.id, ...(video.url ? { url: video.url } : {}), ...(video.videoId ? { expectedVideoId: video.videoId } : {}) };
      return forwarder.forwardDirected(input, { signal, contact });
    },
    async findDirectContact(requested, { signal } = {}) {
      const chat = await getChat();
      const list = await chat.browser.listContacts({ signal, verifyFollowing: false });
      if (list?.blocked || list?.loginRequired || list?.verificationRequired) throw Object.assign(new Error('联系人核对需要登录或验证，未发送私信。'), { code: 'PROACTIVE_LOGIN' });
      const secUid = requested.secUid || secFromProfile(requested.profileUrl);
      const found = (list?.contacts || []).filter(item => samePerson(item, requested, secUid));
      if (found.length > 1) throw Object.assign(new Error('匹配到多个会话，未发送私信。'), { code: 'PROACTIVE_AMBIGUOUS' });
      if (!found.length) return null;
      const contact = chat.browser.contacts.get(found[0].id);
      if (!contact || !hasStableConversationIdentity(contact)) throw Object.assign(new Error('会话缺少稳定身份，未发送私信。'), { code: 'PROACTIVE_IDENTITY' });
      if (contact.isGroup) throw Object.assign(new Error('主动私信只发给个人，未向群聊发送。'), { code: 'PROACTIVE_GROUP' });
      return contact;
    },
    async openColdConversation(requested, { signal } = {}) {
      const chat = await getChat();
      const opened = await chat.browser.withPage(async page => {
        const profile = await openProfile(page, requested);
        const marked = await page.evaluate(markUniqueMessageButton);
        if (marked !== 1) throw Object.assign(new Error(marked === 0 ? '主页没有可核对的私信按钮，未发送。' : '主页私信按钮不唯一，未发送。'), { code: 'PROACTIVE_IDENTITY' });
        await page.locator('[data-proactive-message="ready"]').click({ timeout: 5000 });
        await page.locator('[data-e2e="im-dialog"]').first().waitFor({ state: 'visible', timeout: 8000 }).catch(() => {});
        return { secUid: profile.secUid };
      }, { signal });
      const contact = await this.findDirectContact({ ...requested, secUid: opened.secUid }, { signal });
      if (!contact) throw Object.assign(new Error('已打开私信，但没有核对到唯一的个人会话，未填写文字。'), { code: 'PROACTIVE_NOT_FOUND' });
      if (secFromProfile(contact.profileUrl) && secFromProfile(contact.profileUrl) !== opened.secUid) throw Object.assign(new Error('打开的会话与主页身份不一致，未填写文字。'), { code: 'PROACTIVE_IDENTITY' });
      return contact;
    },
    async sendText(contact, text, { signal } = {}) {
      const chat = await getChat();
      const authorize = async ({ recipientId, phase } = {}) => {
        if (recipientId !== contact.id || !['prepare', 'monitor', 'before-click'].includes(phase)) return false;
        return contactStillAllowed(contact);
      };
      authorize.beginDispatch = () => {
        if (!contactStillAllowed(contact)) throw Object.assign(new Error('主动私信许可已变化，未点击发送。'), { code: 'PROACTIVE_DISABLED' });
        return () => {};
      };
      return chat.browser.sendMessage(contact.id, text, { allowed: true, expectedContact: contact, signal, authorize });
    },
  };
}

export class ProactiveOutreach {
  constructor({ stateDir, now, ports, getForwarder, getChat } = {}) {
    this.policy = new ProactiveSendPolicy({ stateDir, now });
    this.ports = ports ?? createBrowserProactivePorts({
      getForwarder, getChat, getPolicy: () => this.policy.load().policy,
    });
  }
  state() { return this.policy.state(); }
  configure(input, options) { return this.policy.configure(input, options); }
  resolve(input, options) { return this.policy.resolve(input, options); }
  #log(kind, target, result, code, reason) {
    try { this.policy.append({ at: new Date(this.policy.now()).toISOString(), kind, target, result, code: code || '' }); }
    catch (error) { return redactSendDetail(error.message); }
    return '';
  }
  #refused(kind, target, code, reason) {
    const warning = this.#log(kind, target, 'refused', code, reason);
    return publicResult(kind, target, { code, reason, ...(warning ? { receiptWarning: warning } : {}) });
  }
  async #finish(kind, keys, payloadKey, reservation, result) {
    const target = keys[0];
    const keep = result?.confirmed === true || result?.deliveryUncertain === true;
    if (!keep && reservation) {
      try { this.policy.restore(reservation.previous); } catch { /* 次数已占用时保留，避免超发 */ }
    }
    if (result?.deliveryUncertain === true && payloadKey) {
      try { this.policy.rememberUncertain(kind, keys, payloadKey); } catch { /* 不确定记录失败时仍不自动重发 */ }
    }
    const outcome = result?.confirmed === true ? 'confirmed' : result?.deliveryUncertain === true ? 'uncertain' : 'not-sent';
    const reason = result?.confirmed === true ? '已确认发出。' : result?.reason || result?.failure?.message || (outcome === 'uncertain' ? '发送结果未确认，未再次发送。' : '未发送。');
    const warning = this.#log(kind, target, outcome, result?.failure?.code || result?.code || '', reason);
    return {
      confirmed: result?.confirmed === true,
      deliveryUncertain: result?.deliveryUncertain === true,
      sent: result?.confirmed === true,
      kind,
      target,
      code: result?.failure?.code || result?.code || '',
      reason: redactSendDetail(reason),
      ...(result?.videoId ? { videoId: result.videoId } : {}),
      ...(result?.messageId ? { messageId: result.messageId } : {}),
      ...(warning ? { receiptWarning: warning } : {}),
    };
  }
  async share(args = {}, { signal } = {}) {
    let video, requested;
    try { video = parseShareVideo(args); requested = parseShareRecipient(args.recipient); }
    catch (error) { return this.#refused('share', String(args.recipient || '').slice(0, 180), 'PROACTIVE_INPUT', error.message); }
    const preview = this.#preview('share', requested, video.payloadKey);
    if (!preview.ok) return preview.result;
    let reservation;
    try {
      const contact = await this.ports.resolveShareContact(requested, { signal });
      const keys = identityKeys({ ...requested, secUid: requested.secUid || contact.secUid, conversationId: contact.panelOnly ? requested.conversationId : contact.id }, contact);
      const again = this.policy.preview('share', { ...requested, conversationId: contact.panelOnly ? undefined : contact.id, secUid: contact.secUid || requested.secUid }, video.payloadKey);
      if (!again.ok) return this.#refused('share', keys[0], again.code, again.reason);
      if (this.policy.blocked(this.policy.load(), 'share', keys, video.payloadKey)) return this.#refused('share', keys[0], 'PROACTIVE_UNCERTAIN', '同一对象的上一次分享结果未确认，未再次发送。');
      reservation = this.policy.reserve('share');
      if (!reservation.ok) return this.#refused('share', keys[0], reservation.code, reservation.reason);
      let result;
      try { result = await this.ports.share(contact, video, { signal }); }
      finally { reservation.release?.(); }
      const payloadKey = video.payloadKey || (result?.videoId ? `video:${result.videoId}` : null);
      if (result?.confirmed !== true && result?.deliveryUncertain !== true && /未确认/.test(result?.reason || '')) {
        if (payloadKey) this.policy.rememberUncertain('share', keys, payloadKey);
      }
      return await this.#finish('share', keys, payloadKey, reservation, result);
    } catch (error) {
      reservation?.release?.();
      const keys = identityKeys(requested);
      if (reservation?.ok && /未确认的转发记录/.test(error.message || '') && video.payloadKey) this.policy.rememberUncertain('share', keys, video.payloadKey);
      return this.#finish('share', keys, video.payloadKey, reservation?.ok ? reservation : null, { confirmed: false, deliveryUncertain: error.deliveryUncertain === true, reason: error.message, code: error.code });
    }
  }
  async sendMessage(args = {}, { signal } = {}) {
    let text, requested;
    try { text = parseMessageText(args.text); requested = parseMessageTarget(args); }
    catch (error) { return this.#refused('message', identityKeys(requested || {})[0] || 'message', 'PROACTIVE_INPUT', error.message); }
    const payloadKey = `text:${hash(text)}`;
    const preview = this.#preview('message', requested, payloadKey);
    if (!preview.ok) return preview.result;
    let reservation;
    try {
      let contact = await this.ports.findDirectContact(requested, { signal });
      if (!contact) {
        if (requested.conversationId) return this.#refused('message', `conversation:${requested.conversationId}`, 'PROACTIVE_NOT_FOUND', '没有找到这个会话，未发送私信。');
        contact = await this.ports.openColdConversation(requested, { signal });
      }
      if (!contact || contact.isGroup) return this.#refused('message', identityKeys(requested, contact)[0], 'PROACTIVE_GROUP', '主动私信只发给个人，未发送。');
      const keys = identityKeys(requested, contact);
      if (this.policy.blocked(this.policy.load(), 'message', keys, payloadKey)) return this.#refused('message', keys[0], 'PROACTIVE_UNCERTAIN', '同一对象的同一条私信结果未确认，未再次发送。');
      const again = this.policy.preview('message', { ...requested, conversationId: contact.id, secUid: contact.secUid || requested.secUid || secFromProfile(contact.profileUrl) }, payloadKey);
      if (!again.ok) return this.#refused('message', keys[0], again.code, again.reason);
      reservation = this.policy.reserve('message');
      if (!reservation.ok) return this.#refused('message', keys[0], reservation.code, reservation.reason);
      let result;
      try { result = await this.ports.sendText(contact, text, { signal }); }
      finally { reservation.release?.(); }
      return await this.#finish('message', keys, payloadKey, reservation, result);
    } catch (error) {
      reservation?.release?.();
      const keys = identityKeys(requested);
      return this.#finish('message', keys, payloadKey, reservation?.ok ? reservation : null, { confirmed: false, deliveryUncertain: error.deliveryUncertain === true, reason: error.message, code: error.code });
    }
  }
  #preview(kind, target, payloadKey) {
    try {
      const preview = this.policy.preview(kind, target, payloadKey);
      if (!preview.ok) return { ok: false, result: this.#refused(kind, identityKeys(target)[0] || kind, preview.code, preview.reason) };
      return { ok: true };
    } catch (error) {
      return { ok: false, result: this.#refused(kind, identityKeys(target)[0] || kind, error.code || 'PROACTIVE_POLICY_INVALID', error.message) };
    }
  }
}

export const messagePayloadKey = text => `text:${hash(text)}`;
