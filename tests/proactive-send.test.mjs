import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { validateToolArguments, TOOL_DEFINITIONS } from '../tool-definitions.mjs';
import { ProactiveOutreach, PROACTIVE_DEFAULTS, normalizeAllowlistToken, parseShareVideo, parseMessageTarget, parseMessageText, redactSendDetail } from '../proactive-send.mjs';
import { renderedUserShareContact } from '../share-identity.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const conv = char => `conv:${char.repeat(64)}`;

function fixture(t, now = () => Date.parse('2026-11-03T04:00:00Z')) {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proactive-send-'));
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  const calls = [];
  const ports = {
    async resolveShareContact(target) { calls.push(['resolve', target]); return { id: target.conversationId || conv('a'), isGroup: false, name: '合成好友', displayName: '合成好友', identityVersion: 2, identityKind: 'native-conversation', identityHash: (target.conversationId || conv('a')).slice(5), identityVerified: true, identityBinding: `binding:${'b'.repeat(64)}`, secUid: target.secUid }; },
    async share(_contact, video) { calls.push(['share', video]); return { confirmed: true, deliveryUncertain: false, videoId: video.videoId || '123', messageId: 'msg:' + 'c'.repeat(64) }; },
    async findDirectContact(target) { calls.push(['find', target]); return target.conversationId ? { id: target.conversationId, isGroup: false, name: '合成好友', displayName: '合成好友', identityVersion: 2, identityKind: 'native-conversation', identityHash: target.conversationId.slice(5), identityVerified: true, identityBinding: `binding:${'d'.repeat(64)}` } : null; },
    async openColdConversation() { throw new Error('测试不应打开主页'); },
    async sendText(_contact, text) { calls.push(['text', text]); return { confirmed: true, deliveryUncertain: false, messageId: 'msg:' + 'e'.repeat(64) }; },
  };
  const service = new ProactiveOutreach({ stateDir, now, ports });
  return { stateDir, service, calls, ports, now };
}

test('默认总开关关闭、名单开启，分享和私信分开计数', () => {
  assert.equal(PROACTIVE_DEFAULTS.enabled, false);
  assert.equal(PROACTIVE_DEFAULTS.allowlistEnabled, true);
  assert.equal(PROACTIVE_DEFAULTS.shareDailyLimit, 3);
  assert.equal(PROACTIVE_DEFAULTS.messageDailyLimit, 5);
  assert.equal(PROACTIVE_DEFAULTS.minIntervalMs, 60_000);
  const share = TOOL_DEFINITIONS.find(item => item.name === 'douyin_share_video');
  const message = TOOL_DEFINITIONS.find(item => item.name === 'douyin_send_message');
  assert.equal(share.parameters.required.includes('recipient'), true);
  assert.equal(message.parameters.required.includes('text'), true);
  assert.doesNotThrow(() => validateToolArguments(share, { recipient: conv('a') }));
  assert.doesNotThrow(() => validateToolArguments(share, { recipient: conv('a'), url: 'https://www.douyin.com/video/123', videoId: '123' }));
  assert.throws(() => validateToolArguments(share, { recipient: conv('a'), url: 'https://www.douyin.com/video/123', videoId: '456' }), /不一致/);
  assert.throws(() => validateToolArguments(message, { text: '你好' }), /只能指定一种/);
  assert.throws(() => validateToolArguments(message, { text: '你好', recipientId: conv('a'), douyinId: 'feiyu' }), /只能指定一种/);
  assert.equal(parseShareVideo({}).videoId, null);
  assert.equal(parseShareVideo({ videoId: '99' }).url, 'https://www.douyin.com/video/99');
  assert.equal(parseMessageTarget({ douyinId: 'FeiYu' }).douyinId, 'feiyu');
  assert.throws(() => parseMessageText('   '), /1 到 1000/);
  assert.equal(normalizeAllowlistToken('https://www.douyin.com/user/MS4wLjABAAAA1234abcd').kind, 'profile');
});

test('总开关关闭时不调用页面，并写入不含 Cookie 的拒绝日志', async t => {
  const f = fixture(t);
  const result = await f.service.share({ recipient: conv('a'), videoId: '123' });
  assert.equal(result.confirmed, false);
  assert.equal(result.code, 'PROACTIVE_DISABLED');
  assert.equal(f.calls.length, 0);
  const log = fs.readFileSync(path.join(f.stateDir, 'proactive-send-log.json'), 'utf8');
  assert.match(log, /refused/);
  assert.equal(log.includes('cookie'), false);
  assert.equal(f.service.state().policy.enabled, false);
  assert.equal(f.service.state().policy.allowlistEnabled, true);
});

test('名单、间隔、分项日上限、不确定不重发和日志脱敏', async t => {
  let clock = Date.parse('2026-11-03T04:00:00Z');
  const f = fixture(t, () => clock);
  const id = conv('a');
  f.service.configure({ enabled: true, allowlistEnabled: true, shareDailyLimit: 1, messageDailyLimit: 2, minIntervalMs: 10_000, allowlist: [id] }, { explicit: true });
  assert.equal((await f.service.share({ recipient: conv('b'), videoId: '123' })).code, 'PROACTIVE_ALLOWLIST');
  assert.equal(f.calls.length, 0);
  const sent = await f.service.share({ recipient: id, videoId: '123' });
  assert.equal(sent.confirmed, true);
  assert.equal(f.calls.some(item => item[0] === 'share'), true);
  clock += 10_000;
  assert.equal((await f.service.share({ recipient: id, videoId: '456' })).code, 'PROACTIVE_DAILY_LIMIT');
  const early = await f.service.sendMessage({ text: '你好秘密正文', recipientId: id });
  assert.equal(early.confirmed, true);
  const tooSoon = await f.service.sendMessage({ text: '另一句', recipientId: id });
  assert.equal(tooSoon.code, 'PROACTIVE_INTERVAL');
  clock += 10_000;
  f.calls.length = 0;
  f.ports.sendText = async (_contact, text) => { f.calls.push(['text', text]); return { confirmed: false, deliveryUncertain: true, reason: 'cookie=super-secret-value' }; };
  const uncertain = await f.service.sendMessage({ text: '你好秘密正文', recipientId: id });
  assert.equal(uncertain.deliveryUncertain, true);
  assert.equal(uncertain.reason.includes('super-secret-value'), false);
  assert.match(uncertain.reason, /凭据已隐藏/);
  const again = await f.service.sendMessage({ text: '你好秘密正文', recipientId: id });
  assert.equal(again.code, 'PROACTIVE_UNCERTAIN');
  assert.equal(f.calls.filter(item => item[0] === 'text').length, 1);
  const stored = fs.readFileSync(path.join(f.stateDir, 'proactive-send.json'), 'utf8') + fs.readFileSync(path.join(f.stateDir, 'proactive-send-log.json'), 'utf8');
  assert.equal(stored.includes('你好秘密正文'), false);
  assert.equal(stored.includes('super-secret-value'), false);
  assert.equal(stored.includes('cookie='), false);
  const state = f.service.state();
  assert.equal(state.daily.share, 1);
  assert.equal(state.daily.message, 2);
  assert.equal(state.uncertain.length, 1);
  f.service.resolve({ kind: 'message', targetKey: state.uncertain[0].targetKey, payloadKey: state.uncertain[0].payloadKey, outcome: 'not-sent' }, { explicit: true });
  assert.equal(f.service.state().uncertain.length, 0);
  assert.equal(fs.readFileSync(path.join(f.stateDir, 'proactive-send-log.json'), 'utf8').includes('resolved-not-sent'), true);
});

test('未真正发出时退回次数，损坏的配置不覆盖', async t => {
  let clock = Date.parse('2026-11-03T04:00:00Z');
  const f = fixture(t, () => clock);
  f.service.configure({ enabled: true, allowlistEnabled: false, shareDailyLimit: 1, messageDailyLimit: 1, minIntervalMs: 10_000 }, { explicit: true });
  f.ports.share = async () => ({ confirmed: false, deliveryUncertain: false, reason: '分享面板没有打开' });
  const missed = await f.service.share({ recipient: conv('a'), videoId: '123' });
  assert.equal(missed.confirmed, false);
  assert.equal(f.service.state().daily.share, 0);
  clock += 10_000;
  f.ports.share = async () => ({ confirmed: true, deliveryUncertain: false, videoId: '123', messageId: 'msg:' + 'c'.repeat(64) });
  assert.equal((await f.service.share({ recipient: conv('a'), videoId: '123' })).confirmed, true);
  assert.equal(f.service.state().daily.share, 1);
  fs.writeFileSync(f.service.policy.file, '{bad');
  const blocked = await f.service.share({ recipient: conv('a'), videoId: '9' });
  assert.equal(blocked.code, 'PROACTIVE_POLICY_INVALID');
  assert.equal(fs.readFileSync(f.service.policy.file, 'utf8'), '{bad');
});

test('上海日期切换后次数清零，但间隔和待核对记录仍在', async t => {
  let clock = Date.parse('2026-11-03T15:59:00Z');
  const f = fixture(t, () => clock);
  const id = conv('a');
  f.service.configure({ enabled: true, allowlistEnabled: false, shareDailyLimit: 1, messageDailyLimit: 1, minIntervalMs: 60_000 }, { explicit: true });
  f.ports.sendText = async () => ({ confirmed: false, deliveryUncertain: true });
  assert.equal((await f.service.sendMessage({ text: '跨日', recipientId: id })).deliveryUncertain, true);
  clock = Date.parse('2026-11-03T16:01:00Z');
  const state = f.service.state();
  assert.equal(state.daily.date, '2026-11-04');
  assert.equal(state.daily.message, 0);
  assert.equal(state.uncertain.length, 1);
  assert.equal((await f.service.sendMessage({ text: '跨日', recipientId: id })).code, 'PROACTIVE_UNCERTAIN');
});

test('分享对象的 sec_uid 与官方面板行使用同一稳定身份', async t => {
  const secUid = 'MS4SyntheticSelectedStableAccount';
  const contact = renderedUserShareContact(secUid);
  const key = `rendered:user:${hash(secUid)}`;
  assert.equal(contact.identityHash, hash(key));
  assert.equal(contact.identityBinding, `binding:${hash(`direct\0${key}`)}`);
  assert.equal(contact.panelOnly, true);
  let selectForwardRecipient;
  try { ({ selectForwardRecipient } = await import('../video-forward.mjs')); }
  catch { return; }
  const row = { isGroup: false, identityConflict: false, sendTargetVerified: true, disabled: false, sendLabel: '分享', identity: { secUid, userId: '1234567890123456' }, buttonTargetId: '1234567890123456' };
  assert.equal(selectForwardRecipient([row], contact).sendLabel, '分享');
  assert.throws(() => selectForwardRecipient([{ ...row, identity: { ...row.identity, secUid: 'MS4SyntheticDifferentAccount' } }], contact), /稳定身份/);
});

test('脱敏会去掉 Cookie 和密钥样式', () => {
  assert.equal(redactSendDetail('失败 cookie=super-secret-value 以及 sk-abcdef').includes('super-secret-value'), false);
  assert.equal(redactSendDetail('失败 cookie=super-secret-value 以及 sk-abcdef').includes('sk-abcdef'), false);
});

test('设置只接受明确保存，并拒绝越界次数', async t => {
  const f = fixture(t);
  assert.throws(() => f.service.configure({ enabled: true }), /明确保存/);
  assert.throws(() => f.service.configure({ enabled: true, shareDailyLimit: 21 }, { explicit: true }), /1 到 20/);
  assert.throws(() => f.service.configure({ minIntervalMs: 999 }, { explicit: true }), /10 秒/);
  const saved = f.service.configure({ enabled: false, allowlistEnabled: false, allowlist: ['FeiYu88', conv('c')] }, { explicit: true });
  assert.equal(saved.policy.allowlistEnabled, false);
  assert.deepEqual(saved.policy.allowlist.map(item => item.value), ['feiyu88', conv('c')]);
});
