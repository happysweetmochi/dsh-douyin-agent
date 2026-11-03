import React from 'react';
import { Button, Input, Switch, Tag } from '@dsh/primitives';
import { useAutoSave, AutoSaveStatus } from './use-auto-save.jsx';

function bounded(value, label, min, max) {
  const number = Number(value);
  if (String(value).trim() === '' || !Number.isSafeInteger(number) || number < min || number > max) throw new Error(`${label}须为 ${min} 到 ${max} 的整数。`);
  return number;
}

export function readProactive(value) {
  return {
    enabled: value?.policy?.enabled === true,
    allowlistEnabled: value?.policy?.allowlistEnabled !== false,
    shareDailyLimit: value?.policy?.shareDailyLimit ?? 3,
    messageDailyLimit: value?.policy?.messageDailyLimit ?? 5,
    minIntervalSeconds: Math.round((value?.policy?.minIntervalMs ?? 60000) / 1000),
    allowlistText: (value?.policy?.allowlist || []).map(item => item.value).join('\n'),
  };
}

export function encodeProactive(draft) {
  return {
    enabled: draft.enabled === true,
    allowlistEnabled: draft.allowlistEnabled === true,
    shareDailyLimit: bounded(draft.shareDailyLimit, '每日主动分享次数', 1, 20),
    messageDailyLimit: bounded(draft.messageDailyLimit, '每日主动私信次数', 1, 20),
    minIntervalMs: bounded(draft.minIntervalSeconds, '发送间隔秒数', 10, 3600) * 1000,
    allowlist: String(draft.allowlistText || '').split(/[\n,;，；]+/).map(item => item.trim()).filter(Boolean),
  };
}

export function ProactiveSendPanel({ state, api, run, busy, connected }) {
  const ready = connected && state?.protocol === 'proactive-send-v1';
  const save = useAutoSave({
    value: ready ? state : null,
    initial: readProactive(null),
    read: readProactive,
    encode: encodeProactive,
    write: payload => api('/api/proactive/configure', payload),
    canonical: saved => saved?.policy ? encodeProactive(readProactive(saved)) : saved,
    available: ready,
  });
  return <section className="panel" aria-label="主动发送"><div className="panel-title"><h2>主动发送</h2><Tag>{ready && state.policy?.enabled ? '已开启' : '默认关闭'}</Tag></div>
    <p className="notice">模型调用 douyin_share_video 或 douyin_send_message 时才走这里。总开关默认关闭，允许名单默认开启。分享和私信分开计每日次数，两次发送之间有最小间隔。结果未确认不会自动重发。建议用小号：抖音网页改版或风控都可能导致失败。</p>
    <div className="switch-row"><span>允许模型主动发送</span><Switch label="允许模型主动发送" checked={save.draft.enabled} disabled={!ready} onChange={value => save.edit({ enabled: value }, { immediate: true })} /></div>
    <div className="switch-row"><span>只发给允许名单</span><Switch label="只发给允许名单" checked={save.draft.allowlistEnabled} disabled={!ready} onChange={value => save.edit({ allowlistEnabled: value }, { immediate: true })} /></div>
    <label className="field"><span>每日主动分享上限</span><Input aria-label="每日主动分享上限" type="number" min={1} max={20} value={save.draft.shareDailyLimit} disabled={!ready} onChange={event => save.edit({ shareDailyLimit: event.target.value })} /></label>
    <label className="field"><span>每日主动私信上限</span><Input aria-label="每日主动私信上限" type="number" min={1} max={20} value={save.draft.messageDailyLimit} disabled={!ready} onChange={event => save.edit({ messageDailyLimit: event.target.value })} /></label>
    <label className="field"><span>两次发送最小间隔（秒）</span><Input aria-label="两次发送最小间隔（秒）" type="number" min={10} max={3600} value={save.draft.minIntervalSeconds} disabled={!ready} onChange={event => save.edit({ minIntervalSeconds: event.target.value })} /></label>
    <label className="field"><span>允许发送的对象，每行一个</span><textarea aria-label="允许发送的对象" rows={4} value={save.draft.allowlistText} disabled={!ready} onChange={event => save.edit({ allowlistText: event.target.value }, { blurOnly: true })} onBlur={() => { void save.flush(); }} /></label>
    <AutoSaveStatus status={save.status} />
    <p className="notice">{ready ? `今日主动分享 ${state.daily?.share || 0}/${state.daily?.shareLimit || save.draft.shareDailyLimit} 次 · 主动私信 ${state.daily?.message || 0}/${state.daily?.messageLimit || save.draft.messageDailyLimit} 次。` : '主动发送设置尚未核实。'} 对象可以是会话 ID、抖音号、sec_uid 或主页链接。日志只记时间、对象、类型和结果，不记正文和 Cookie。</p>
    {(state?.uncertain || []).map(item => <div className="paused-contact" key={`${item.kind}:${item.payloadKey}`}><strong>待核对{item.kind === 'share' ? '分享' : '私信'}</strong><p>{item.targetKey}。核对只记录结果，不会重发。</p><div className="actions"><Button size="sm" disabled={!ready || busy.has(`proactive:${item.payloadKey}`)} onClick={() => { void run(`proactive:${item.payloadKey}`, () => api('/api/proactive/resolve', { kind: item.kind, targetKey: item.targetKey, payloadKey: item.payloadKey, outcome: 'not-sent' })); }}>已核对未发出</Button><Button size="sm" variant="outline" disabled={!ready || busy.has(`proactive:${item.payloadKey}:ok`)} onClick={() => { void run(`proactive:${item.payloadKey}:ok`, () => api('/api/proactive/resolve', { kind: item.kind, targetKey: item.targetKey, payloadKey: item.payloadKey, outcome: 'confirmed' })); }}>已核对已发出</Button></div></div>)}
    {(state?.recent || []).slice().reverse().map(item => <p className="notice" key={`${item.at}:${item.target}:${item.result}`}>{item.at} · {item.kind === 'share' ? '分享' : '私信'} · {item.target} · {item.result}</p>)}
  </section>;
}
