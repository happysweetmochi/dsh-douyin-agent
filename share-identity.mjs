import { createHash } from 'node:crypto';

const hash = value => createHash('sha256').update(String(value)).digest('hex');

// 与分享面板 rendered-user 行使用同一套稳定身份：sec_uid 先哈希，再套 rendered:user 前缀。
export function renderedUserShareContact(secUid, name = '指定好友') {
  if (typeof secUid !== 'string' || !/^MS4[A-Za-z0-9_-]{8,180}$/.test(secUid)) throw new TypeError('sec_uid 格式不正确。');
  const display = typeof name === 'string' && name.trim() ? name.trim() : '指定好友';
  if ([...display].length > 80) throw new TypeError('分享对象显示名过长。');
  const key = `rendered:user:${hash(secUid)}`;
  const identityHash = hash(key);
  return {
    id: `conv:${identityHash}`,
    name: display,
    displayName: display,
    isGroup: false,
    identityVersion: 2,
    identityKind: 'rendered-user',
    identityHash,
    identityVerified: true,
    identityBinding: `binding:${hash(`direct\0${key}`)}`,
    verifiedAt: new Date().toISOString(),
    followed: null,
    authorizationKind: 'manual',
    panelOnly: true,
    secUid,
  };
}
