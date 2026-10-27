import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';
const source = await readFile(new URL('../src/account-avatar.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText;
const {accountAvatarCacheKey,AccountAvatarCache,validatedAccountAvatar}=await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);
test('avatar replies are exact-profile and generation scoped and accept only bounded PNG/JPEG data URLs',()=>{
  const data='data:image/png;base64,AA==';
  assert.equal(accountAvatarCacheKey('profile-a',4),'profile-a:4');
  assert.equal(validatedAccountAvatar({profile_id:'profile-a',auth_generation:4,data_url:data},'profile-a',4),data);
  assert.equal(validatedAccountAvatar({profile_id:'profile-b',auth_generation:4,data_url:data},'profile-a',4),null);
  assert.equal(validatedAccountAvatar({profile_id:'profile-a',auth_generation:3,data_url:data},'profile-a',4),null);
  assert.equal(validatedAccountAvatar({profile_id:'profile-a',auth_generation:4,data_url:'https://example.test/avatar.png'},'profile-a',4),null);
  assert.equal(validatedAccountAvatar({profile_id:'profile-a',auth_generation:4,data_url:'data:image/svg+xml;base64,AA=='},'profile-a',4),null);
});
test('different profiles load concurrently and remain isolated in the bounded cache',()=>{
  const cache=new AccountAvatarCache(2),a=cache.begin('profile-a',1,7),b=cache.begin('profile-b',3,7);
  assert.ok(a&&b);assert.notEqual(a.profileId,b.profileId);assert.equal(a.accountEpoch,b.accountEpoch);
  const imageA='data:image/png;base64,AA==',imageB='data:image/jpeg;base64,AQ==';
  assert.equal(cache.complete(a,{profile_id:'profile-a',auth_generation:1,data_url:imageA},7,1,true),true);
  assert.equal(cache.complete(b,{profile_id:'profile-b',auth_generation:3,data_url:imageB},7,3,true),true);
  assert.equal(cache.get('profile-a',1),imageA);assert.equal(cache.get('profile-b',3),imageB);
  assert.equal(cache.begin('profile-c',4,7),null,'cache and pending work are bounded to two profiles');
});
test('late or removed-account avatar responses cannot populate a cache after an epoch switch',()=>{
  const cache=new AccountAvatarCache(2),old=cache.begin('profile-a',1,7);
  cache.cancelPendingExceptEpoch(8);
  const current=cache.begin('profile-a',1,8);
  const image='data:image/png;base64,AA==';
  assert.equal(cache.complete(old,{profile_id:'profile-a',auth_generation:1,data_url:image},8,1,true),false);
  assert.equal(cache.complete(current,{profile_id:'profile-a',auth_generation:1,data_url:image},8,1,false),false);
  assert.equal(cache.get('profile-a',1),undefined);
  const latest=cache.begin('profile-a',1,8);
  assert.equal(cache.complete(latest,{profile_id:'profile-a',auth_generation:1,data_url:image},8,1,true),true);
  cache.clearProfile('profile-a');assert.equal(cache.get('profile-a',1),undefined);
});
