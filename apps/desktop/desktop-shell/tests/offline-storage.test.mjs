import test from 'node:test';
import assert from 'node:assert/strict';
import ts from 'typescript';
import { readFile } from 'node:fs/promises';
const source = await readFile(new URL('../src/offline-storage.ts', import.meta.url), 'utf8');
const {parseCacheLimit,cacheLimitDraft,formatStorageBytes,validateCacheLimitReply}=await import('data:text/javascript;base64,'+Buffer.from(ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText).toString('base64'));
test('cache limit accepts exact IEC values and rejects unsafe, ambiguous or out of range input',()=>{
 assert.equal(parseCacheLimit('0.25','GiB'),256*1024**2);
 assert.equal(parseCacheLimit('5','GiB'),5*1024**3);
 assert.equal(parseCacheLimit('1024','GiB'),1024**4);
 for(const [amount,unit] of [['0','GiB'],['255','MiB'],['1025','GiB'],['1e3','MiB'],['Infinity','GiB'],['-1','GiB'],['1,5','GiB'],['1.001','GiB'],['1','GB']]) assert.throws(()=>parseCacheLimit(amount,unit));
 for(const bytes of [256*1024**2,1024**3,5*1024**3]) {const d=cacheLimitDraft(bytes);assert.equal(parseCacheLimit(d.amount,d.unit),bytes);}
 assert.equal(formatStorageBytes(1024**3),'1.0 GiB');assert.equal(formatStorageBytes(NaN),'Not available');
});
test('saved quota acknowledgements must match account, generation, device token, scope and exact value',()=>{
 const expected={profileId:'test',generation:4,windows:true,token:'scope'};
 const ok={profile_id:'test',auth_generation:4,recovery_scope_token:'scope',scope:'device_all_accounts',quota_bytes:5*1024**3,saved:true,eviction_performed:false};
 validateCacheLimitReply(ok,expected,ok.quota_bytes);
 for(const change of [{profile_id:'other'},{auth_generation:3},{recovery_scope_token:'old'},{scope:'account'},{quota_bytes:1},{saved:false},{eviction_performed:true}]) assert.throws(()=>validateCacheLimitReply({...ok,...change},expected,ok.quota_bytes));
});
