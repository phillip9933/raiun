import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import ts from 'typescript';
const source = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
const parsed = ts.createSourceFile('main.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
const names = ['addAccount','addAccountModal','normalizeServerAddress','updateAddAccountSubmit'];
const extracted = parsed.statements.filter(n => ts.isFunctionDeclaration(n) && names.includes(n.name?.text)).map(n => n.getFullText(parsed)).join('\n');
const compiled = ts.transpileModule(extracted, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
test('actual account setup uses label-only Windows payload and retains Linux folder-first flow', async () => {
  function fixture(signInFirst) {
    const calls = [], submit = {};
    const state = {status:signInFirst ? {account_setup_requires_sign_in:true} : {}, addAccountStep:'details', addAccountLabel:' Work ', addAccountRoot:signInFirst ? 'C:\\must-not-send' : '/synthetic/cloud', addAccountServer:signInFirst ? '' : 'https://synthetic.invalid', addAccountClientId:'', addAccountBusy:false, mutationBusy:0, accountEpoch:1, selectedAccount:'old',addAccountCreatedId:'',addAccountError:''};
    const context = {state, URL, accountSelectionRevision:0, featureAvailable:()=>true, render:()=>{}, svg:()=>'',esc:v=>String(v), app:{querySelector:()=>submit}, request:async(action,payload)=>{calls.push([action,structuredClone(payload)]);return action==='account_add'?{id:'new'}:{};},syncAccountsForSelection:async id=>{state.selectedAccount=id;state.accountEpoch++;},refresh:async()=>{},isCurrentAccount:(epoch,id)=>epoch===state.accountEpoch&&id===state.selectedAccount,closeAccountSetup:()=>{state.addAccountOpen=false;},beginNewAccountSignIn:async()=>calls.push(['auth_begin']),isStaleAccountRequest:()=>false,messageOf:String};
    vm.createContext(context); vm.runInContext(compiled,context);
    return {context,state,calls,submit};
  }
  const windows = fixture(true);
  const windowsHtml = windows.context.addAccountModal();
  assert.match(windowsHtml,/id="account-label"/);
  assert.doesNotMatch(windowsHtml,/id="account-(server|client-id|root)"/);
  windows.context.updateAddAccountSubmit(); assert.equal(windows.submit.disabled,false);
  await windows.context.addAccount();
  assert.deepEqual(windows.calls,[['account_add',{label:'Work'}],['account_select',{profile_id:'new'}]]);
  assert.equal(windows.state.selectedAccount,'new'); assert.equal(windows.state.addAccountOpen,false);
  assert.match(windows.state.message,/Sign in from Settings/);
  assert.equal(windows.state.addAccountBusy,false); assert.equal(windows.state.mutationBusy,0);
  const linux = fixture(false);
  assert.match(linux.context.addAccountModal(),/id="account-root"/);
  await linux.context.addAccount();
  assert.deepEqual(linux.calls,[['account_add',{label:'Work',cloud_root:'/synthetic/cloud'}],['account_select',{profile_id:'new'}],['auth_begin']]);
  assert.equal(linux.state.addAccountStep,'waiting');
  const noRoot = fixture(false); noRoot.state.addAccountRoot='';
  noRoot.context.updateAddAccountSubmit(); assert.equal(noRoot.submit.disabled,true);
  await noRoot.context.addAccount(); assert.deepEqual(noRoot.calls,[]);
});
