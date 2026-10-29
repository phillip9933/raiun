import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import ts from 'typescript';
const compile=async name=>ts.transpileModule(await readFile(new URL(`../src/${name}.ts`,import.meta.url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText;
const url=s=>'data:text/javascript;base64,'+Buffer.from(s).toString('base64');
let code=await compile('sharing-controller');
for(const name of ['sharing-workspace','sharing-inventory','guest-sharing'])code=code.replace(`'./${name}'`,JSON.stringify(url(await compile(name))));
const {SharingController}=await import(url(code));
class Field{constructor(field,value){this.dataset={sharingField:field};this.value=value;this.handlers={};}addEventListener(name,fn){this.handlers[name]=fn;}}
globalThis.HTMLSelectElement=class Select extends Field{};
const owned=(id='owned-1',path='/Folder')=>({ocs_share_id:id,kind:{kind:'user'},path,resource_id:'resource',recipient_id:'person',recipient_display_name:'Existing recipient',permissions:1,expires_at:null});
function setup(override={}){
 let c={server:'https://cloud.example.test/',profileId:'test',accountEpoch:1,generation:3,connected:true,spaces:[{id:'space',name:'Personal',personal:true}]};
 const calls=[],copied=[],confirmations=[];let mutations=0;
 const ack=()=>({profile_id:c.profileId,auth_generation:c.generation});
 const deps={context:()=>c,render:()=>{},confirm:async message=>{confirmations.push(message);return override.confirm?override.confirm(message):true;},copy:async value=>{copied.push(value);},rpc:async(action,args)=>{
  calls.push({action,args});if(override.rpc){const v=await override.rpc(action,args);if(v!==undefined)return v;}
  if(action==='sharing_capabilities')return{...ack(),capabilities:{files_sharing_enabled:true,groups_enabled:false,public_links_enabled:true,public_link_creation_supported:true,public_password_required_for:[]},guest_invitations:true};
  if(action==='sharing_inventory')return{...ack(),inventory:args.inventory,read_only:true,snapshot:{scope:{account_id:c.profileId,server_url:'https://cloud.example.test/',token_generation:1,response_complete:true},items:args.inventory==='with-me'?[{shared_item_id:'incoming-1',name:'Shared project folder',is_folder:true,remote_item:{id:'target',created_by:{user_display_name:'Casey'}}}]:args.inventory==='by-me'?[owned(),...(mutations?[{...owned('guest-created'),recipient_display_name:'guest@example.test'}]:[])]:[{...owned('link'),kind:{kind:'public_link'},public_url:'https://cloud.example.test/s/synthetic'}]}};
  if(action==='list')return[{id:'resource',path:'/Folder',directory:true,encrypted:false,writable:true},{path:'/secret',directory:true,encrypted:true,writable:true}];
  if(action==='guest_permissions')return{...ack(),available:true,item_id:'resource',roles:[{id:'view',name:'Can view'}],guests:[]};
  if(action==='sharing_permissions')return{...ack(),item_id:'resource',permissions:{roles:[{id:'view',name:'Can view'},{id:'edit',name:'Can edit'}],people_and_groups:[],public_links:[]},link_types:['view','edit']};
  if(action==='guest_invite'){mutations++;return{...ack(),accepted:true};}
  if(action==='sharing_owned_settings'){
   const share={...owned(args.permission_id),space_id:null,owner_id:null,recipient_id:'person',label:null,expires_at:override.expiresAt??null};
   if(args.inventory==='public-links'){share.kind={kind:'public_link'};share.label='Review link';share.recipient_id=null;}
   return{...ack(),inventory:args.inventory,read_only:true,settings:{scope:{account_id:c.profileId,server_url:c.server,token_generation:1,response_complete:true},category:args.inventory==='public-links'?'public_links':'shared_by_me',share,baseline:Object.fromEntries(['ocs_share_id','resource_id','space_id','owner_id','kind','recipient_id','path','file_target','item_type','permissions','expires_at','label'].map(k=>[k,share[k]])),editable_fields:args.inventory==='public-links'?['access','expiration','name']:['access','expiration'],access_choices:[{id:'view',name:'Can view',permissions:1},{id:'edit',name:'Can edit',permissions:15}]}};
  }
  if(action==='sharing_owned_update')return{...ack(),accepted:true};
  if(action==='sharing_owned_revoke')return{...ack(),accepted:true};
  throw new Error('Unexpected RPC '+action);
 }};
 const ctrl=new SharingController(deps);
 const fieldRoot=el=>({querySelectorAll:s=>s==='[data-sharing-field]'?[el]:[]});
 const input=(field,value,select=false)=>{const el=select?new HTMLSelectElement(field,value):new Field(field,field==='password'?'':value);ctrl.bind(fieldRoot(el));if(field==='password')el.value=value;el.handlers[select?'change':'input']();};
 const passwordValue=()=>{const el=new Field('password','');ctrl.bind(fieldRoot(el));return el.value;};
 return{ctrl,calls,copied,confirmations,input,passwordValue,setContext:next=>{c=next;},context:()=>c};
}
const settle=()=>new Promise(done=>setTimeout(done,0));
async function choose(h,method='guests'){await h.ctrl.enter();await h.ctrl.handle({type:'set-inventory',inventory:'by-me'});await h.ctrl.handle({type:'new-share'});await h.ctrl.handle({type:'choose-method',method});h.input('space','space',true);await settle();await h.ctrl.handle({type:'select-item',itemId:'/Folder'});await h.ctrl.handle({type:'use-item'});}
test('landing automatically lists received items and changing tabs automatically lists outgoing shares without browsing',async()=>{
 const h=setup();await h.ctrl.enter();let html=h.ctrl.render();assert.match(html,/Shared project folder/);assert.match(html,/Shared with me/);assert.doesNotMatch(html,/id="sharing-recipient"|Choose a file or folder to check/);
 assert.equal(h.calls.filter(v=>v.action==='list').length,0);
 await h.ctrl.handle({type:'set-inventory',inventory:'by-me'});html=h.ctrl.render();assert.match(html,/Existing recipient/);assert.ok(html.indexOf('Existing recipient')<html.indexOf('data-sharing-action="new-share"'));
 assert.equal(h.calls.filter(v=>v.action==='sharing_inventory').length,2);
});
test('creation uses an explicit method choice and only the final action sends an invitation',async()=>{
 const h=setup();await choose(h);assert.equal(h.calls.filter(v=>v.action==='guest_invite').length,0);
 h.input('recipient','invalid');await h.ctrl.handle({type:'save-access'});assert.equal(h.calls.filter(v=>v.action==='guest_invite').length,0);
 h.input('recipient','guest@example.test');await h.ctrl.handle({type:'save-access'});
 const sends=h.calls.filter(v=>v.action==='guest_invite');assert.equal(sends.length,1);assert.equal(sends[0].args.expected_item_id,'resource');assert.equal(sends[0].args.expected_auth_generation,3);
 assert.match(h.ctrl.render(),/guest@example.test/);assert.doesNotMatch(h.ctrl.render(),/id="sharing-recipient"/);
});
test('stale inventory replies cannot expose data after switching account',async()=>{
 let release;const held=new Promise(done=>release=done);const h=setup({rpc:async action=>action==='sharing_inventory'?held:undefined});
 const pending=h.ctrl.enter();await settle();h.setContext({...h.context(),profileId:'other',accountEpoch:2,connected:false});h.ctrl.render();
 release({profile_id:'test',auth_generation:3,inventory:'with-me',read_only:true,snapshot:{scope:{account_id:'test',response_complete:true,token_generation:1},items:[{shared_item_id:'private',name:'Old account file',is_folder:true,remote_item:{id:'remote'}}]}});await pending;
 assert.doesNotMatch(h.ctrl.render(),/Old account file/);
});
test('failed inventory refresh preserves the previous rows and never reports an empty successful list',async()=>{
 let fail=false;const h=setup({rpc:async action=>{if(action==='sharing_inventory'&&fail)throw new Error('Could not refresh the sharing list.');}});
 await h.ctrl.enter();fail=true;await h.ctrl.handle({type:'refresh'});const html=h.ctrl.render();assert.match(html,/Shared project folder/);assert.match(html,/Could not refresh/);assert.doesNotMatch(html,/No files or folders have been shared/);
});
test('an uncertain invitation is never automatically resent and another creation is blocked until refresh',async()=>{
 const h=setup({rpc:async action=>{if(action==='guest_invite')throw new Error('Could not confirm the sharing result. Refresh before trying again.');}});await choose(h);h.input('recipient','guest@example.test');await h.ctrl.handle({type:'save-access'});await h.ctrl.handle({type:'save-access'});await h.ctrl.handle({type:'new-share'});
 assert.equal(h.calls.filter(v=>v.action==='guest_invite').length,1);assert.match(h.ctrl.render(),/Refresh/);
});
test('incoming items can never revoke and outgoing revocation cannot cross an account change while confirmation is open',async()=>{
 const h=setup();await h.ctrl.enter();await h.ctrl.handle({type:'remove-access',shareId:'incoming:incoming-1'});assert.equal(h.calls.filter(v=>v.action==='sharing_owned_revoke').length,0);
 let confirmed;const gate=new Promise(done=>confirmed=done);const revoke=setup({confirm:()=>gate});await revoke.ctrl.enter();await revoke.ctrl.handle({type:'set-inventory',inventory:'by-me'});
 const pending=revoke.ctrl.handle({type:'remove-access',shareId:'ocs:owned-1'});await settle();revoke.setContext({...revoke.context(),profileId:'other',accountEpoch:2,connected:false});revoke.ctrl.render();confirmed(true);await pending;
 assert.equal(revoke.calls.filter(v=>v.action==='sharing_owned_revoke').length,0);
});
test('outgoing revoke sends the OCS share identifier and exact resource through the separate OCS operation',async()=>{
 const h=setup();await h.ctrl.enter();await h.ctrl.handle({type:'set-inventory',inventory:'by-me'});await h.ctrl.handle({type:'remove-access',shareId:'ocs:owned-1'});
 const call=h.calls.find(v=>v.action==='sharing_owned_revoke');assert.equal(call.args.permission_id,'owned-1');assert.equal(call.args.expected_resource_id,'resource');assert.equal(call.args.inventory,'by-me');assert.equal(h.calls.some(v=>v.action==='guest_revoke'||v.action==='sharing_revoke'),false);
});
test('public links list automatically and copy only after an explicit click, keeping URLs out of markup',async()=>{
 const h=setup();await h.ctrl.enter();await h.ctrl.handle({type:'set-inventory',inventory:'public-links'});assert.doesNotMatch(h.ctrl.render(),/https:\/\/cloud\.example\.test\/s\/synthetic/);assert.equal(h.copied.length,0);
 await h.ctrl.handle({type:'copy-link',shareId:'ocs:link'});assert.deepEqual(h.copied,['https://cloud.example.test/s/synthetic']);
});
test('encrypted chooser entries cannot enter a share form',async()=>{const h=setup();await h.ctrl.enter();await h.ctrl.handle({type:'set-inventory',inventory:'by-me'});await h.ctrl.handle({type:'new-share'});await h.ctrl.handle({type:'choose-method',method:'guests'});h.input('space','space',true);await settle();await h.ctrl.handle({type:'select-item',itemId:'/secret'});await h.ctrl.handle({type:'use-item'});assert.equal(h.calls.filter(v=>v.action==='guest_permissions').length,0);});
test('role-only and link-name-only drafts prompt before switching inventory',async()=>{
 for(const method of ['guests','links']){const h=setup();await choose(h,method);h.input(method==='guests'?'role':'link-name',method==='guests'?'edit':'Project link',method==='guests');await h.ctrl.handle({type:'set-inventory',inventory:'public-links'});assert.equal(h.confirmations.length,1);}
});
test('directory search labels results partial when one recipient kind fails',async()=>{
 const h=setup({rpc:async(action,args)=>{
  if(action==='sharing_capabilities')return{profile_id:'test',auth_generation:3,capabilities:{files_sharing_enabled:true,groups_enabled:true,public_links_enabled:true,public_link_creation_supported:true},guest_invitations:true};
  if(action==='sharing_recipients'&&args.recipient_kind==='user')return{profile_id:'test',auth_generation:3,recipients:[{id:'person-1',display_name:'Casey',kind:'user'}]};
  if(action==='sharing_recipients'&&args.recipient_kind==='group')throw new Error('Directory unavailable');
 }});await choose(h,'people');h.input('recipient-query','case');await new Promise(resolve=>setTimeout(resolve,380));assert.match(h.ctrl.render(),/Casey/);assert.match(h.ctrl.render(),/partial result/);
});
test('clearing or choosing an invalid location removes the previous location entries',async()=>{
 const h=setup();await choose(h);await h.ctrl.handle({type:'change-item'});assert.match(h.ctrl.render(),/Folder/);h.input('space','missing-space',true);await settle();assert.doesNotMatch(h.ctrl.render(),/Open folder Folder/);assert.match(h.ctrl.render(),/Choose a location/);
});

async function edit(h,inventory='by-me',id='ocs:owned-1'){await h.ctrl.enter();await h.ctrl.handle({type:'set-inventory',inventory});await h.ctrl.handle({type:'edit-access',shareId:id});}
test('outgoing share editor loads fresh settings and saves only changed fields with its OCS baseline',async()=>{const h=setup();await edit(h);assert.match(h.ctrl.render(),/Edit share/);h.input('role','edit',true);await h.ctrl.handle({type:'save-access'});const call=h.calls.find(c=>c.action==='sharing_owned_update');assert.equal(call.args.permission_id,'owned-1');assert.equal(call.args.expected_resource_id,'resource');assert.equal(call.args.baseline.recipient_id,'person');assert.deepEqual(call.args.update,{kind:'user_or_group',permissions:15,expiration:{action:'keep'}});assert.equal(h.calls.some(c=>c.action==='sharing_update'),false);assert.match(h.ctrl.render(),/Sharing settings saved/);});
test('public link name edits preserve access expiry and password by omitting unrelated updates',async()=>{const h=setup();await edit(h,'public-links','ocs:link');assert.match(h.ctrl.render(),/Its current link and password are kept/);h.input('link-name','New name');await h.ctrl.handle({type:'save-access'});const call=h.calls.find(c=>c.action==='sharing_owned_update');assert.deepEqual(call.args.update,{kind:'public_link',name:'New name',expiration:{action:'keep'}});assert.equal('password' in call.args.update,false);});
test('unchanged settings cause no write and incoming shares can never open an editor',async()=>{const h=setup();await h.ctrl.enter();await h.ctrl.handle({type:'edit-access',shareId:'incoming:incoming-1'});assert.equal(h.calls.some(c=>c.action==='sharing_owned_settings'),false);await edit(h);await h.ctrl.handle({type:'save-access'});assert.equal(h.calls.some(c=>c.action==='sharing_owned_update'),false);});
test('expiry clear and set are explicit while unchanged expirations stay untouched',async()=>{const h=setup();await edit(h);h.input('expiry','2035-10-28T12:30');await h.ctrl.handle({type:'save-access'});const call=h.calls.find(c=>c.action==='sharing_owned_update');assert.equal(call.args.update.expiration.action,'set');assert.equal(Number.isFinite(Date.parse(call.args.update.expiration.value)),true);assert.equal('permissions'in call.args.update,false);});
test('an uncertain edit cannot repeat and Refresh reloads its current settings',async()=>{const h=setup({rpc:async action=>{if(action==='sharing_owned_update')throw new Error('Could not confirm the sharing result. Refresh before trying again.');}});await edit(h);h.input('role','edit',true);await h.ctrl.handle({type:'save-access'});await h.ctrl.handle({type:'save-access'});assert.equal(h.calls.filter(c=>c.action==='sharing_owned_update').length,1);assert.match(h.ctrl.render(),/data-sharing-action="refresh"/);await h.ctrl.handle({type:'refresh'});assert.equal(h.calls.filter(c=>c.action==='sharing_owned_settings').length,2);assert.doesNotMatch(h.ctrl.render(),/sharing-unknown-outcome/);});
test('an account switch while settings load cannot expose the old account editor',async()=>{let finish;const gate=new Promise(done=>finish=done);const h=setup({rpc:async action=>action==='sharing_owned_settings'?gate:undefined});await h.ctrl.enter();await h.ctrl.handle({type:'set-inventory',inventory:'by-me'});const pending=h.ctrl.handle({type:'edit-access',shareId:'ocs:owned-1'});await settle();h.setContext({...h.context(),profileId:'another',accountEpoch:2,connected:false});h.ctrl.render();finish({profile_id:'test',auth_generation:3});await pending;assert.doesNotMatch(h.ctrl.render(),/Existing recipient|Edit share/);assert.equal(h.calls.some(c=>c.action==='sharing_owned_update'),false);});

test('clearing an existing expiration is distinct from leaving its exact timestamp untouched',async()=>{const h=setup({expiresAt:'2035-10-28T03:30:17Z'});await edit(h);h.input('expiry','');await h.ctrl.handle({type:'save-access'});const call=h.calls.find(c=>c.action==='sharing_owned_update');assert.deepEqual(call.args.update.expiration,{action:'clear'});assert.equal(call.args.baseline.expires_at,'2035-10-28T03:30:17Z');const keep=setup({expiresAt:'2035-10-28T03:30:17Z'});await edit(keep);keep.input('role','edit',true);await keep.ctrl.handle({type:'save-access'});assert.deepEqual(keep.calls.find(c=>c.action==='sharing_owned_update').args.update.expiration,{action:'keep'});});
test('same-profile authentication generation changes clear an edit draft before any write',async()=>{const h=setup();await edit(h);h.input('role','edit',true);h.setContext({...h.context(),generation:4});h.ctrl.render();await h.ctrl.handle({type:'save-access'});assert.equal(h.calls.some(c=>c.action==='sharing_owned_update'),false);assert.doesNotMatch(h.ctrl.render(),/Edit share|Existing recipient/);});

test('failed inventory refresh keeps rows readable but blocks stale edit and remove actions',async()=>{let fail=false;const h=setup({rpc:async action=>{if(action==='sharing_inventory'&&fail)throw new Error('List refresh failed');}});await h.ctrl.enter();await h.ctrl.handle({type:'set-inventory',inventory:'by-me'});fail=true;await h.ctrl.handle({type:'refresh'});assert.match(h.ctrl.render(),/Existing recipient/);assert.doesNotMatch(h.ctrl.render(),/data-sharing-action="edit-access"|data-sharing-action="remove-access"/);await h.ctrl.handle({type:'edit-access',shareId:'ocs:owned-1'});await h.ctrl.handle({type:'remove-access',shareId:'ocs:owned-1'});assert.equal(h.calls.some(c=>c.action==='sharing_owned_revoke'||c.action==='sharing_owned_settings'),false);fail=false;await h.ctrl.handle({type:'refresh'});assert.match(h.ctrl.render(),/data-sharing-action="edit-access"/);});

test('directory-selected people and group invitations send the exact server identity only after review',async()=>{
 for(const recipientKind of ['user','group']){
  const h=setup({rpc:async(action,args)=>{
   if(action==='sharing_capabilities')return{profile_id:'test',auth_generation:3,capabilities:{files_sharing_enabled:true,groups_enabled:true,public_links_enabled:true,public_link_creation_supported:true},guest_invitations:true};
   if(action==='sharing_recipients')return{profile_id:'test',auth_generation:3,recipients:[{id:recipientKind==='group'?'group-7':'person-7',display_name:recipientKind==='group'?'Editors':'Ada Lovelace',kind:recipientKind}]};
   if(action==='sharing_invite')return{profile_id:'test',auth_generation:3,accepted:true};
   return undefined;
  }});
  await h.ctrl.enter();await h.ctrl.handle({type:'set-inventory',inventory:'by-me'});await h.ctrl.handle({type:'new-share'});await h.ctrl.handle({type:'choose-method',method:'people'});
  h.input('space','space',true);await settle();await h.ctrl.handle({type:'select-item',itemId:'/Folder'});await h.ctrl.handle({type:'use-item'});
  h.input('recipient-query','ada');await new Promise(resolve=>setTimeout(resolve,380));
  await h.ctrl.handle({type:'choose-recipient',recipientId:`${recipientKind}:${recipientKind==='group'?'group-7':'person-7'}`});
  h.input('role','view',true);await h.ctrl.handle({type:'save-access'});
  const call=h.calls.find(c=>c.action==='sharing_invite');assert.ok(call,`${recipientKind} invitation should be sent after review`);
  assert.equal(call.args.recipient_kind,recipientKind);assert.equal(call.args.recipient_id,recipientKind==='group'?'group-7':'person-7');assert.equal(call.args.role_id,'view');assert.equal(call.args.expected_item_id,'resource');
  assert.match(h.ctrl.render(),/Sharing change saved/);
 }
});

test('public-link creation sends the chosen link access and name after the item is selected',async()=>{
 const h=setup({rpc:async action=>action==='sharing_link_create'?{profile_id:'test',auth_generation:3,accepted:true}:undefined});await h.ctrl.enter();await h.ctrl.handle({type:'set-inventory',inventory:'by-me'});await h.ctrl.handle({type:'new-share'});await h.ctrl.handle({type:'choose-method',method:'links'});
 h.input('space','space',true);await settle();await h.ctrl.handle({type:'select-item',itemId:'/Folder'});await h.ctrl.handle({type:'use-item'});
 h.input('role','view',true);h.input('link-name','Project handoff');await h.ctrl.handle({type:'save-access'});
 const call=h.calls.find(c=>c.action==='sharing_link_create');assert.ok(call);assert.equal(call.args.link_type,'view');assert.equal(call.args.display_name,'Project handoff');assert.equal(call.args.expected_item_id,'resource');assert.equal(call.args.path,'/Folder');assert.equal('recipient_id'in call.args,false);
 assert.equal('password' in call.args,false);
 assert.equal(h.copied.length,0);assert.match(h.ctrl.render(),/Sharing change saved/);
});

test('required public-link password stays outside rendered HTML and is consumed once after create',async()=>{
 const h=setup({rpc:async(action,args)=>{
  if(action==='sharing_capabilities')return{profile_id:'test',auth_generation:3,capabilities:{files_sharing_enabled:true,groups_enabled:false,public_links_enabled:true,public_link_creation_supported:true,public_password_required_for:['view']},guest_invitations:true};
  if(action==='sharing_link_create')return{profile_id:'test',auth_generation:3,accepted:true};
 }});
 await choose(h,'links');h.input('role','view',true);
 let html=h.ctrl.render();assert.match(html,/Password \(required\)/);assert.match(html,/id="sharing-password"[^>]*type="password"[^>]*autocomplete="new-password"[^>]*maxlength="72"[^>]*required/);assert.match(html,/data-sharing-action="save-access" disabled/);
 const secret='synth-only-password';h.input('password',secret);html=h.ctrl.render();assert.doesNotMatch(html,new RegExp(secret));assert.equal(h.passwordValue(),secret);
 await h.ctrl.handle({type:'save-access'});const call=h.calls.find(v=>v.action==='sharing_link_create');assert.equal(call.args.password,secret);assert.doesNotMatch(h.ctrl.render(),new RegExp(secret));assert.equal(h.passwordValue(),'');
});

test('unknown public-link password policy blocks link creation at the capability and action layers',async()=>{
 const h=setup({rpc:async action=>action==='sharing_capabilities'?{profile_id:'test',auth_generation:3,capabilities:{files_sharing_enabled:true,groups_enabled:false,public_links_enabled:true,public_link_creation_supported:true,public_password_required_for:null},guest_invitations:true}:undefined});
 await h.ctrl.enter();await h.ctrl.handle({type:'set-inventory',inventory:'by-me'});await h.ctrl.handle({type:'new-share'});
 let html=h.ctrl.render();assert.match(html,/server password requirements for links are unknown/i);assert.match(html,/data-sharing-method="links"[^>]*disabled/);
 const before=h.calls.length;await h.ctrl.handle({type:'choose-method',method:'links'});
 assert.equal(h.calls.length,before);assert.doesNotMatch(h.ctrl.render(),/id="sharing-password"/);
 assert.equal(h.calls.some(call=>call.action==='sharing_link_create'),false);
});

test('server-echoed password errors are redacted and cannot trigger a second automatic submission',async()=>{
 const h=setup({rpc:async(action,args)=>{
  if(action==='sharing_capabilities')return{profile_id:'test',auth_generation:3,capabilities:{files_sharing_enabled:true,groups_enabled:false,public_links_enabled:true,public_link_creation_supported:true,public_password_required_for:['view']},guest_invitations:true};
  if(action==='sharing_link_create')throw new Error(`rejected secret ${args.password}`);
 }});
 await choose(h,'links');h.input('role','view',true);const secret='do-not-render-this-secret';h.input('password',secret);
 await h.ctrl.handle({type:'save-access'});await h.ctrl.handle({type:'save-access'});
 assert.equal(h.calls.filter(v=>v.action==='sharing_link_create').length,1);assert.doesNotMatch(h.ctrl.render(),new RegExp(secret));assert.match(h.ctrl.render(),/\[redacted\]/);assert.equal(h.passwordValue(),'');
});

test('link password draft clears on access-type, method, item, cancel and account changes',async()=>{
 const h=setup({rpc:async action=>action==='sharing_capabilities'?{profile_id:'test',auth_generation:3,capabilities:{files_sharing_enabled:true,groups_enabled:false,public_links_enabled:true,public_link_creation_supported:true,public_password_required_for:['view']},guest_invitations:true}:undefined});
 await choose(h,'links');h.input('role','view',true);h.input('password','type-change-secret');h.input('role','edit',true);assert.equal(h.passwordValue(),'');
 h.input('role','view',true);h.input('password','method-change-secret');await h.ctrl.handle({type:'choose-method',method:'people'});assert.equal(h.passwordValue(),'');
 await h.ctrl.handle({type:'choose-method',method:'links'});h.input('space','space',true);await settle();await h.ctrl.handle({type:'select-item',itemId:'/Folder'});await h.ctrl.handle({type:'use-item'});h.input('role','view',true);h.input('password','item-change-secret');await h.ctrl.handle({type:'change-item'});assert.equal(h.passwordValue(),'');
 await h.ctrl.handle({type:'choose-item'});h.input('space','space',true);await settle();await h.ctrl.handle({type:'select-item',itemId:'/Folder'});await h.ctrl.handle({type:'use-item'});h.input('role','view',true);h.input('password','cancel-secret');await h.ctrl.handle({type:'cancel'});assert.equal(h.passwordValue(),'');
 await choose(h,'links');h.input('role','view',true);h.input('password','account-secret');h.setContext({...h.context(),profileId:'another',accountEpoch:2});h.ctrl.render();assert.equal(h.passwordValue(),'');
});

test('auth-generation rotation clears an active draft and explains why the flow stopped',async()=>{
 const h=setup();await choose(h,'links');h.input('role','view',true);h.input('password','generation-secret');
 assert.doesNotMatch(h.ctrl.render(),/account connection changed/i);
 h.setContext({...h.context(),generation:5});const html=h.ctrl.render();
 assert.equal(h.passwordValue(),'');assert.match(html,/The account connection changed\. Review sharing again\./);
});
