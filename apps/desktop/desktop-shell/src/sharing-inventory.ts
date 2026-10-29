import type { SharingInventory, SharingRow } from './sharing-workspace';
export type OwnedInventoryBinding = { ocsId: string; resourceId: string; inventory: 'by-me' | 'public-links' };
export type InventorySnapshot = { rows: SharingRow[]; urls: Map<string,string>; owned: Map<string,OwnedInventoryBinding> };
const object = (v: unknown): Record<string,unknown> => { if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('The sharing list could not be confirmed.'); return v as Record<string,unknown>; };
const value = (v: unknown): string | null => { if (v == null) return null; if (typeof v !== 'string' || v.length > 16384 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(v)) throw new Error('The sharing list contains invalid metadata.'); return v || null; };
const required = (v: unknown): string => { const s=value(v); if(!s)throw new Error('The sharing list contains an invalid identity.');return s; };
const name = (v:string) => v.split('/').filter(Boolean).at(-1) || 'Shared item';
function access(bits: unknown): string | null {
 if(bits==null)return null;
 if(!Number.isSafeInteger(bits)||(bits as number)<0)throw new Error('Invalid sharing permissions.');
 const n=bits as number;
 if(n>31)return 'Custom access';
 if(n===0)return 'No access';
 if(n===1)return 'Can view';
 if(n===4)return 'Can upload only';
 return [[1,'View'],[2,'Edit'],[4,'Upload'],[8,'Delete'],[16,'Share']].filter(([bit])=>!!(n & Number(bit))).map(([,label])=>label).join(' · ');
}
function expiration(v:unknown):string|null{
 const raw=value(v);if(!raw)return null;
 if(/^\d{4}-\d{2}-\d{2}$/.test(raw))return raw+'T00:00:00Z';
 if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(raw))return raw.replace(' ','T')+'Z';
 return raw;
}
function serverKey(value: unknown): string {
 const url=new URL(required(value));
 if(!['https:','http:'].includes(url.protocol)||url.username||url.password||url.search||url.hash)throw new Error('Invalid sharing server identity.');
 return url.origin+(url.pathname.replace(/\/+$/,'')||'/');
}
export function parseSharingInventory(reply:unknown, expected:{profileId:string;generation:number;inventory:SharingInventory;server:string}):InventorySnapshot{
 const r=object(reply),snapshot=object(r.snapshot),scope=object(snapshot.scope);
 if(r.profile_id!==expected.profileId||r.auth_generation!==expected.generation||r.inventory!==expected.inventory||r.read_only!==true||scope.account_id!==expected.profileId||serverKey(scope.server_url)!==serverKey(expected.server)||scope.response_complete!==true||!Number.isSafeInteger(scope.token_generation)||Number(scope.token_generation)<1)throw new Error('This sharing list no longer matches the selected account. Refresh it.');
 if(!Array.isArray(snapshot.items)||snapshot.items.length>100000)throw new Error('The sharing list is too large or incomplete.');
 const rows:SharingRow[]=[],urls=new Map<string,string>(),owned=new Map<string,OwnedInventoryBinding>(),seen=new Set<string>();
 for(const raw of snapshot.items){const item=object(raw);
  if(expected.inventory==='with-me'){
   const id='incoming:'+required(item.shared_item_id),remote=object(item.remote_item);
   required(remote.id);if(typeof item.is_folder!=='boolean')throw new Error('Invalid incoming item.');
   const creator=remote.created_by==null?null:object(remote.created_by);
   const owner=creator?(value(creator.user_display_name)||value(creator.group_display_name)||value(creator.user_id)||value(creator.group_id)):null;
   rows.push({id,itemName:required(item.name),location:'Shared with this account',sharedWith:owner||'Shared with this account',role:null,expiresAt:null,canEdit:false,canRemove:false,canCopyLink:false,accessSource:'unknown'});
  }else{
   const kind=object(item.kind).kind;
   if(typeof kind!=='string')throw new Error('Invalid share kind.');
   if((expected.inventory==='public-links')!==(kind==='public_link'))throw new Error('The server returned a share in the wrong list.');
   const ocsId=required(item.ocs_share_id),id='ocs:'+ocsId;
   const path=value(item.path)||value(item.file_target),label=value(item.label);
   const resourceId=value(item.resource_id),known=['user','group','public_link'].includes(kind);
   const publicUrl=value(item.public_url);
   if(publicUrl&&kind==='public_link'){const url=new URL(publicUrl);if(!['https:','http:'].includes(url.protocol)||url.username||url.password)throw new Error('The public link URL could not be confirmed.');urls.set(id,url.href);}
   const recipient=kind==='public_link'?(label||'Anyone with the link'):(value(item.recipient_display_name)||value(item.recipient_additional_info)||value(item.recipient_id)||'Recipient unavailable');
   const canRemove=!!resourceId&&known;
   rows.push({id,itemName:path?name(path):'Shared item (name unavailable)',location:[value(item.space_alias),path].filter(Boolean).join(' · ')||'Location unavailable',sharedWith:recipient,role:access(item.permissions),expiresAt:expiration(item.expires_at),canEdit:canRemove&&(kind==='public_link'||!!value(item.recipient_id)),canRemove,canCopyLink:urls.has(id),accessSource:'direct'});
   if(canRemove)owned.set(id,{ocsId,resourceId:resourceId!,inventory:expected.inventory});
  }
  const last=rows[rows.length-1];if(seen.has(last.id))throw new Error('The sharing list contains duplicate identities.');seen.add(last.id);
 }
 return {rows,urls,owned};
}

export type OwnedEditSettings = {
 binding: OwnedInventoryBinding;
 baseline: Record<string,unknown>;
 row: SharingRow;
 kind: 'user_or_group' | 'public_link';
 fields: {access:boolean;expiration:boolean;name:boolean};
 roles: {id:string;name:string}[];
 permissions: Map<string,number>;
 roleId: string;
 linkName: string;
};
export function parseOwnedEditSettings(reply:unknown, expected:{profileId:string;generation:number;inventory:'by-me'|'public-links';server:string;binding:OwnedInventoryBinding}):OwnedEditSettings {
 const r=object(reply), settings=object(r.settings), baseline=object(settings.baseline), share=object(settings.share);
 const parsed=parseSharingInventory({...r,snapshot:{scope:settings.scope,items:[share]}},expected);
 const row=parsed.rows[0],binding=parsed.owned.get(row.id);
 if(!binding || binding.ocsId!==expected.binding.ocsId || binding.resourceId!==expected.binding.resourceId || binding.inventory!==expected.binding.inventory || settings.category!==(expected.inventory==='by-me'?'shared_by_me':'public_links')) throw new Error('This share changed. Refresh its settings.');
 const keys=['ocs_share_id','resource_id','space_id','owner_id','kind','recipient_id','path','file_target','item_type','permissions','expires_at','label'];
 if(keys.some(key=>JSON.stringify(baseline[key]??null)!==JSON.stringify(share[key]??null)) || baseline.resource_id!==binding.resourceId)throw new Error('The share settings could not be confirmed.');
 if(!Array.isArray(settings.editable_fields)||settings.editable_fields.some(v=>!['access','expiration','name'].includes(String(v))))throw new Error('Unsupported share settings.');
 if(!Array.isArray(settings.access_choices)||settings.access_choices.length>32)throw new Error('Unsupported share permissions.');
 const permissions=new Map<string,number>();
 const roles=settings.access_choices.map(raw=>{const v=object(raw),id=required(v.id),label=required(v.name);if(permissions.has(id)||!Number.isSafeInteger(v.permissions)||Number(v.permissions)<0||Number(v.permissions)>31)throw new Error('Invalid share permission.');permissions.set(id,Number(v.permissions));return{id,name:label};});
 const kind=object(share.kind).kind==='public_link'?'public_link':'user_or_group';
 const fields={access:settings.editable_fields.includes('access'),expiration:settings.editable_fields.includes('expiration'),name:settings.editable_fields.includes('name')};
 if(kind!=='public_link'&&fields.name)throw new Error('Invalid share name setting.');
 let roleId=roles.find(role=>permissions.get(role.id)===share.permissions)?.id||'';
 if(!roleId&&fields.access){roleId='__keep_current_access__';roles.unshift({id:roleId,name:'Current access (unchanged)'});}
 return{binding,baseline:structuredClone(baseline),row,kind,fields,roles,permissions,roleId,linkName:value(share.label)||''};
}
