import { parseSharingInventory, parseOwnedEditSettings, type OwnedEditSettings, type InventorySnapshot } from './sharing-inventory';
import { renderSharingWorkspace, sharingActionFromDataset, type SharingWorkspaceProps, type SharingInventory, type SharingSection, type SharingMode, type SharingMethodCapability, type SharingRow, type SharingRole, type SharingItem, type SharingBrowserEntry, type SharingRecipientOption, type SharingAction } from './sharing-workspace';
import { guestExpiryInput, guestExpiryValue } from './guest-sharing';
export type SharingContext = {
    server: string;
    profileId: string;
    accountEpoch: number;
    generation: number;
    connected: boolean;
    spaces: {
        id: string;
        name: string;
        personal?: boolean;
        encrypted?: boolean;
    }[];
};
type Dependencies = {
    context: () => SharingContext | null;
    rpc: (action: string, args: Record<string, unknown>) => Promise<unknown>;
    render: () => void;
    confirm: (message: string) => Promise<boolean>;
    copy: (value: string) => Promise<void>;
    focus?: (target: 'heading' | 'new-share') => void;
};
type Capabilities = {
    files_sharing_enabled: boolean;
    groups_enabled: boolean;
    public_links_enabled: boolean;
    public_link_creation_supported?: boolean;
    public_password_enforced?: boolean | null;
    public_password_required_for?: string[] | null;
    public_expiration_enabled?: boolean | null;
    public_expiration_enforced?: boolean | null;
};
type Data = {
    item_id: string;
    roles: SharingRole[];
    rows: SharingRow[];
    linkTypes: string[];
    urls: Map<string, string>;
    roleIds: Map<string, string | null>;
};
const initialCapability = (): SharingMethodCapability => ({ server: 'unknown', adapter: 'implemented', accountList: false, itemList: true, create: false, edit: false, remove: false, copyLink: false, expiration: false, password: false });
const errorText = (e: unknown) => e instanceof Error ? e.message : 'Could not complete sharing.';
const text = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= 16384;
const parent = (p: string) => p.slice(0, p.lastIndexOf('/')) || '/';
const basename = (p: string) => p.split('/').filter(Boolean).at(-1) || 'Root';
const linkLabels: Record<string, string> = { view: 'Can view', edit: 'Can edit', blocksDownload: 'Can view without downloading', upload: 'Can upload and view', createOnly: 'Can upload only' };
const emptyInventory = (): InventorySnapshot => ({ rows: [], urls: new Map(), owned: new Map() });
export class SharingController {
    private inventory: SharingInventory = 'with-me';
    private inventoryData = emptyInventory();
    private inventorySequence = 0;
    private inventoryLoaded = false;
    private inventoryLoading = false;
    private inventoryError = '';
    private selectedInventoryId = '';
    private ownedEdit: OwnedEditSettings | null = null;

    private scope = '';
    private sequence = 0;
    private searchSequence = 0;
    private caps: Capabilities | null = null;
    private guestSupported = false;
    private capsLoading = false;
    private capsError = '';
    private busy = false;
    private section: SharingSection = 'guests';
    private mode: SharingMode = 'list';
    private status: SharingWorkspaceProps['list']['status'] = 'idle';
    private spaceId = '';
    private path = '/';
    private selectedItem: SharingItem | null = null;
    private entries: SharingBrowserEntry[] = [];
    private selectedEntryId = '';
    private itemData: Data | null = null;
    private selectedShareId = '';
    private draft = { recipient: '', role: '', expiry: '', linkName: '', query: '', recipientId: '', password: '' };
    private draftBaseline = '';
    private recipientResults: SharingRecipientOption[] = [];
    private recipientStatus: 'idle' | 'loading' | 'ready' | 'error' = 'idle';
    private message = '';
    private notice = '';
    private unknown = false;
    private listQuery = '';
    private createdId = '';
    private searchTimer: ReturnType<typeof setTimeout> | null = null;
    constructor(private readonly deps: Dependencies) { }
    private key(c: SharingContext) { return JSON.stringify([c.profileId, c.accountEpoch, c.generation, c.server]); }
    private current(key: string, seq?: number) { const c = this.deps.context(); return !!c && this.scope === key && this.key(c) === key && (seq === undefined || seq === this.sequence); }
    private sync() { const c = this.deps.context(); const key = c ? this.key(c) : ''; if (key !== this.scope) {
        const interruptedFlow = !!this.scope && this.mode !== 'list';
        this.leave();
        this.scope = key;
        if (interruptedFlow) this.notice = 'The account connection changed. Review sharing again.';
    } return c; }
    leave() {
    this.sequence++; this.searchSequence++; this.inventorySequence++;
    if (this.searchTimer) clearTimeout(this.searchTimer);
    this.searchTimer = null; this.scope = ''; this.caps = null; this.capsError = ''; this.capsLoading = false; this.busy = false;
    this.mode = 'list'; this.status = 'idle'; this.spaceId = ''; this.path = '/'; this.selectedItem = null; this.selectedEntryId = ''; this.entries = [];
    this.itemData = null; this.selectedShareId = ''; this.selectedInventoryId = ''; this.resetDraft(); this.message = ''; this.notice = ''; this.unknown = false;
    this.listQuery = ''; this.createdId = ''; this.inventoryData = emptyInventory(); this.inventoryLoaded = false; this.inventoryLoading = false; this.inventoryError = '';
}
    private draftFingerprint() { const { password: _password, ...shareFields } = this.draft; return JSON.stringify(shareFields); }
    private resetDraft() { this.ownedEdit = null; this.draft = { recipient: '', role: '', expiry: '', linkName: '', query: '', recipientId: '', password: '' }; this.recipientResults = []; this.recipientStatus = 'idle'; this.draftBaseline = this.draftFingerprint(); }
    private passwordRequiredFor(linkType: string): boolean | null {
        if (!this.caps) return null;
        const policy = this.caps.public_password_required_for;
        if (Array.isArray(policy)) {
            if (policy.some(type => typeof type !== 'string' || !Object.hasOwn(linkLabels, type))) return null;
            return !!linkType && policy.includes(linkType);
        }
        if (policy === null) return null;
        if (this.caps.public_password_enforced === true) return true;
        if (this.caps.public_password_enforced === false) return false;
        return null;
    }
    async enter() {
    const c = this.sync();
    if (!c?.connected || this.capsLoading) return;
    if (!this.caps) await this.loadCapabilities();
    if (!this.inventoryLoaded && !this.inventoryLoading && !this.inventoryError) await this.refreshInventory();
}
    private async rpc(action: string, args: Record<string, unknown>, key: string): Promise<Record<string, unknown>> {
        const c = this.deps.context();
        if (!c || this.key(c) !== key || !c.connected)
            throw new Error('Connect this account before managing sharing.');
        const result = await this.deps.rpc(action, { ...args, profile_id: c.profileId, expected_auth_generation: c.generation });
        if (!this.current(key))
            throw new Error('The account changed. Review sharing again.');
        const r = result as Record<string, unknown> | null;
        if (!r || r.profile_id !== c.profileId || r.auth_generation !== c.generation)
            throw new Error('The sharing response did not match this account. Refresh before continuing.');
        return r;
    }
    private async refreshInventory(force = false) {
        const c = this.sync();
        if (!c?.connected || (this.inventoryLoading && !force)) return;
        const key = this.scope, inventory = this.inventory, seq = ++this.inventorySequence, operation = this.sequence;
        this.inventoryLoading = true; this.inventoryError = ''; this.deps.render();
        const current = () => this.current(key) && this.inventory === inventory && this.inventorySequence === seq;
        try {
            const result = await this.rpc('sharing_inventory', { inventory }, key);
            if (!current()) return;
            this.inventoryData = parseSharingInventory(result, { profileId: c.profileId, generation: c.generation, inventory, server: c.server });
            this.inventoryLoaded = true;
            if (this.sequence === operation) this.unknown = false;
        } catch (error) {
            if (current()) this.inventoryError = errorText(error);
        } finally {
            if (current()) { this.inventoryLoading = false; this.deps.render(); }
        }
    }
    private async revokeInventory(id: string) {
        const c = this.sync(), binding = this.inventoryData.owned.get(id), row = this.inventoryData.rows.find(row => row.id === id);
        if (!c?.connected || !binding || !row?.canRemove || this.inventory === 'with-me' || this.unknown || !this.inventoryLoaded || this.inventoryLoading || !!this.inventoryError) return;
        const key = this.scope, seq = ++this.sequence, inventory = this.inventory;
        this.busy = true; this.message = ''; this.deps.render();
        try {
            const allowed = await this.deps.confirm('Remove ' + row.sharedWith + "'s access to " + row.itemName + '? This does not delete the item or remove other grants or downloaded copies.');
            if (!allowed || !this.current(key, seq) || this.inventory !== inventory) return;
            const current = this.inventoryData.owned.get(id);
            if (!current || current.ocsId !== binding.ocsId || current.resourceId !== binding.resourceId || current.inventory !== binding.inventory) throw new Error('This share changed. Refresh before removing access.');
            const result = await this.rpc('sharing_owned_revoke', { inventory: binding.inventory, permission_id: binding.ocsId, expected_resource_id: binding.resourceId }, key);
            if (!this.current(key, seq)) return;
            if (result.accepted !== true) throw new Error('Could not confirm the result. Refresh before trying again.');
            this.notice = 'Access removed.'; this.selectedInventoryId = ''; this.mode = 'list'; this.busy = false;
            await this.refreshInventory(true);
        } catch (error) {
            if (this.current(key, seq)) { this.inventoryError = errorText(error); this.unknown = !/denied|unavailable|Reconnect|no longer|changed|Refresh this/i.test(this.inventoryError); }
        } finally {
            if (this.current(key, seq)) { this.busy = false; this.deps.render(); }
        }
    }
    private async editInventory(id: string, force = false) {
        const c=this.sync(),binding=this.inventoryData.owned.get(id),row=this.inventoryData.rows.find(row=>row.id===id);
        if(!c?.connected || !binding || !row?.canEdit || this.inventory==='with-me' || (!force && (this.unknown || !this.inventoryLoaded || this.inventoryLoading || !!this.inventoryError))) return;
        const key=this.scope,seq=++this.sequence,inventory=binding.inventory;
        this.selectedInventoryId=id;this.mode='details';this.busy=true;this.message='';this.notice='Loading share settings…';this.deps.render();
        try {
            const result=await this.rpc('sharing_owned_settings',{inventory,permission_id:binding.ocsId,expected_resource_id:binding.resourceId},key);
            if(!this.current(key,seq)||this.inventory!==inventory)return;
            const settings=parseOwnedEditSettings(result,{profileId:c.profileId,generation:c.generation,inventory,server:c.server,binding});
            this.resetDraft();this.ownedEdit=settings;
            this.inventoryData.rows=this.inventoryData.rows.map(row=>row.id===id?settings.row:row);
            this.selectedItem={id:binding.resourceId,name:settings.row.itemName,location:settings.row.location,path:'/',isFolder:false,shareable:true};
            this.section=settings.kind==='public_link'?'links':'people';
            this.draft.role=settings.roleId;this.draft.expiry=guestExpiryInput(settings.row.expiresAt);this.draft.linkName=settings.linkName;
            this.draftBaseline=this.draftFingerprint();this.unknown=false;this.notice='';this.mode='edit';
            if(!Object.values(settings.fields).some(Boolean))this.message='The server does not allow changing settings for this share.';
        } catch(error) {if(this.current(key,seq)){this.notice='';this.inventoryError=errorText(error);}}
        finally {if(this.current(key,seq)){this.busy=false;this.deps.render();this.deps.focus?.('heading');}}
    }
    private async saveInventoryEdit() {
        const c=this.sync(),edit=this.ownedEdit;
        if(!c?.connected || !edit || this.unknown || this.mode!=='edit')return;
        const binding=this.inventoryData.owned.get(this.selectedInventoryId);
        if(!binding || binding.ocsId!==edit.binding.ocsId || binding.resourceId!==edit.binding.resourceId || binding.inventory!==edit.binding.inventory)return;
        const baseline=JSON.parse(this.draftBaseline) as Record<string,string>;
        const update:Record<string,unknown>={kind:edit.kind,expiration:{action:'keep'}};
        let changed=false;
        if(this.draft.role!==baseline.role){
            if(!edit.fields.access||!edit.permissions.has(this.draft.role)){this.message='Choose one of the supported access levels.';this.deps.render();return;}
            update.permissions=edit.permissions.get(this.draft.role);changed=true;
        }
        if(this.draft.expiry!==baseline.expiry){
            const expiry=this.draft.expiry?guestExpiryValue(this.draft.expiry):null;
            if(!edit.fields.expiration||(this.draft.expiry&&(!expiry||Date.parse(expiry)<=Date.now()))){this.message='Choose a future expiration or leave it empty for no expiration.';this.deps.render();return;}
            update.expiration=expiry?{action:'set',value:expiry}:{action:'clear'};changed=true;
        }
        if(this.draft.linkName!==baseline.linkName){
            if(!edit.fields.name||edit.kind!=='public_link'||!this.draft.linkName.trim()){this.message='Enter a name for this link.';this.deps.render();return;}
            update.name=this.draft.linkName.trim();changed=true;
        }
        if(!changed){this.notice='No changes to save.';this.mode='list';this.resetDraft();this.deps.render();return;}
        const key=this.scope,seq=++this.sequence;
        this.busy=true;this.message='';this.deps.render();
        try {
            const result=await this.rpc('sharing_owned_update',{inventory:binding.inventory,permission_id:binding.ocsId,expected_resource_id:binding.resourceId,baseline:edit.baseline,update},key);
            if(!this.current(key,seq))return;
            if(result.accepted!==true)throw new Error('Could not confirm the sharing result. Refresh before trying again.');
            this.mode='list';this.resetDraft();this.selectedInventoryId='';this.selectedItem=null;this.notice='Sharing settings saved.';this.busy=false;
            await this.refreshInventory(true);
        } catch(error){if(this.current(key,seq)){this.message=errorText(error);this.unknown=true;}}
        finally {if(this.current(key,seq)){this.busy=false;this.deps.render();}}
    }
    private async loadCapabilities() {
        const c = this.sync();
        if (!c)
            return;
        const key = this.scope, seq = ++this.sequence;
        this.capsLoading = true;
        this.capsError = '';
        this.deps.render();
        try {
            const r = await this.rpc('sharing_capabilities', {}, key);
            if (!this.current(key, seq))
                return;
            const caps = r.capabilities as Capabilities;
            if (!caps || [caps.files_sharing_enabled, caps.groups_enabled, caps.public_links_enabled].some(v => typeof v !== 'boolean') || typeof r.guest_invitations !== 'boolean')
                throw new Error('Server sharing capabilities could not be confirmed.');
            this.caps = caps;
            this.guestSupported = r.guest_invitations;
        }
        catch (e) {
            if (this.current(key, seq))
                this.capsError = errorText(e);
        }
        finally {
            if (this.current(key, seq)) {
                this.capsLoading = false;
                this.deps.render();
            }
        }
    }
    private capability(section: SharingSection): SharingMethodCapability {
        const cap = initialCapability();
        if (!this.caps)
            return cap;
        const enabled = this.caps.files_sharing_enabled && (section === 'guests' ? this.guestSupported : section === 'links' ? this.caps.public_links_enabled : true);
        const passwordPolicyKnown = section === 'links' && this.passwordRequiredFor('') !== null;
        const passwordBlocked = section === 'links' && (this.caps.public_link_creation_supported !== true || !passwordPolicyKnown);
        return { ...cap, server: enabled ? 'supported' : 'unsupported', create: enabled && !passwordBlocked, createUnavailableMessage: section === 'links' && this.caps.public_link_creation_supported === true && !passwordPolicyKnown ? 'The server password requirements for links are unknown. Refresh sharing information before creating a link.' : undefined, edit: enabled && section !== 'links', remove: enabled, copyLink: enabled && section === 'links', expiration: section === 'guests' || (section === 'people' && this.mode !== 'edit') || (section === 'links' && this.caps.public_expiration_enabled !== false), password: section === 'links' && this.mode !== 'edit' && passwordPolicyKnown };
    }
    render(): string {
    const c = this.sync();
    if (c?.connected && this.mode === 'list' && !this.capsLoading && !this.capsError && !this.inventoryLoading && !this.inventoryError && (!this.caps || !this.inventoryLoaded)) queueMicrotask(() => void this.enter());
    const creation = !['list', 'details'].includes(this.mode);
    const inventoryMutable = this.inventoryLoaded && !this.inventoryLoading && !this.inventoryError && !this.unknown;
    const methodCap = this.ownedEdit ? { ...this.capability(this.section), server: 'supported' as const, edit: true, expiration: this.ownedEdit.fields.expiration } : this.capability(this.section);
    const cap = creation ? methodCap : { ...initialCapability(), server: (this.caps || this.inventoryLoaded) ? 'supported' as const : 'unknown' as const, accountList: true, itemList: false, edit: this.inventory !== 'with-me' && inventoryMutable, remove: this.inventory !== 'with-me' && inventoryMutable, copyLink: this.inventory === 'public-links' };
    const rows = this.inventoryData.rows.filter(row => !this.listQuery || (row.itemName + ' ' + row.location + ' ' + row.sharedWith).toLowerCase().includes(this.listQuery.toLowerCase()));
    const roles = this.ownedEdit?.roles || (this.section === 'links' ? (this.itemData?.linkTypes || []).map(id => ({ id, name: linkLabels[id] || id })) : this.itemData?.roles || []);
    const listStatus = creation ? this.status : this.capsLoading ? 'loading' : (!this.inventoryLoaded && this.capsError) || this.inventoryError || (this.unknown && this.mode === 'list') ? 'error' : this.inventoryLoading && !this.inventoryLoaded ? 'loading' : this.inventoryLoaded ? 'ready' : 'idle';
    const props: SharingWorkspaceProps = {
        inventory: this.inventory, creationMethod: this.mode === 'choose-method' || this.mode === 'list' || this.mode === 'details' ? null : this.section,
        section: this.section, mode: this.mode, capability: cap,
        methodCapabilities: { people: this.capability('people'), links: this.capability('links'), guests: this.capability('guests') },
        canStartShare: ['people','links','guests'].some(method => this.capability(method as SharingSection).create),
        list: { status: listStatus, rows, coverage: { scope: 'account', complete: this.inventoryLoaded && !this.inventoryError && !this.inventoryLoading, nextPageAvailable: false }, refreshing: this.inventoryLoading && this.inventoryLoaded, message: this.inventoryError || this.capsError || (this.unknown ? 'Could not confirm the previous change. Refresh the sharing list before trying again.' : this.message) },
        connected: c?.connected === true, busy: this.busy || this.capsLoading, query: this.listQuery,
        spaces: (c?.spaces || []).map(s => ({ id: s.id, label: s.personal ? 'Personal' : s.name, encrypted: s.encrypted === true })),
        spaceId: this.spaceId, currentPath: this.path, entries: this.entries, selectedEntryId: this.selectedEntryId,
        selectedItem: this.selectedItem, selectedShare: this.inventoryData.rows.find(row => row.id === this.selectedInventoryId) || this.itemData?.rows.find(row => row.id === this.selectedShareId) || null,
        editableFields: this.ownedEdit?.fields,
        roles, roleId: this.draft.role, recipient: this.draft.recipient, expiry: this.draft.expiry, linkName: this.draft.linkName,
        recipientQuery: this.draft.query, recipientSelectedId: this.draft.recipientId, recipientResults: this.recipientResults, recipientSearchStatus: this.recipientStatus,
        passwordRequired: this.section === 'links' && !this.ownedEdit && this.passwordRequiredFor(this.draft.role) === true,
        passwordPolicyKnown: this.section !== 'links' || !!this.ownedEdit || this.passwordRequiredFor(this.draft.role) !== null,
        passwordPresent: this.draft.password.length > 0,
        passwordLengthValid: new TextEncoder().encode(this.draft.password).length <= 72,
        expirationRequired: this.section === 'links' && this.caps?.public_expiration_enforced === true,
        outcomeUnknown: this.unknown, validationMessage: this.message, notice: this.notice, createdShareId: this.createdId
    };
    if (creation && !this.ownedEdit && this.section === 'links' && this.caps && this.caps.public_link_creation_supported !== true) props.notice = 'This server requires link settings Raiun cannot currently provide.';
    return renderSharingWorkspace(props);
}
    bind(root: HTMLElement) {
        const key = this.scope;
        const tabs = [...root.querySelectorAll<HTMLButtonElement>('[data-sharing-inventory]')];
        tabs.forEach((tab, index) => tab.addEventListener('keydown', event => {
            if (!this.current(key) || !['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
            event.preventDefault();
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
            tabs.forEach((button, i) => { button.tabIndex = i === next ? 0 : -1; });
            tabs[next]?.focus();
        }));
        root.querySelectorAll<HTMLElement>('[data-sharing-action]').forEach(el => el.addEventListener('click', () => { if (!this.current(key))
            return; const a = sharingActionFromDataset(el.dataset); if (a)
            void this.handle(a); }));
        root.querySelectorAll<HTMLInputElement | HTMLSelectElement>('[data-sharing-field]').forEach(el => {
            if (el.dataset.sharingField === 'password') el.value = this.draft.password;
            el.addEventListener(el instanceof HTMLSelectElement ? 'change' : 'input', () => {
            if (!this.current(key) || this.busy)
                return;
            const field = el.dataset.sharingField, value = el.value;
            if (field === 'space') {
                this.spaceId = value;
                this.selectedItem = null;
                this.selectedEntryId = '';
                this.itemData = null;
                void this.browse('/');
                return;
            }
            if (field === 'role' && this.section === 'links' && this.draft.role !== value)
                this.draft.password = '';
            if (field === 'role')
                this.draft.role = value;
            else if (field === 'expiry')
                this.draft.expiry = value;
            else if (field === 'recipient')
                this.draft.recipient = value;
            else if (field === 'link-name')
                this.draft.linkName = value;
            else if (field === 'password')
                this.draft.password = value;
            else if (field === 'recipient-query') {
                this.draft.query = value;
                this.draft.recipientId = '';
                this.searchSequence++;
                if (this.searchTimer)
                    clearTimeout(this.searchTimer);
                this.searchTimer = setTimeout(() => void this.searchRecipients(), 350);
            }
            else if (field === 'query')
                this.listQuery = value;
            this.message = '';
            this.deps.render();
            });
        });
    }
    private async browse(path: string) {
        const c = this.sync();
        if (!c)
            return;
        if (!c.spaces.some(s => s.id === this.spaceId && !s.encrypted)) {
            this.entries = [];
            this.selectedItem = null;
            this.selectedEntryId = '';
            this.status = 'idle';
            this.message = 'Choose an unencrypted location.';
            this.deps.render();
            return;
        }
        const key = this.scope, seq = ++this.sequence, spaceId = this.spaceId;
        this.path = path;
        this.entries = [];
        this.selectedEntryId = '';
        this.selectedItem = null;
        this.busy = true;
        this.status = 'loading';
        this.message = '';
        this.deps.render();
        try {
            const raw = await this.deps.rpc('list', { profile_id: c.profileId, space_id: spaceId, path });
            if (!this.current(key, seq))
                return;
            if (!Array.isArray(raw) || raw.length > 100000)
                throw new Error('The file listing could not be confirmed.');
            this.entries = raw.map((e: Record<string, unknown>) => { if (!text(e.path) || typeof e.directory !== 'boolean')
                throw new Error('Invalid file listing.'); return { id: e.path, name: basename(e.path), path: e.path, isFolder: e.directory, encrypted: e.encrypted === true, shareable: e.writable === true && e.encrypted !== true }; });
            this.status = 'ready';
        }
        catch (e) {
            if (this.current(key, seq)) {
                this.status = 'error';
                this.message = errorText(e);
            }
        }
        finally {
            if (this.current(key, seq)) {
                this.busy = false;
                this.deps.render();
            }
        }
    }
    private select(entry: SharingBrowserEntry) {
        const c = this.sync();
        if (!c || entry.encrypted || entry.shareable === false)
            return;
        const space = c.spaces.find(s => s.id === this.spaceId && !s.encrypted);
        if (!space)
            return;
        this.selectedEntryId = entry.id;
        this.selectedItem = { id: entry.id, name: entry.name, location: `${space.personal ? 'Personal' : space.name} / ${entry.path.replace(/^\//, '')}`, path: entry.path, isFolder: entry.isFolder };
        this.deps.render();
    }
    private async loadItem(forSettings: boolean) {
        const item = this.selectedItem;
        if (!item || !this.spaceId || !this.sync())
            return;
        const key = this.scope, seq = ++this.sequence, section = this.section, space = this.spaceId;
        this.busy = true;
        this.message = '';
        this.status = 'loading';
        this.deps.render();
        try {
            const r = await this.rpc(section === 'guests' ? 'guest_permissions' : 'sharing_permissions', { space_id: space, path: item.path }, key);
            if (!this.current(key, seq))
                return;
            const data = this.parseData(r, item, section);
            this.selectedItem = { ...item, id: data.item_id };
            this.itemData = data;
            this.unknown = false;
            this.status = 'ready';
            if (forSettings) {
                this.resetDraft();
                const role = section === 'links' ? data.linkTypes.find(id => id === 'view') : data.roles.find(r => /view|read|viewer/i.test(r.name))?.id;
                this.draft.role = role || '';
                this.draft.linkName = item.name;
                this.draftBaseline = this.draftFingerprint();
                this.mode = 'settings';
            }
            else
                this.mode = 'list';
        }
        catch (e) {
            if (this.current(key, seq)) {
                this.status = 'error';
                this.message = errorText(e);
            }
        }
        finally {
            if (this.current(key, seq)) {
                this.busy = false;
                this.deps.render();
                if (forSettings)
                    this.deps.focus?.('heading');
            }
        }
    }
    private parseData(r: Record<string, unknown>, item: SharingItem, section: SharingSection): Data {
        if (!text(r.item_id))
            throw new Error(r.available === false ? 'Guest invitations are unavailable for this item.' : 'The selected item could not be confirmed.');
        const payload = section === 'guests' ? r : r.permissions as Record<string, unknown>;
        if (!payload || !Array.isArray(payload.roles) || payload.roles.length > 64)
            throw new Error('Invalid sharing roles.');
        const roles: SharingRole[] = payload.roles.map((v: Record<string, unknown>) => { if (!text(v.id) || !text(v.name))
            throw new Error('Invalid sharing role.'); return { id: v.id, name: v.name }; });
        const rows: SharingRow[] = [], urls = new Map<string, string>(), roleIds = new Map<string, string | null>();
        const source = section === 'guests' ? payload.guests : section === 'people' ? payload.people_and_groups : payload.public_links;
        if (!Array.isArray(source) || source.length > 1000)
            throw new Error('Invalid sharing list.');
        for (const v of source) {
            const id = section === 'guests' ? v.id : v.permission_id;
            if (!text(id))
                throw new Error('Invalid share identifier.');
            const names = Array.isArray(v.roles) ? v.roles.map((id: string) => roles.find(r => r.id === id)?.name || 'Unknown access').join(', ') : section === 'links' ? linkLabels[v.link_type] || v.link_type : null;
            const recipient = section === 'guests' ? v.email : section === 'people' ? v.display_name || v.recipient_id : v.display_name || 'Anyone with this link';
            if (!text(recipient))
                throw new Error('Invalid sharing recipient.');
            if (v.expiration_date_time != null && (typeof v.expiration_date_time !== 'string' || !Number.isFinite(Date.parse(v.expiration_date_time))))
                throw new Error('Invalid expiration.');
            const row: SharingRow = { id, itemName: item.name, location: item.location, sharedWith: recipient, role: names, expiresAt: v.expiration_date_time ?? null, canEdit: section !== 'links' && v.inherited === false, canRemove: v.inherited === false, canCopyLink: section === 'links' && text(v.web_url), accessSource: v.inherited === false ? 'direct' : v.inherited === true ? 'inherited' : 'unknown' };
            if (row.canCopyLink) {
                const u = new URL(v.web_url);
                if (u.protocol !== 'https:' || u.username || u.password)
                    throw new Error('The share link URL could not be confirmed.');
                urls.set(id, u.href);
            }
            roleIds.set(id, Array.isArray(v.roles) && v.roles.length === 1 && roles.some(r => r.id === v.roles[0]) ? v.roles[0] : null);
            rows.push(row);
        }
        const linkTypes = section === 'links' && Array.isArray(r.link_types) ? r.link_types.filter((v): v is string => typeof v === 'string' && Object.hasOwn(linkLabels, v)) : [];
        return { item_id: r.item_id, roles, rows, linkTypes, urls, roleIds };
    }
    private async searchRecipients() {
        const query = this.draft.query.trim();
        if (this.section !== 'people' || query.length < 2) {
            this.recipientResults = [];
            this.recipientStatus = 'idle';
            this.deps.render();
            return;
        }
        const key = this.scope, seq = ++this.searchSequence;
        this.recipientStatus = 'loading';
        this.deps.render();
        try {
            const kinds = this.caps?.groups_enabled ? ['user', 'group'] : ['user'];
            const outcomes = await Promise.allSettled(kinds.map(kind => this.rpc('sharing_recipients', { query, recipient_kind: kind }, key)));
            const result = outcomes.filter((v): v is PromiseFulfilledResult<Record<string, unknown>> => v.status === 'fulfilled').map(v => v.value);
            if (!result.length)
                throw new Error('Directory search unavailable');
            const partial = outcomes.some(v => v.status === 'rejected');
            if (!this.current(key) || seq !== this.searchSequence)
                return;
            this.recipientResults = result.flatMap(r => { if (!Array.isArray(r.recipients) || r.recipients.length > 1000)
                throw new Error('Invalid recipient results.'); return r.recipients.map((v: Record<string, unknown>) => { if (!text(v.id) || !text(v.display_name) || (v.kind !== 'user' && v.kind !== 'group'))
                throw new Error('Invalid recipient.'); return { id: `${v.kind}:${v.id}`, label: v.display_name, kind: v.kind === 'group' ? 'group' as const : 'person' as const, secondary: typeof v.mail === 'string' ? v.mail : undefined }; }); });
            this.recipientStatus = 'ready';
            if (partial)
                this.message = 'Some directory results could not be loaded. The choices shown are a partial result; try searching again.';
        }
        catch {
            if (this.current(key) && seq === this.searchSequence)
                this.recipientStatus = 'error';
        }
        finally {
            if (this.current(key) && seq === this.searchSequence)
                this.deps.render();
        }
    }
    private dirty() { return (this.mode === 'settings' || this.mode === 'edit') && (this.draftFingerprint() !== this.draftBaseline || !!this.draft.password); }
    async handle(a: SharingAction): Promise<void> {
    const c = this.sync(); if (!c || this.busy || this.capsLoading) return;
    if (this.unknown && ['new-share','choose-item','change-item','set-section','set-inventory','choose-method'].includes(a.type)) {
        this.message = 'Refresh the sharing list to confirm the previous result before making another change.'; this.deps.render(); return;
    }
    if (a.type === 'set-inventory') {
        if (a.inventory === this.inventory && this.mode === 'list') return;
        const key = this.scope;
        const dirty = this.dirty();
        if (this.draft.password) { this.draft.password = ''; this.deps.render(); }
        if (dirty && !await this.deps.confirm('Discard the unsaved sharing changes?')) return;
        if (!this.current(key)) return;
        this.sequence++; this.searchSequence++; this.inventorySequence++;
        this.inventory = a.inventory; this.mode = 'list'; this.itemData = null; this.selectedItem = null; this.selectedInventoryId = ''; this.selectedShareId = '';
        this.resetDraft(); this.message = ''; this.notice = ''; this.listQuery = ''; this.inventoryData = emptyInventory(); this.inventoryLoaded = false; this.inventoryLoading = false; this.inventoryError = '';
        this.deps.render(); await this.refreshInventory(); return;
    }
    if (a.type === 'new-share') {
        if (this.inventory !== 'by-me' || !['people','links','guests'].some(method => this.capability(method as SharingSection).create)) return;
        this.sequence++; this.searchSequence++; this.resetDraft(); this.itemData = null; this.selectedItem = null; this.selectedEntryId = ''; this.entries = [];
        this.mode = 'choose-method'; this.status = 'idle'; this.message = ''; this.notice = ''; this.createdId = ''; this.deps.render(); this.deps.focus?.('heading'); return;
    }
    if (a.type === 'choose-method' || a.type === 'set-section') {
        const method = a.type === 'choose-method' ? a.method : a.section;
        if (this.inventory !== 'by-me' || !this.capability(method).create) return;
        const key = this.scope;
        const dirty = this.dirty();
        if (this.draft.password) { this.draft.password = ''; this.deps.render(); }
        if (dirty && !await this.deps.confirm('Discard the unsaved sharing changes?')) return;
        if (!this.current(key)) return;
        this.sequence++; this.searchSequence++; this.section = method; this.resetDraft(); this.itemData = null; this.selectedItem = null; this.selectedEntryId = ''; this.entries = [];
        this.mode = 'choose-item'; this.status = 'idle'; this.message = ''; this.notice = ''; this.deps.render(); this.deps.focus?.('heading');
        if (this.spaceId) await this.browse('/'); return;
    }
    if (a.type === 'choose-item' || a.type === 'change-item') {
        const key = this.scope;
        const dirty = this.dirty();
        if (this.draft.password) { this.draft.password = ''; this.deps.render(); }
        if (dirty && !await this.deps.confirm('Discard the unsaved sharing changes and choose another item?')) return;
        if (!this.current(key)) return;
        this.sequence++; this.searchSequence++; this.resetDraft(); this.itemData = null; this.selectedItem = null; this.selectedEntryId = ''; this.entries = [];
        this.mode = a.type === 'choose-item' ? 'lookup-item' : 'choose-item'; this.status = 'idle'; this.message = ''; this.deps.render(); this.deps.focus?.('heading');
        if (this.spaceId) await this.browse('/'); return;
    }
    if (a.type === 'cancel') { const key=this.scope, dirty=this.dirty(); if(this.draft.password){this.draft.password='';this.deps.render();} if(dirty && !await this.deps.confirm('Discard the unsaved sharing changes?')) return; if(!this.current(key)) return; this.sequence++; this.searchSequence++; this.mode = 'list'; this.selectedInventoryId = ''; this.resetDraft(); this.message = ''; this.deps.render(); this.deps.focus?.('new-share'); return; }
    if (a.type === 'open-folder') { const e = this.entries.find(e => e.id === a.itemId); if (e?.isFolder && !e.encrypted) await this.browse(e.path); return; }
    if (a.type === 'open-parent') { if (this.spaceId) await this.browse(parent(this.path)); return; }
    if (a.type === 'refresh-items') { if (this.spaceId) await this.browse(this.path); return; }
    if (a.type === 'select-item') { const e = this.entries.find(e => e.id === a.itemId); if (e) this.select(e); return; }
    if (a.type === 'use-item' || a.type === 'view-item-shares') { await this.loadItem(a.type === 'use-item'); return; }
    if (a.type === 'choose-recipient') { if (this.recipientResults.some(r => r.id === a.recipientId)) { this.draft.recipientId = a.recipientId; this.deps.render(); } return; }
    if (a.type === 'show-details') { if (this.inventoryData.rows.some(r => r.id === a.shareId)) { this.selectedInventoryId = a.shareId; this.selectedShareId = ''; this.mode = 'details'; this.deps.render(); this.deps.focus?.('heading'); } return; }
    if (a.type === 'copy-link') {
        const url = this.inventoryData.urls.get(a.shareId);
        if (url) { const key = this.scope; try { await this.deps.copy(url); if (this.current(key)) this.notice = 'Link copied.'; } catch { if (this.current(key)) this.inventoryError = 'Could not copy the link. Try again.'; } if (this.current(key)) this.deps.render(); } return;
    }
    if (a.type === 'edit-access') { await this.editInventory(a.shareId); return; }
    if (a.type === 'refresh') {
        if (this.ownedEdit) { const id=this.selectedInventoryId,key=this.scope; if(this.dirty() && !await this.deps.confirm('Discard the unsaved changes and reload current share settings?')) return; if(this.current(key)) await this.editInventory(id,true); return; }
        if (!this.caps) { this.capsError = ''; await this.loadCapabilities(); await this.refreshInventory(true); }
        else if (['settings','edit'].includes(this.mode) && this.selectedItem) { const key = this.scope, mode = this.mode; await this.loadItem(false); if (this.current(key)) { this.mode = mode; this.deps.render(); } }
        else await this.refreshInventory(true);
        return;
    }
    if (a.type === 'remove-access') { await this.revokeInventory(a.shareId); return; }
    if (a.type === 'save-access') { if(this.ownedEdit) await this.saveInventoryEdit(); else await this.mutate(a); }
}
    private async mutate(a: Extract<SharingAction, {
        type: 'save-access' | 'remove-access';
    }>) {
        const c = this.sync(), item = this.selectedItem, data = this.itemData;
        if (!c?.connected || !item || !data || this.unknown)
            return;
        const section = this.section, editing = this.mode === 'edit', removing = a.type === 'remove-access';
        const selectedId = removing ? a.shareId : this.selectedShareId;
        const row = data.rows.find(r => r.id === selectedId);
        if (removing && !row?.canRemove)
            return;
        if (editing && !removing && !row?.canEdit)
            return;
        const cap = this.capability(section);
        if (!removing && !editing && !cap.create)
            return;
        const role = section === 'links' ? data.linkTypes.includes(this.draft.role) : data.roles.some(r => r.id === this.draft.role);
        const expiry = this.draft.expiry ? guestExpiryValue(this.draft.expiry) : null;
        const linkPasswordPolicy = section === 'links' && !editing ? this.passwordRequiredFor(this.draft.role) : false;
        const passwordBytes = new TextEncoder().encode(this.draft.password).length;
        if (!removing && section === 'links' && !editing && linkPasswordPolicy === null) {
            this.message = 'The server password requirements for this link type are unknown. Refresh sharing information before creating the link.';
            this.deps.render();
            return;
        }
        if (!removing && section === 'links' && !editing && (passwordBytes > 72 || (linkPasswordPolicy === true && !this.draft.password))) {
            this.message = passwordBytes > 72 ? 'Link passwords can be at most 72 UTF-8 bytes.' : 'Enter a password for this link type.';
            this.deps.render();
            return;
        }
        if (!removing && (!role || (this.draft.expiry && !expiry) || (expiry && Date.parse(expiry) <= Date.now()) || (section === 'guests' && !editing && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(this.draft.recipient)))) {
            this.message = 'Review the recipient, access and expiration before continuing.';
            this.deps.render();
            return;
        }
        const key = this.scope, seq = ++this.sequence;
        const args: Record<string, unknown> = { space_id: this.spaceId, path: item.path, expected_item_id: data.item_id };
        let action: string;
        if (removing) {
            action = section === 'guests' ? 'guest_revoke' : section === 'links' ? 'sharing_link_revoke' : 'sharing_revoke';
            args.permission_id = selectedId;
        }
        else if (section === 'guests') {
            action = editing ? 'guest_update' : 'guest_invite';
            args.role_id = this.draft.role;
            args.expiration_date_time = expiry;
            if (editing)
                args.permission_id = selectedId;
            else
                args.email = this.draft.recipient.trim();
        }
        else if (section === 'links') {
            action = 'sharing_link_create';
            args.link_type = this.draft.role;
            args.display_name = this.draft.linkName.trim() || item.name;
            args.expiration_date_time = expiry;
            if (!editing && this.draft.password) args.password = this.draft.password;
        }
        else {
            action = editing ? 'sharing_update' : 'sharing_invite';
            args.role_id = this.draft.role;
            if (editing)
                args.permission_id = selectedId;
            else {
                const selected = this.recipientResults.find(r => r.id === this.draft.recipientId);
                if (!selected) {
                    this.message = 'Choose a person or group from the server results.';
                    this.deps.render();
                    return;
                }
                args.recipient_kind = selected.kind === 'group' ? 'group' : 'user';
                args.recipient_id = selected.id.slice(selected.id.indexOf(':') + 1);
                args.expiration_date_time = expiry;
            }
        }
        const submittedPassword = action === 'sharing_link_create' && typeof args.password === 'string' ? args.password : '';
        if (action === 'sharing_link_create') this.draft.password = '';
        this.busy = true;
        this.message = '';
        this.deps.render();
        try {
            if (removing && !await this.deps.confirm(`Remove ${row?.sharedWith}'s access to ${item.name}? This does not delete the file or folder or remove other grants and downloaded copies.`))
                return;
            if (!this.current(key, seq))
                return;
            const ack = await this.rpc(action, args, key);
            if (!this.current(key, seq))
                return;
            if (ack.accepted !== true)
                throw new Error('Could not confirm the sharing result. Refresh before trying again.');
            this.busy = false;
            this.mode = 'list';
            this.resetDraft();
            this.notice = removing ? 'Access removed.' : section === 'guests' && !editing ? 'Invitation submitted to the server.' : 'Sharing change saved.';
            this.inventory = section === 'links' ? 'public-links' : 'by-me';
            this.itemData = null; this.selectedItem = null; this.selectedInventoryId = ''; this.listQuery = '';
            await this.refreshInventory(true);
        }
        catch (e) {
            if (this.current(key, seq)) {
                this.message = errorText(e);
                if (submittedPassword && this.message.includes(submittedPassword)) this.message = this.message.split(submittedPassword).join('[redacted]');
                this.unknown = !/denied|unavailable|Reconnect|Choose|Review/.test(this.message);
            }
        }
        finally {
            if (this.current(key, seq)) {
                this.busy = false;
                this.deps.render();
            }
        }
    }
}
