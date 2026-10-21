#!/usr/bin/env python3
"""Offline notice inventory for the locked Linux release graph; never builds/downloads.
Run from any directory. --node-modules selects an existing locked UI installation.
Includes non-dev build/proc-macro dependencies conservatively, not a binary SBOM.
"""
import argparse, hashlib, json, os, re, shutil, subprocess, tarfile, tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def digest(b): return hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--node-modules',type=Path,required=True);a=p.parse_args()
 out=ROOT/'legal';out.mkdir(exist_ok=True);rows={};gaps=[]
 def put(source,destination):
  b=source.read_bytes()
  if len(b)>2*1024*1024: raise RuntimeError('notice file exceeds bound: '+str(source))
  dest=out/destination;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(b)
  return {'path':str(Path('legal')/destination),'bytes':len(b),'sha256':digest(b)}
 def licenses(folder,prefix,explicit=None):
  found=[]
  for current,dirs,files in os.walk(folder,followlinks=False):
   dirs[:]=[d for d in dirs if d not in {'.git','target','node_modules'} and not (Path(current)/d).is_symlink()]
   for name in sorted(files):
    f=Path(current)/name
    if f.is_symlink():continue
    if re.match(r'^(licen[cs]e|copying|notice|copyright)(?:$|[._-])',name,re.I) or (explicit is not None and f==explicit):
     found.append(put(f,prefix/f.relative_to(folder)))
  return sorted(found,key=lambda x:x['path'])
 for manifest,roots,feature in [(ROOT/'Cargo.toml',{'raiun-agent','raiun-cli'},[]),(ROOT/'desktop-shell/src-tauri/Cargo.toml',{'raiun-desktop-shell'},['--features','custom-protocol'])]:
  cmd=['cargo','metadata','--offline','--locked','--format-version','1','--filter-platform','x86_64-unknown-linux-gnu','--manifest-path',str(manifest),*feature]
  graph=json.loads(subprocess.check_output(cmd,cwd=ROOT));packages={v['id']:v for v in graph['packages']};nodes={v['id']:v for v in graph['resolve']['nodes']};pending=[k for k,v in packages.items() if v['name'] in roots and v.get('source') is None];seen=set()
  while pending:
   key=pending.pop()
   if key in seen:continue
   seen.add(key);package=packages[key]
   pending.extend(dep['pkg'] for dep in nodes[key]['deps'] if any(k['kind']!='dev' for k in dep['dep_kinds']))
   if package.get('source') is None:continue
   identity=(package['name'],package['version'],package['source']);record=rows.get(identity)
   if record is None:
    directory=Path(package['manifest_path']).parent;explicit=Path(package['license_file']) if package.get('license_file') else None
    texts=licenses(directory,Path('rust')/(package['name']+'-'+package['version']),explicit)
    record={'ecosystem':'cargo','name':package['name'],'version':package['version'],'source':package['source'],'declared_license':package.get('license'),'repository':package.get('repository'),'description':package.get('description'),'notice_files':texts,'graphs':[]};rows[identity]=record
    if not texts:gaps.append({'package':package['name']+'@'+package['version'],'reason':'no cached license/notice file found; declared expression is not a license text'})
    if not package.get('license') and not explicit:gaps.append({'package':package['name']+'@'+package['version'],'reason':'no declared license expression or license_file'})
   record['graphs'].append(str(manifest.relative_to(ROOT)))
 # Previously authorized upstream text retrieval is a frozen input; this
 # collector stays offline. Verify exact registry checksums and VCS commits
 # again before applying supplements to the cached-text gaps.
 provenance_path=out/'upstream-notice-provenance.json'
 resolved=[]
 if provenance_path.is_file():
  provenance=json.loads(provenance_path.read_bytes())
  locked={(r['name'],r['version']):r.get('checksum') for f in [ROOT/'Cargo.lock',ROOT/'desktop-shell/src-tauri/Cargo.lock'] for r in tomllib.loads(f.read_text())['package']}
  cargo_home=Path(os.environ.get('CARGO_HOME',Path.home()/'.cargo'))
  for supplement in provenance['packages']:
   name,version=supplement['package'].rsplit('@',1)
   expected=locked[(name,version)]
   if expected!=supplement['crate_sha256']:raise RuntimeError('upstream supplement lock mismatch')
   archives=list((cargo_home/'registry/cache').glob('*/'+name+'-'+version+'.crate'))
   if not archives or digest(archives[0].read_bytes())!=expected:raise RuntimeError('upstream registry archive checksum mismatch')
   with tarfile.open(archives[0]) as archive:
    vcs=json.load(archive.extractfile(name+'-'+version+'/.cargo_vcs_info.json'))
   if vcs['git']['sha1']!=supplement['vcs_commit']:raise RuntimeError('upstream supplement commit mismatch')
   row=next(r for r in rows.values() if r['name']==name and r['version']==version)
   for notice in supplement['supplemental_notices']+supplement['registry_metadata_files']:
    body=(ROOT/notice['path']).read_bytes()
    if len(body)!=notice['bytes'] or digest(body)!=notice['sha256']:raise RuntimeError('retained upstream notice changed')
   row['upstream_notice_provenance']={'path':'legal/upstream-notice-provenance.json','vcs_commit':supplement['vcs_commit'],'registry_crate_sha256':expected,'resolution':supplement['resolution']}
   row['notice_files'].extend(supplement['supplemental_notices'])
   gaps=[g for g in gaps if g['package']!=supplement['package']]
   resolved.append(supplement['package'])
 # Production UI lockfiles, no npm install. Dev build tools are not UI runtime.
 npm=[]
 for lock in [ROOT/'package-lock.json',ROOT/'desktop-shell/package-lock.json']:
  data=json.loads(lock.read_bytes())
  for name,entry in data['packages'].items():
   if not name or entry.get('dev'):continue
   module=name.split('node_modules/',1)[1];folder=a.node_modules/module;actual=json.loads((folder/'package.json').read_bytes())
   if actual['name']!=module or actual['version']!=entry['version']:raise RuntimeError('cached npm version differs from lock: '+module)
   existing=next((r for r in npm if r['name']==module and r['version']==entry['version']),None)
   if existing:existing['lockfiles'].append(str(lock.relative_to(ROOT)));continue
   texts=licenses(folder,Path('npm')/(module.replace('/','__')+'-'+entry['version']))
   record={'ecosystem':'npm','name':module,'version':entry['version'],'declared_license':entry.get('license') or actual.get('license'),'lock_integrity':entry.get('integrity'),'notice_files':texts,'lockfiles':[str(lock.relative_to(ROOT))]};npm.append(record)
   if module=='@tauri-apps/plugin-dialog':
    # npm ships SPDX attribution; retain full license texts from the same
    # versioned upstream project's already cached Rust crate as supplement.
    crate=next((r for r in rows.values() if r['name']=='tauri-plugin-dialog' and r['version']==entry['version']),None)
    if crate:
     record['supplemental_same_version_upstream_texts']=[x for x in crate['notice_files'] if Path(x['path']).name in {'LICENSE_MIT','LICENSE_APACHE-2.0'}]
   if not texts:gaps.append({'package':module+'@'+entry['version'],'reason':'no cached npm license texts'})
 # Vite can emit its preload helper into the production bundle. Retain
 # cached build-tool notices separately; this is not a claim all tools ship.
 tool_notices=[]
 shell_lock=json.loads((ROOT/'desktop-shell/package-lock.json').read_bytes())['packages']
 for name in ['vite','rollup','esbuild','typescript']:
  entry=shell_lock.get('node_modules/'+name);folder=a.node_modules/name
  if entry and folder.is_dir():
   meta=json.loads((folder/'package.json').read_bytes())
   if meta['version']!=entry['version']:raise RuntimeError('cached tool differs from lock: '+name)
   tool_notices.append({'name':name,'version':entry['version'],'scope':'build tooling; Vite may emit runtime preload helper','notice_files':licenses(folder,Path('build-tools')/(name+'-'+entry['version']))})
 eme=put(ROOT/'crates/raiun-vault/EME-MIT-LICENSE',Path('EME-MIT-LICENSE'))
 # The compiler runtime is linked separately from Cargo packages.
 sysroot=Path(subprocess.check_output(['rustc','--print','sysroot'],text=True).strip());rustdocs=sysroot/'share/doc/rust'
 runtime=[]
 for f in [rustdocs/'COPYRIGHT-library.html']:
  if f.is_file():runtime.append(put(f,Path('rust-toolchain')/f.name))
 for f in sorted((rustdocs/'licenses').glob('*')):
  if f.is_file():runtime.append(put(f,Path('rust-toolchain/licenses')/f.name))
 if not runtime:gaps.append({'package':'Rust standard library/runtime','reason':'toolchain copyright/license files unavailable'})
 locks={str(f.relative_to(ROOT)):digest(f.read_bytes()) for f in [ROOT/'Cargo.lock',ROOT/'desktop-shell/src-tauri/Cargo.lock',ROOT/'package-lock.json',ROOT/'desktop-shell/package-lock.json']}
 result={'schema':'raiun-desktop-offline-linux-notice-inventory-v1','target':'x86_64-unknown-linux-gnu','scope':'Locked non-dev dependency closure from raiun-agent, raiun-cli and raiun-desktop-shell/custom-protocol; includes build/proc-macro dependencies conservatively; not exact linked-binary audit','lock_sha256':locks,'rust_packages':sorted(rows.values(),key=lambda r:(r['name'],r['version'])),'production_ui_packages':npm,'eme_notice':eme,'rust_toolchain_notices':runtime,'supplemental_build_tool_notices':tool_notices,'gaps':gaps,'cached_notice_gaps_resolved_from_verified_upstream':resolved,'system_libraries':'GTK/WebKitGTK/AppIndicator/FUSE/Secret Service/Zenity and other distribution libraries are runtime prerequisites, not copied by this collector; distribution packages retain their licenses.'}
 (out/'dependency-inventory.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps({'rust_packages':len(rows),'ui_packages':len(npm),'gaps':gaps},indent=2))
if __name__=='__main__':main()
