#!/usr/bin/env python3
"""Offline notice inventory for a locked platform release graph; never builds/downloads.
Run from any directory. --node-modules selects an existing locked UI installation.
Includes non-dev build/proc-macro dependencies conservatively, not a binary SBOM.
"""
import argparse, hashlib, json, os, re, shutil, subprocess, tarfile, tomllib, zipfile, xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def digest(b): return hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--node-modules',type=Path,required=True);p.add_argument('--target-platform',default='x86_64-unknown-linux-gnu');p.add_argument('--output-root',type=Path,default=ROOT/'legal');p.add_argument('--webview2-sdk-package',type=Path,help='Exact Microsoft.Web.WebView2 NuGet package used to source WebView2Loader.dll for Windows targets');a=p.parse_args()
 out=a.output_root if a.output_root.is_absolute() else ROOT/a.output_root
 out=out.resolve();out.mkdir(parents=True,exist_ok=True);rows={};gaps=[]
 try: out_prefix=out.relative_to(ROOT).as_posix()
 except ValueError: raise RuntimeError('--output-root must stay within the desktop source tree')
 legacy_default=out==(ROOT/'legal').resolve() and a.target_platform=='x86_64-unknown-linux-gnu'
 windows_target='windows' in a.target_platform
 if windows_target and not a.webview2_sdk_package:raise RuntimeError('Windows target notice collection requires --webview2-sdk-package for the bundled WebView2 loader.')
 def put_bytes(b,destination):
  if len(b)>2*1024*1024: raise RuntimeError('notice file exceeds bound: '+str(destination))
  dest=out/destination;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(b)
  return {'path':str(Path(out_prefix)/destination),'bytes':len(b),'sha256':digest(b)}
 def put(source,destination):return put_bytes(source.read_bytes(),destination)
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
  cmd=['cargo','metadata','--offline','--locked','--format-version','1','--filter-platform',a.target_platform,'--manifest-path',str(manifest),*feature]
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
 provenance_path=ROOT/'legal'/'upstream-notice-provenance.json'
 resolved=[];retained_outside_graph=[]
 if provenance_path.is_file():
  provenance=json.loads(provenance_path.read_bytes())
  locked={(r['name'],r['version']):r.get('checksum') for f in [ROOT/'Cargo.lock',ROOT/'desktop-shell/src-tauri/Cargo.lock'] for r in tomllib.loads(f.read_text())['package']}
  cargo_home=Path(os.environ.get('CARGO_HOME',Path.home()/'.cargo'))
  for supplement in provenance['packages']:
   name,version=supplement['package'].rsplit('@',1)
   row=next((r for r in rows.values() if r['name']==name and r['version']==version),None)
   if row is None:
    # Preserve historical provenance/texts without treating an obsolete package
    # as part of this release or requiring its removed Cargo.lock entry.
    retained_outside_graph.append(supplement['package']);continue
   expected=locked[(name,version)]
   if expected!=supplement['crate_sha256']:raise RuntimeError('upstream supplement lock mismatch')
   archives=list((cargo_home/'registry/cache').glob('*/'+name+'-'+version+'.crate'))
   if not archives or digest(archives[0].read_bytes())!=expected:raise RuntimeError('upstream registry archive checksum mismatch')
   with tarfile.open(archives[0]) as archive:
    vcs=json.load(archive.extractfile(name+'-'+version+'/.cargo_vcs_info.json'))
   if vcs['git']['sha1']!=supplement['vcs_commit']:raise RuntimeError('upstream supplement commit mismatch')
   for notice in supplement['supplemental_notices']+supplement['registry_metadata_files']:
    body=(ROOT/notice['path']).read_bytes()
    if len(body)!=notice['bytes'] or digest(body)!=notice['sha256']:raise RuntimeError('retained upstream notice changed')
   row['upstream_notice_provenance']={'path':'legal/upstream-notice-provenance.json','vcs_commit':supplement['vcs_commit'],'registry_crate_sha256':expected,'resolution':supplement['resolution']}
   if out == (ROOT/'legal').resolve():
    # Preserve the established Linux inventory paths and behavior exactly.
    row['notice_files'].extend(supplement['supplemental_notices'])
   else:
    retained=[]
    for notice in supplement['supplemental_notices']+supplement['registry_metadata_files']:
     source=ROOT/notice['path']
     retained.append(put(source,Path('upstream')/name/notice['path'].split('/')[-1]))
    row['notice_files'].extend(retained)
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
 result={'schema':'raiun-desktop-offline-notice-inventory-v1','target':a.target_platform,'scope':f'Locked non-dev dependency closure from raiun-agent, raiun-cli and raiun-desktop-shell/custom-protocol for {a.target_platform}; includes build/proc-macro dependencies conservatively; not exact linked-binary audit','lock_sha256':locks,'rust_packages':sorted(rows.values(),key=lambda r:(r['name'],r['version'])),'production_ui_packages':npm,'eme_notice':eme,'rust_toolchain_notices':runtime,'supplemental_build_tool_notices':tool_notices,'gaps':gaps,'cached_notice_gaps_resolved_from_verified_upstream':resolved,'retained_upstream_supplements_outside_current_graph':retained_outside_graph,'bundled_external_artifact_review':[],'system_libraries':'Windows API and WebView2 Evergreen Runtime dependencies are prerequisites supplied by Windows; this collector does not bundle them.' if windows_target else 'GTK/WebKitGTK/AppIndicator/FUSE/Secret Service/Zenity and other distribution libraries are runtime prerequisites, not copied by this collector; distribution packages retain their licenses.'}
 if windows_target:
  webview_package=next((r for r in result['rust_packages'] if r['name']=='webview2-com-sys'),None)
  if webview_package:
   sdk_path=a.webview2_sdk_package.resolve()
   if not sdk_path.is_file():raise RuntimeError('Microsoft WebView2 SDK package file is missing: '+str(sdk_path))
   sdk_sha=digest(sdk_path.read_bytes())
   with zipfile.ZipFile(sdk_path) as archive:
    nuspec_name=next((n for n in archive.namelist() if n.lower().endswith('.nuspec')),None)
    if not nuspec_name:raise RuntimeError('Microsoft WebView2 NuGet package has no nuspec metadata')
    ns={'n':'http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd'}
    metadata=ET.fromstring(archive.read(nuspec_name)).find('n:metadata',ns)
    if metadata is None or metadata.findtext('n:id',namespaces=ns)!='Microsoft.Web.WebView2':raise RuntimeError('Unexpected NuGet package identity')
    sdk_version=metadata.findtext('n:version',namespaces=ns)
    license_element=metadata.find('n:license',ns)
    if not sdk_version or license_element is None or license_element.get('type')!='file':raise RuntimeError('NuGet SDK license metadata is missing or not file-backed')
    license_name=license_element.text
    license_data=archive.read(license_name)
    sdk_notice=archive.read('NOTICE.txt')
    nuspec_data=archive.read(nuspec_name)
    loader_name='runtimes/win-x64/native/WebView2Loader.dll'
    sdk_loader=archive.read(loader_name)
   if sdk_version not in sdk_loader.decode('utf-16le',errors='ignore'):raise RuntimeError('WebView2Loader version resource does not match the official NuGet SDK version')
   crate_archive=next((Path(r['manifest_path']).parent/'x64'/'WebView2Loader.dll' for r in packages.values() if r['name']=='webview2-com-sys' and r['version']==webview_package['version']),None)
   if crate_archive is None or digest(crate_archive.read_bytes())!=digest(sdk_loader):raise RuntimeError('Cached crate WebView2Loader.dll does not match the official x64 NuGet package binary')
   license_out=put_bytes(license_data,Path('webview2-sdk')/f'Microsoft.Web.WebView2-{sdk_version}-LICENSE.txt')
   notice_out=put_bytes(sdk_notice,Path('webview2-sdk')/f'Microsoft.Web.WebView2-{sdk_version}-NOTICE.txt')
   nuspec_out=put_bytes(nuspec_data,Path('webview2-sdk')/f'Microsoft.Web.WebView2-{sdk_version}.nuspec')
   sdk_provenance_out=put(ROOT/'legal'/'windows-sdk'/'PROVENANCE.json',Path('webview2-sdk')/'PROVENANCE.json')
   rs_license=ROOT/'legal'/'windows-sdk'/'webview2-rs-LICENSE-MIT.txt'
   if not rs_license.is_file() or 'MIT License' not in rs_license.read_text() or 'Copyright (c) 2021 Bill Avery' not in rs_license.read_text():raise RuntimeError('Version-pinned webview2-rs MIT license source is missing')
   license_commits={'webview2-com':None,'webview2-com-sys':None,'webview2-com-macros':None}
   crate_records=[]
   for name in license_commits:
    row=next((r for r in result['rust_packages'] if r['name']==name),None)
    if row is None:continue
    crate=next((p for p in packages.values() if p['name']==name and p['version']==row['version']),None)
    if crate is None:raise RuntimeError('Locked WebView2 crate metadata is missing: '+name)
    vcs_path=Path(crate['manifest_path']).parent/'.cargo_vcs_info.json'
    vcs=json.loads(vcs_path.read_bytes())
    expected_lock=next((p['checksum'] for p in tomllib.loads((ROOT/'desktop-shell/src-tauri/Cargo.lock').read_text())['package'] if p['name']==name and p['version']==row['version']),None)
    if not expected_lock:raise RuntimeError('Locked WebView2 crate checksum is missing: '+name)
    cargo_home=Path(os.environ.get('CARGO_HOME',Path.home()/'.cargo'))
    archives=list((cargo_home/'registry/cache').glob('*/'+name+'-'+row['version']+'.crate'))
    if not archives or digest(archives[0].read_bytes())!=expected_lock:raise RuntimeError('WebView2 crate archive checksum differs from Cargo.lock: '+name)
    with tarfile.open(archives[0]) as tar:
     archived_vcs=json.load(tar.extractfile(f"{name}-{row['version']}/.cargo_vcs_info.json"))
    if archived_vcs['git']['sha1']!=vcs['git']['sha1']:raise RuntimeError('WebView2 crate source commit differs from cached package metadata: '+name)
    row['notice_files'].append(put(rs_license,Path('webview2-rs')/'LICENSE-MIT.txt'))
    gaps[:]=[g for g in gaps if g['package']!=name+'@'+row['version']]
    crate_records.append({'package':name,'version':row['version'],'crate_sha256':expected_lock,'vcs_commit':vcs['git']['sha1'],'license_source':f"https://raw.githubusercontent.com/wravery/webview2-rs/{vcs['git']['sha1']}/LICENSE"})
   result['bundled_external_artifact_review'].append({'artifact':'WebView2Loader.dll','source_package':f"webview2-com-sys@{webview_package['version']}",'source_package_sha256':next((p['checksum'] for p in tomllib.loads((ROOT/'desktop-shell/src-tauri/Cargo.lock').read_text())['package'] if p['name']=='webview2-com-sys' and p['version']==webview_package['version']),None),'status':'verified','sdk_package':'Microsoft.Web.WebView2','sdk_version':sdk_version,'nuget_package_url':f'https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/{sdk_version.lower()}/microsoft.web.webview2.{sdk_version.lower()}.nupkg','nuget_package_sha256':sdk_sha,'nuget_package_bytes':sdk_path.stat().st_size,'loader_sha256':digest(sdk_loader),'license_file':license_out,'notice_file':notice_out,'nuspec':nuspec_out,'package_provenance':sdk_provenance_out,'matching_crate_loader_sha256':digest(crate_archive.read_bytes())})
   result['webview2_rs_license_provenance']={'license_file':str(Path(out_prefix)/'webview2-rs/LICENSE-MIT.txt'),'license_sha256':digest(rs_license.read_bytes()),'crates':crate_records}
 if legacy_default:
  result={'schema':'raiun-desktop-offline-linux-notice-inventory-v1','target':'x86_64-unknown-linux-gnu','scope':'Locked non-dev dependency closure from raiun-agent, raiun-cli and raiun-desktop-shell/custom-protocol; includes build/proc-macro dependencies conservatively; not exact linked-binary audit','lock_sha256':locks,'rust_packages':sorted(rows.values(),key=lambda r:(r['name'],r['version'])),'production_ui_packages':npm,'eme_notice':eme,'rust_toolchain_notices':runtime,'supplemental_build_tool_notices':tool_notices,'gaps':gaps,'cached_notice_gaps_resolved_from_verified_upstream':resolved,'retained_upstream_supplements_outside_current_graph':retained_outside_graph,'system_libraries':'GTK/WebKitGTK/AppIndicator/FUSE/Secret Service/Zenity and other distribution libraries are runtime prerequisites, not copied by this collector; distribution packages retain their licenses.'}
 if not legacy_default:
  lines=[f'# Third-party notices ({a.target_platform})','','Generated from the locked target Cargo dependency closure and cached production npm package metadata. This is a conservative dependency/notice inventory, not a claim that every listed crate is linked into each binary or that all binary redistributions have been cleared.','']
  lines += [f"Target: `{a.target_platform}`",'', 'The exact target lock hashes, declared license expressions, source references, retained notice paths and unresolved gaps are recorded in `dependency-inventory.json`. Files listed there are retained under this folder. The first-party product license and attribution are distributed separately as `LICENSE` and `NOTICE.txt`.','', '## Rust packages']
  for row in result['rust_packages']:
   refs=', '.join(f"`{x['path']}`" for x in row['notice_files']) or 'no retained text'
   lines.append(f"- `{row['name']} {row['version']}` — {row.get('declared_license') or 'license expression unavailable'}; {refs}")
  lines += ['', '## Production UI packages']
  for row in result['production_ui_packages']:
   refs=', '.join(f"`{x['path']}`" for x in row['notice_files']) or 'no retained text'
   lines.append(f"- `{row['name']} {row['version']}` — {row.get('declared_license') or 'license expression unavailable'}; {refs}")
  lines += ['', '## Bundled external components']
  for artifact in result['bundled_external_artifact_review']:
   if artifact['status']=='verified': lines.append(f"- `{artifact['artifact']}` from `{artifact['source_package']}` matches `{artifact['sdk_package']} {artifact['sdk_version']}` (NuGet SHA-256 `{artifact['nuget_package_sha256']}`); retained its SDK license and notice texts.")
   else:lines.append(f"- `{artifact['artifact']}` from `{artifact['source_package']}`: {artifact['reason']}")
  lines += ['', '## Unresolved review items']
  for gap in gaps:lines.append(f"- `{gap['package']}`: {gap['reason']}")
  if not gaps and not result['bundled_external_artifact_review']:lines.append('- None recorded by the offline collector.')
  lines += ['', 'No unresolved item should be read as cleared for redistribution.']
  (out/'THIRD-PARTY-NOTICES.md').write_text('\n'.join(lines)+'\n')
  def existing_record(source,path):
   body=source.read_bytes()
   return {'path':str(path),'bytes':len(body),'sha256':digest(body)}
  result['first_party_notice_files']=[existing_record(ROOT/'LICENSE','LICENSE'),existing_record(ROOT/'NOTICE','NOTICE'),existing_record(out/'THIRD-PARTY-NOTICES.md',str(Path(out_prefix)/'THIRD-PARTY-NOTICES.md'))]
 (out/'dependency-inventory.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
 print(json.dumps({'rust_packages':len(rows),'ui_packages':len(npm),'gaps':gaps} if legacy_default else {'rust_packages':len(rows),'ui_packages':len(npm),'gaps':gaps,'bundled_external_artifact_review':result['bundled_external_artifact_review']},indent=2))
if __name__=='__main__':main()
