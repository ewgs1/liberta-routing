import {lstat,readFile,readdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {ARTIFACTS,args,ensure,sha256} from './lib.mjs';
export async function verifyRelease(directory,pinned){
 ensure(/^[a-f0-9]{64}$/.test(pinned??''),'trusted manifest SHA256 required');
 ensure(!(await lstat(directory)).isSymbolicLink(),'symlink directory refused');
 ensure((await readdir(directory)).sort().join(',')===[...ARTIFACTS,'release.json'].sort().join(','),'unexpected release files');
 const bytes=await readFile(join(directory,'release.json'));ensure(sha256(bytes)===pinned,'manifest hash mismatch');
 const release=JSON.parse(bytes);ensure(release.schemaVersion===2,'unsupported manifest');
 for(const name of ARTIFACTS){ensure((await lstat(join(directory,name))).isFile(),'regular file required');const body=await readFile(join(directory,name));ensure(sha256(body)===release.files[name]?.sha256&&body.length===release.files[name]?.bytes,'artifact hash mismatch: '+name);}
 return release;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{const o=args(process.argv.slice(2),['--dir','--manifest-sha256']);console.log('Verified '+(await verifyRelease(o['--dir'],o['--manifest-sha256'])).name);}catch(error){console.error(error.message);process.exitCode=1;}}
