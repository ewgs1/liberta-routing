import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { args, ensure, json, readJson, sha256 } from './lib.mjs';
import { privateOutput } from './integrate.mjs';
export const templateHash = value => sha256(JSON.stringify(value));
export function prepareTemplate(current, generated) {
  ensure(current?.templateType==='XRAY_JSON' && current.uuid && current.templateJson && !Array.isArray(current.templateJson), 'expected one XRAY_JSON template');
  const base=current.templateJson;
  ensure(Array.isArray(base.outbounds) && base.outbounds.some(o=>o.tag==='direct'&&o.protocol==='freedom') && base.outbounds.some(o=>o.tag==='block'&&o.protocol==='blackhole'), 'direct/block outbounds required');
  ensure(!base.fakedns && !base.routing?.balancers && !base.routing?.rules?.some(r=>r.balancerTag), 'existing FakeDNS or balancers require review');
  ensure(!base.inbounds || base.inbounds.every(i=>['socks','http'].includes(i.protocol)&&i.listen==='127.0.0.1'), 'unsupported template inbounds');
  const result=structuredClone(base);
  result.dns=structuredClone(generated.dns);result.routing=structuredClone(generated.routing);
  if(result.inbounds)for(const inbound of result.inbounds)inbound.sniffing={enabled:true,destOverride:['http','tls','quic'],routeOnly:true};
  result.remarks='Liberta Routing v1';
  return result;
}
export function makePlan(current, generated, revision) {
  ensure(/^[a-f0-9]{40,64}$/.test(revision),'source revision hash required');
  const after=prepareTemplate(current,generated);
  return {schemaVersion:1,uuid:current.uuid,templateType:current.templateType,revision,before:current.templateJson,after,beforeSha256:templateHash(current.templateJson),afterSha256:templateHash(after)};
}
export function validatePlan(plan) {
  ensure(plan.schemaVersion===1 && typeof plan.uuid==='string' && plan.templateType==='XRAY_JSON' && templateHash(plan.before)===plan.beforeSha256 && templateHash(plan.after)===plan.afterSha256,'invalid or modified deployment plan');
}
export async function applyPlan(plan, api, {rollback=false}={}) {
  validatePlan(plan);
  const current=await api('GET',`subscription-templates/${plan.uuid}`);
  ensure(current.uuid===plan.uuid && current.templateType===plan.templateType,'target template mismatch');
  const expected=rollback?plan.afterSha256:plan.beforeSha256, target=rollback?plan.before:plan.after;
  ensure(templateHash(current.templateJson)===expected,'template changed since plan; prepare a new plan');
  await api('PATCH','subscription-templates',{uuid:plan.uuid,templateJson:target});
  const actual=await api('GET',`subscription-templates/${plan.uuid}`);
  ensure(templateHash(actual.templateJson)===templateHash(target),'template verification failed; inspect the private backup before further writes');
  return {templateUpdated:true,rollback,revision:plan.revision};
}
function apiClient() {
  const endpoint=new URL(process.env.REMNAWAVE_API_URL??'');
  ensure(endpoint.protocol==='https:'&&!endpoint.username&&!endpoint.password&&!endpoint.search&&!endpoint.hash,'HTTPS panel URL required');
  ensure(process.env.REMNAWAVE_API_TOKEN,'panel API token required');
  return async(method,path,body)=>{
    ensure(/^subscription-templates(?:\/[a-f0-9-]{36})?$/.test(path),'unsupported panel endpoint');
    const response=await fetch(endpoint.href.replace(/\/$/,'')+'/api/'+path,{method,headers:{Authorization:'Bearer '+process.env.REMNAWAVE_API_TOKEN,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined,redirect:'error',signal:AbortSignal.timeout(20000)});
    ensure(response.ok,'panel API request failed');
    const result=await response.json();ensure(result.response,'unexpected panel response');return result.response;
  };
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {
    const options=args(process.argv.slice(2),['--mode','--template','--plan','--uuid']);
    if(options['--mode']==='plan') {
      ensure(options['--plan'],'--plan required');
      const current=options['--template']?await readJson(options['--template']):await apiClient()('GET',`subscription-templates/${options['--uuid']}`);
      const generated=await readJson('dist/liberta.xray.json');
      const plan=makePlan(current,generated,sha256(json(generated)));
      await mkdir('.private',{recursive:true,mode:0o700});await writeFile(await privateOutput(options['--plan'],options['--template']??''),json(plan),{mode:0o600,flag:'wx'});
      console.log(JSON.stringify({planCreated:true,revision:plan.revision,templateUpdated:false}));
    }else {
      ensure(['apply','rollback'].includes(options['--mode'])&&options['--plan'],'required: --mode plan|apply|rollback --plan .private/plan.json');
      console.log(JSON.stringify(await applyPlan(await readJson(options['--plan']),apiClient(),{rollback:options['--mode']==='rollback'})));
    }
  } catch {console.error('Template synchronization failed; panel details and credentials were not printed');process.exitCode=1;}
}
