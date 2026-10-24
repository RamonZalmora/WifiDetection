'use strict';
const $ = id => document.getElementById(id);
const routes = {dashboard:'Dashboard',scanner:'WiFi Scanner',hardware:'Hardware Detection',lab:'WPA2 Recovery Lab',verification:'Password Verification',analysis:'Security Analysis',history:'Test History',reports:'Reports',settings:'Settings'};
const fragment = new URLSearchParams(location.hash.slice(1));
if(fragment.has('token')) { sessionStorage.setItem('lab-token',fragment.get('token')); history.replaceState(null,'',location.pathname); }
const token = sessionStorage.getItem('lab-token') || '';
let state = {scan:{networks:[],adapters:[],errors:[]},projects:[],jobs:[],history:[]};
let currentJob = null, polling = null, refreshBusy = false;
const esc = text => String(text ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function notice(message,error=false){$('notice').hidden=false;$('notice').textContent=message;$('notice').className=error?'error':'';}
async function api(path,body,raw=false){
  const options={headers:{'X-Lab-Token':token}};
  if(body!==undefined){options.method='POST';options.headers['Content-Type']='application/json';options.body=JSON.stringify(body);}
  const response=await fetch('/api/'+path,options);
  if(!response.ok){let detail;try{detail=(await response.json()).detail;}catch{detail='Request failed';}throw new Error(typeof detail==='string'?detail:detail.map(x=>x.msg).join('\n'));}
  return raw?response:response.json();
}
function handle(fn){return async event=>{event?.preventDefault();try{await fn(event);}catch(error){notice(error.message,true);}};}
function go(route){if(!routes[route])route='dashboard';document.querySelectorAll('.view').forEach(e=>e.hidden=e.id!==route);document.querySelectorAll('nav a').forEach(e=>e.classList.toggle('active',e.hash==='#'+route));$('page-title').textContent=routes[route];}
$('nav').innerHTML=Object.entries(routes).map(([key,label],i)=>`<a href="#${key}"><span>${String(i+1).padStart(2,'0')}</span>${label}</a>`).join('');
window.addEventListener('hashchange',()=>go(location.hash.slice(1)));
document.querySelectorAll('[data-go]').forEach(button=>button.onclick=()=>{location.hash=button.dataset.go;});
function download(content,name,type='application/json'){const url=URL.createObjectURL(new Blob([content],{type}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function metrics(){const s=state.scan;const last=state.jobs.at(-1)||state.history[0];const entries=[['Detected networks',s.networks.length],['WPA2 networks',s.networks.filter(n=>n.authentication?.startsWith('WPA2')).length],['WiFi adapters',s.adapters.length],['Lab projects',state.projects.length],['Verification',currentJob?.status||'READY'],['Last result',last?.status||'No experiments']];$('metrics').innerHTML=entries.map(([label,value])=>`<div class="metric"><small>${label}</small><span class="number">${esc(value)}</span></div>`).join('');}
function renderScan(){
  const scan=state.scan;const query=$('search').value.toLowerCase(),security=$('security-filter').value;
  const rows=scan.networks.filter(n=>(n.ssid+' '+n.bssid).toLowerCase().includes(query)&&(!security||n.authentication===security));
  rows.sort($('sort').value==='ssid'?(a,b)=>a.ssid.localeCompare(b.ssid):(a,b)=>b.signal-a.signal);
  $('scan-note').textContent=[scan.timestamp?'Last request: '+new Date(scan.timestamp*1000).toLocaleString():'No scan requested.',scan.freshness,...scan.errors].filter(Boolean).join(' · ');
  $('networks').innerHTML=rows.map(n=>`<tr><td>${esc(n.ssid||'(Hidden SSID)')}<small>${esc(n.bssid)}</small></td><td>${n.signal}%<small>${n.rssi_dbm} dBm</small></td><td>${esc(n.authentication)}</td><td>${esc(n.encryption)}</td><td>${esc(n.band)} / ${esc(n.channel??'?')}</td><td><button data-bssid="${esc(n.bssid)}">View</button></td></tr>`).join('')||'<tr><td colspan="6" class="empty">No observed networks. Use Scan now on Windows with WiFi enabled.</td></tr>';
  $('networks').querySelectorAll('button').forEach(button=>button.onclick=()=>{const network=scan.networks.find(n=>n.bssid===button.dataset.bssid);$('network-details').hidden=false;$('network-details').innerHTML='<h3>Observed network details</h3><pre>'+esc(JSON.stringify(network,null,2))+'</pre>';});
  $('adapters').innerHTML=scan.adapters.map(a=>`<article><h2>${esc(a.name)}</h2><p>State: ${esc(a.state)}</p><p>Manufacturer: ${esc(a.manufacturer)} · Driver: ${esc(a.driver)} · Provider: ${esc(a.driver_provider||'Not exposed')}</p><p>Standards: ${esc(a.standards.join(', ')||'Not determined')}</p><p>Native scanning: ${a.native_scan?'Supported; scan request accepted':'Unavailable / not verified'}<br>Advanced capture / monitor mode: ${esc(a.monitor_mode)}</p><p class="muted">No advanced capture controls are provided.</p></article>`).join('')||'<article>No wireless adapters observed. Run hardware detection on Windows; check radio, driver, WLAN AutoConfig, and Location privacy settings.</article>';
  $('assessments').innerHTML=scan.networks.map(n=>`<article><h3>${esc(n.ssid||'(Hidden SSID)')} / ${esc(n.bssid)}</h3><p>${esc(n.authentication)} · ${esc(n.encryption)}</p><p>${esc(n.analysis.observed_risks.join(' ')||'No legacy risk identified from the available classification. This is not a complete security assessment.')}</p><p class="muted">${esc(n.security_scope)}. WPS: Not determined. Firmware: Not determined.</p></article>`).join('')||'<p>No observations available. Scan first.</p>';
}
function renderProjects(){
  const selected=$('project-select').value;
  $('project-select').innerHTML=state.projects.map(p=>`<option value="${p.id}">${esc(p.name)} — ${esc(p.ssid)}</option>`).join('')||'<option value="">Create a laboratory project first</option>';
  if(state.projects.some(p=>p.id===selected))$('project-select').value=selected;
  $('start-test').disabled=!state.projects.length;
  $('projects').innerHTML=state.projects.map(p=>`<div class="project-row"><div>${esc(p.name)}<small>${esc(p.ssid)} · ${esc(p.source)} · READY</small></div><button data-export="${p.id}">Export proof</button></div>`).join('')||'<p>No projects in this session.</p>';
  $('projects').querySelectorAll('button').forEach(button=>button.onclick=handle(async()=>{if(!confirm('Export sensitive laboratory proof? Anyone with this file can test password guesses offline.'))return;download(JSON.stringify(await api('projects/'+button.dataset.export+'/data'),null,2),'laboratory-proof.json');}));
}
function renderHistory(){
  $('history-rows').innerHTML=state.history.map(j=>`<tr><td>${esc(j.project)}<small>${esc(j.ssid)}</small></td><td>${esc(j.status)}</td><td>${j.tested} / ${j.total}</td><td>${j.duration.toFixed(3)} s</td><td>${new Date(j.finished*1000).toLocaleString()}</td></tr>`).join('')||'<tr><td colspan="5">No completed experiments.</td></tr>';
  const selection=$('report-job').value;const jobs=new Map([...state.history,...state.jobs].map(j=>[j.id,j]));
  $('report-job').innerHTML=[...jobs.values()].map(j=>`<option value="${j.id}">${esc(j.project)} — ${esc(j.status)} — ${esc(j.id.slice(0,8))}</option>`).join('');
  if(jobs.has(selection))$('report-job').value=selection;
}
async function refresh(){if(refreshBusy)return;refreshBusy=true;try{state=await api('dashboard');metrics();renderScan();renderProjects();renderHistory();}finally{refreshBusy=false;}}
$('refresh').onclick=handle(refresh);
document.querySelectorAll('.scan').forEach(button=>button.onclick=handle(async()=>{button.disabled=true;try{await api('scan',{});await refresh();notice('Scan request completed. Windows may return cached results; refresh the scan after a few seconds.');}finally{button.disabled=false;}}));
['search','security-filter','sort'].forEach(id=>$(id).addEventListener('input',renderScan));
$('generate-form').onsubmit=handle(async event=>{const form=event.target;const data=new FormData(form);const p=await api('projects/generated',{name:data.get('name'),ssid:data.get('ssid'),password:data.get('password'),authorized:data.has('authorized')});form.elements.password.value='';await refresh();$('project-select').value=p.id;notice('READY · Laboratory proof generated. Setup password is not stored.');location.hash='verification';});
$('import-form').onsubmit=handle(async event=>{const form=event.target;const values=new FormData(form);const file=values.get('file');if(file.size>16384)throw new Error('Proof file exceeds 16 KiB');$('import-status').textContent='VALIDATING DATA';try{const data=JSON.parse(await file.text());await api('projects/import',{name:values.get('name'),authorized:values.has('authorized'),data});$('import-status').textContent='READY · Proof schema validated; no router authenticity is asserted.';form.reset();await refresh();}catch(error){$('import-status').textContent='UNSUPPORTED FORMAT / ERROR · '+error.message;throw error;}});
$('candidate-file').onchange=handle(async event=>{const file=event.target.files[0];if(!file)return;if(file.size>650000)throw new Error('Candidate file exceeds 650,000 bytes');const text=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());$('test-form').elements.candidates.value=text;});
function showJob(job){
  currentJob=job;$('job-state').textContent=job.status;$('job-state').className='state'+(job.status==='VERIFIED MATCH'?' success':job.status==='ERROR'?' error':'');
  $('progress').value=job.total?100*job.tested/job.total:0;
  const details=[['Tested',`${job.tested} / ${job.total}`],['Duration',job.duration.toFixed(3)+' s'],['Attempts / second',job.attempts_per_second.toFixed(1)],['Estimated remaining',job.eta_seconds===null?'—':job.eta_seconds.toFixed(1)+' s']];
  $('job-metrics').innerHTML=details.map(([key,value])=>`<div><small>${key}</small>${esc(value)}</div>`).join('');
  $('job-note').textContent=[job.ssid,job.method,job.confidence,job.error,job.supplied>job.total?`Limit applied: ${job.total} of ${job.supplied} supplied candidates.`:''].filter(Boolean).join(' · ');
  const active=job.status==='TESTING';$('cancel-test').disabled=!active;$('start-test').disabled=active||!state.projects.length;
  $('match').hidden=!job.password;$('matched-password').textContent=job.password||'';metrics();
}
async function poll(){if(!currentJob)return;try{const job=await api('tests/'+currentJob.id);showJob(job);if(job.status==='TESTING')polling=setTimeout(poll,300);else await refresh();}catch(error){notice(error.message,true);}}
$('test-form').onsubmit=handle(async event=>{const data=new FormData(event.target);const lines=data.get('candidates').replace(/\r\n/g,'\n').split('\n');if(lines.at(-1)==='')lines.pop();showJob(await api('tests',{project_id:data.get('project_id'),candidates:lines,limit:Number(data.get('limit'))}));event.target.elements.candidates.value='';$('candidate-file').value='';clearTimeout(polling);await poll();});
$('cancel-test').onclick=handle(async()=>{if(currentJob)await api('tests/'+currentJob.id+'/cancel',{});});
$('hide-password').onclick=()=>{$('matched-password').textContent='Hidden';$('match').hidden=true;};
$('report-form').onsubmit=handle(async event=>{const data=new FormData(event.target);const response=await api('reports',{job_id:data.get('job_id'),format:data.get('format'),include_password:data.has('include_password'),confirm_sensitive:data.has('confirm_sensitive')},true);download(await response.text(),'lab-report.'+data.get('format'),response.headers.get('content-type'));});
$('advice-form').onsubmit=handle(async event=>{const result=await api('password/analyze',{password:event.target.elements.password.value});$('advice-result').textContent=`Length: ${result.length}. ${result.warnings.join(' ')} ${result.note}`;event.target.elements.password.value='';});
$('strong-password').onclick=handle(async()=>{const result=await api('password/generate',{});$('advice-result').textContent='Generated locally: '+result.password;});
$('clear-session').onclick=handle(async()=>{if(!confirm('Clear all in-memory projects and password results?'))return;await api('session/clear',{});clearTimeout(polling);currentJob=null;$('match').hidden=true;$('matched-password').textContent='';$('job-state').textContent='READY';$('progress').value=0;$('job-metrics').textContent='';$('job-note').textContent='Session cleared.';$('advice-result').textContent='';await refresh();notice('Projects and sensitive results cleared. History retained.');});
$('shutdown').onclick=handle(async()=>{if(!confirm('Stop the local application and cancel any active experiment?'))return;await api('shutdown',{});clearTimeout(polling);sessionStorage.removeItem('lab-token');notice('Application stopped. Close this tab. Restart with START.bat.');document.querySelectorAll('button').forEach(b=>b.disabled=true);});
go(location.hash.slice(1));
refresh().then(()=>{const active=state.jobs.find(j=>j.status==='TESTING');if(active){showJob(active);poll();}else if(state.jobs.length)showJob(state.jobs.at(-1));}).catch(error=>notice(error.message,true));
