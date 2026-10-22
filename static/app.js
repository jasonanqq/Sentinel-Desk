const state = {view:'overview', page:1, status:'all', timeline:[], timeMode:'relative', start:'', end:'', trendSeries:'count', hoverIndex:-1};
const $ = id => document.getElementById(id);
const make = (tag, className='', value='') => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== '') node.textContent = String(value);
  return node;
};
const notify = (message, error=false) => {
  const box = $('toast');
  box.textContent = message;
  box.className = error ? 'show error' : 'show';
  clearTimeout(notify.timer);
  notify.timer = setTimeout(() => { box.className = ''; }, 3500);
};
async function api(path, options={}) {
  const response = await fetch(path, options);
  let payload;
  try { payload = await response.json(); } catch { payload = {error:'Unexpected response'}; }
  if (!response.ok) throw new Error(payload.error || 'Request failed');
  return payload;
}
async function post(path, payload) {
  return api(path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
}
function displayView(view) {
  state.view = view;
  document.querySelectorAll('.view').forEach(node => node.classList.toggle('hidden', node.id !== `view-${view}`));
  document.querySelectorAll('[data-view]').forEach(node => node.classList.toggle('active', node.dataset.view === view));
  $('page-title').textContent = ({overview:'Overview',events:'Event Explorer',alerts:'Alert Center',sources:'Data Ingestion',email:'Email Threat Analysis'})[view];
  if (view === 'email') window.EmailDesk?.load();
  if (view === 'events') loadEvents();
  if (view === 'alerts') loadAlerts();
  if (view === 'overview') loadOverview();
  if (view === 'sources') { loadIndexStatus(); loadCollectors(); }
}
function shortTime(value) {
  return value ? value.replace('T',' ').slice(0,19) : '';
}
function label(text, style) {
  return make('span', `tag ${style || 'info'}`, text);
}
function timeParameters() {
  const params = new URLSearchParams();
  if (state.start) params.set('from',state.start);
  if (state.end) params.set('to',state.end);
  return params;
}
function localInput(iso) {
  const date=new Date(iso);
  const pad=n=>String(n).padStart(2,'0');
  return `${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
function subtractCalendar(date, number, unit) {
  const result=new Date(date);
  if(unit==='days'||unit==='weeks') {
    result.setDate(result.getDate()-number*(unit==='weeks'?7:1));
  } else {
    const day=result.getDate();
    result.setDate(1);
    result.setMonth(result.getMonth()-number*(unit==='years'?12:1));
    const lastDay=new Date(result.getFullYear(),result.getMonth()+1,0).getDate();
    result.setDate(Math.min(day,lastDay));
  }
  return result;
}
function applyRelative() {
  const number=Number($('relative-count').value);
  const unit=$('relative-unit').value;
  if(!Number.isInteger(number)||number<1||number>1000||!['days','weeks','months','years'].includes(unit))return notify('Enter a whole number from 1 to 1000',true);
  const end=new Date(),start=subtractCalendar(end,number,unit);
  if(!Number.isFinite(start.getTime())||start>=end)return notify('Invalid time range',true);
  state.timeMode='relative';state.start=start.toISOString();state.end=end.toISOString();state.page=1;
  document.querySelectorAll('[data-range]').forEach(button=>button.classList.remove('active'));
  $('range-custom').classList.add('hidden');
  $('range-summary').textContent=`Last ${number} ${number===1?unit.slice(0,-1):unit} · ${start.toLocaleString()} to now`;
  refreshData();
}
function applyPreset(mode) {
  state.timeMode=mode;
  if (mode==='all') {
    state.start='';state.end='';
  } else if(mode!=='custom') {
    const now=new Date();
    const duration=mode==='7d'?7*86400000:mode==='30d'?30*86400000:86400000;
    state.start=new Date(now.getTime()-duration).toISOString();
    state.end=now.toISOString();
  }
  document.querySelectorAll('[data-range]').forEach(node=>node.classList.toggle('active',node.dataset.range===mode));
  $('range-custom').classList.toggle('hidden',mode!=='custom');
  $('time-from').value=localInput(state.start||new Date(Date.now()-86400000).toISOString());
  $('time-to').value=localInput(state.end||new Date().toISOString());
  const formats={'24h':'Last 24 hours','7d':'Last 7 days','30d':'Last 30 days','all':'All available events','custom':'Custom time range'};
  $('range-summary').textContent=`${formats[mode]} · Input times use your device timezone`;
  state.page=1;
  $('event-search').value='';
  $('filter-source').value='';
  $('filter-severity').value='';
  $('filter-type').value='';
  refreshData();
}
function applyCustom() {
  const from=$('time-from').value, to=$('time-to').value;
  if(!from||!to) return notify('Select both dates and times',true);
  const start=new Date(from),end=new Date(to);
  if (!Number.isFinite(start.getTime())||!Number.isFinite(end.getTime())||start>=end) return notify('End time must be after start time',true);
  state.start=start.toISOString();
  state.end=end.toISOString();
  state.page=1;
  $('range-summary').textContent=`${start.toLocaleString()} – ${end.toLocaleString()} (local time)`;
  refreshData();
}
function refreshData() {
  updateExports();
  return Promise.all([loadOverview(),loadEvents(),loadAlerts(),window.EmailDesk?.load()]);
}
function updateExports() {
  const eventParams=eventParameters();
  eventParams.delete('page');eventParams.delete('size');
  $('export-events').href=`/api/export/events.csv?${eventParams}`;
  const alertParams=timeParameters();alertParams.set('status',state.status);
  $('export-alerts').href=`/api/export/alerts.csv?${alertParams}`;
}
function eventParameters() {
  const params=timeParameters();
  params.set('q',$('event-search').value);
  params.set('source',$('filter-source').value);
  params.set('severity',$('filter-severity').value);
  params.set('event_type',$('filter-type').value);
  params.set('page',state.page);
  params.set('size',25);
  return params;
}
function drilldown(point, eventType='') {
  if(!point)return;
  state.start=point.from;state.end=point.to;state.timeMode='custom';state.page=1;
  document.querySelectorAll('[data-range]').forEach(node=>node.classList.toggle('active',node.dataset.range==='custom'));
  $('range-custom').classList.remove('hidden');
  $('time-from').value=localInput(point.from);
  $('time-to').value=localInput(point.to);
  $('range-summary').textContent=`${new Date(point.from).toLocaleString()} – ${new Date(point.to).toLocaleString()} (local time)`;
  $('filter-type').value=eventType;
  updateExports();
  displayView('events');
}
const chartGeometry=()=>{
  const canvas=$('trend-chart');
  const w=canvas.getBoundingClientRect().width;
  return {w,h:220,left:38,right:14,top:20,bottom:35};
};
function drawTrend(points) {
  const canvas=$('trend-chart');
  if(!canvas||!points?.length)return;
  const {w,h,left,right,top,bottom}=chartGeometry();
  const ratio=window.devicePixelRatio||1;
  canvas.width=Math.round(w*ratio);canvas.height=Math.round(h*ratio);
  const ctx=canvas.getContext('2d');ctx.setTransform(ratio,0,0,ratio,0,0);
  const usableW=w-left-right,usableH=h-top-bottom;
  ctx.clearRect(0,0,w,h);
  const key=state.trendSeries;
  const max=Math.max(4,...points.map(point=>point[key]));
  ctx.lineWidth=1;ctx.strokeStyle='#30405d';ctx.font='11px system-ui';ctx.fillStyle='#91a6c7';
  for(let n=0;n<=4;n++){
    const y=top+usableH*n/4;
    ctx.beginPath();ctx.moveTo(left,y);ctx.lineTo(w-right,y);ctx.stroke();
    ctx.fillText(String(Math.round(max*(1-n/4))),4,y+4);
  }
  const xFor=i=>left+(points.length===1?0.5:i/(points.length-1))*usableW;
  const yFor=v=>top+usableH-(v/max)*usableH;
  const gradient=ctx.createLinearGradient(0,top,0,top+usableH);
  gradient.addColorStop(0,'rgba(78,214,197,.34)');gradient.addColorStop(1,'rgba(78,214,197,0)');
  ctx.beginPath();ctx.moveTo(xFor(0),top+usableH);
  points.forEach((p,i)=>ctx.lineTo(xFor(i),yFor(p[key])));
  ctx.lineTo(xFor(points.length-1),top+usableH);ctx.closePath();ctx.fillStyle=gradient;ctx.fill();
  ctx.beginPath();points.forEach((p,i)=>i?ctx.lineTo(xFor(i),yFor(p[key])):ctx.moveTo(xFor(i),yFor(p[key])));
  ctx.strokeStyle='#52d4cc';ctx.lineWidth=2.5;ctx.stroke();
  const labels=[0,Math.floor((points.length-1)/4),Math.floor((points.length-1)/2),Math.floor((points.length-1)*3/4),points.length-1];
  ctx.fillStyle='#91a6c7';ctx.textAlign='center';
  [...new Set(labels)].forEach(i=>ctx.fillText(points[i].hour||'',Math.max(35,Math.min(w-35,xFor(i))),h-9));
  if(state.hoverIndex>=0&&state.hoverIndex<points.length){
    const i=state.hoverIndex,x=xFor(i),y=yFor(points[i][key]);
    ctx.beginPath();ctx.moveTo(x,top);ctx.lineTo(x,top+usableH);ctx.strokeStyle='#7188a5';ctx.lineWidth=1;ctx.setLineDash([4,5]);ctx.stroke();ctx.setLineDash([]);
    ctx.beginPath();ctx.arc(x,y,5,0,Math.PI*2);ctx.fillStyle='#e7fff9';ctx.fill();ctx.strokeStyle='#52d4cc';ctx.lineWidth=2;ctx.stroke();
  }
}
function showChartTooltip(index){
  state.hoverIndex=index;
  const tooltip=$('chart-tooltip'),points=state.timeline;
  if(index<0||index>=points.length){tooltip.classList.add('hidden');drawTrend(points);return;}
  const point=points[index],text={'count':'Events','denied':'Firewall denies','failed':'Failed logins'}[state.trendSeries];
  tooltip.textContent=`${text}: ${point[state.trendSeries]} · ${new Date(point.from).toLocaleString()} – ${new Date(point.to).toLocaleString()}`;
  tooltip.classList.remove('hidden');
  drawTrend(points);
}
function nearestIndex(event){
  if(!state.timeline.length)return -1;
  const bounds=$('trend-chart').getBoundingClientRect();
  const {left,right}=chartGeometry();
  const x=event.clientX-bounds.left;
  return Math.min(state.timeline.length-1,Math.max(0,Math.round((x-left)/(bounds.width-left-right)*(state.timeline.length-1))));
}
function showSources(items) {
  const root=$('source-breakdown');root.replaceChildren();
  if(!items.length){root.append(make('div','empty','No events in the selected time range.'));return;}
  const max=items[0].value||1;
  for(const item of items){
    const button=make('button','source-button');button.type='button';
    button.title=`Investigate ${item.label} logs`;
    const head=make('div','bar-head');
    head.append(make('span','',item.label),make('span','',item.value));
    const track=make('div','bar-track'),fill=make('div','bar-fill');
    fill.style.width=`${Math.max(2,item.value/max*100)}%`;
    track.append(fill);button.append(head,track);root.append(button);
    button.addEventListener('click',()=>{state.page=1;$('filter-source').value=item.label;$('filter-type').value='';updateExports();displayView('events');});
  }
}
function buildAlert(item, actionable) {
  const card=make('article','alert-item');const main=make('div','alert-main');const top=make('div','alert-top');
  top.append(label(item.severity,item.severity),make('strong','',item.title));
  if(item.status==='closed') top.append(label('Resolved','closed'));
  main.append(top,make('p','',item.summary),make('small','',`${item.rule_id} · ${item.entity} · ${shortTime(item.last_seen)} UTC · ${item.hits} trigger${item.hits===1?'':'s'}`));
  card.append(main);
  if(actionable){
    const button=make('button','button secondary',item.status==='open'?'Mark resolved':'Reopen');
    button.addEventListener('click',async()=>{
      button.disabled=true;
      try{await post(`/api/alerts/${item.id}/status`,{status:item.status==='open'?'closed':'open'});await Promise.all([loadAlerts(),loadOverview()]);notify('Alert status updated');}
      catch(error){notify(error.message,true);}finally{button.disabled=false;}
    });card.append(button);
  }
  return card;
}
async function loadOverview() {
  try {
    const [data, alerts]=await Promise.all([api(`/api/stats?${timeParameters()}`),api(`/api/alerts?status=open&${timeParameters()}`)]);
    $('metric-total').textContent=data.total.toLocaleString();
    $('metric-day').textContent=data.denied.toLocaleString();
    $('metric-alerts').textContent=data.open_alerts.toLocaleString();
    $('metric-critical').textContent=data.critical.toLocaleString();
    state.timeline=data.timeline;
    state.hoverIndex=-1;
    $('chart-tooltip').classList.add('hidden');
    $('trend-total').textContent=`${data.timeline.reduce((sum,point)=>sum+point[state.trendSeries],0).toLocaleString()} matching ${$('trend-series').selectedOptions[0].textContent.toLowerCase()}`;
    drawTrend(state.timeline);
    showSources(data.sources);
    window.EmailDesk?.snapshot();
    const root=$('overview-alerts');root.replaceChildren();
    if(alerts.items.length===0)root.append(make('div','empty','No open alerts. Generate demo activity to see the detection engine in action.'));
    else alerts.items.slice(0,5).forEach(item=>root.append(buildAlert(item,false)));
  }catch(error){notify(error.message,true);}
}
async function loadEvents(){
  const params=eventParameters();
  updateExports();
  try{
    const data=await api(`/api/events?${params}`),root=$('events-body');root.replaceChildren();
    for(const item of data.items){
      const row=make('tr');
      [shortTime(item.timestamp),item.source,item.event_type].forEach(text=>row.append(make('td','',text)));
      const cell=make('td');cell.append(label(item.severity,item.severity));row.append(cell);
      [item.src_ip||'—',item.username||'—',item.message||'—'].forEach(text=>row.append(make('td','',text)));
      root.append(row);
    }
    if(data.items.length===0){const row=make('tr'),cell=make('td','','No events match your filters');cell.colSpan=7;row.append(cell);root.append(row);}
    $('events-count').textContent=`${data.total.toLocaleString()} events`;
    $('page-label').textContent=String(state.page);
    $('page-prev').disabled=state.page<=1;
    $('page-next').disabled=state.page*data.size>=data.total;
  }catch(error){notify(error.message,true);}
}
async function loadAlerts(){
  try{
    const data=await api(`/api/alerts?status=${state.status}&${timeParameters()}`),root=$('all-alerts');root.replaceChildren();
    if(!data.items.length)root.append(make('div','empty','No alerts in this view.'));
    else data.items.forEach(item=>root.append(buildAlert(item,true)));
  }catch(error){notify(error.message,true);}
}
async function loadIndexStatus(){
  try{
    const data=await api('/api/index/status');
    $('index-events').textContent=data.events.toLocaleString();
    $('index-count').textContent=data.indexed.toLocaleString();
    $('index-health').textContent=data.synced&&data.emails?.synced?'Up to date':'Needs rebuilding';
    $('index-emails').textContent=(data.emails?.indexed||0).toLocaleString();
  }catch(error){$('index-health').textContent='Unavailable';notify(error.message,true);}
}
async function rebuildIndex(){
  const button=$('rebuild-index');button.disabled=true;
  try{
    const data=await post('/api/index/rebuild',{});
    await loadIndexStatus();
    notify(`Search indexes rebuilt: ${data.indexed.toLocaleString()} events and ${(data.emails?.indexed||0).toLocaleString()} emails`);
  }catch(error){notify(error.message,true);}finally{button.disabled=false;}
}
async function generateDemo(){
  try{const result=await post('/api/demo',{});notify(`Added ${result.inserted} synthetic events`);await refreshData();}
  catch(error){notify(error.message,true);}
}
async function importFile(){
  const file=$('event-file').files[0];
  if(!file){notify('Choose a file first',true);return;}
  try{
    if(file.size>1_800_000)throw new Error('File must be smaller than 1.8 MB');
    const content=await file.text();
    let events;
    const isFortigate=/\.(log|txt)$/i.test(file.name);
    if(isFortigate)events=content.split(/\r?\n/).filter(line=>line.trim());
    else if(file.name.toLowerCase().endsWith('.jsonl'))events=content.split(/\r?\n/).filter(line=>line.trim()).map(line=>JSON.parse(line));
    else{const parsed=JSON.parse(content);events=Array.isArray(parsed)?parsed:parsed.events?[...parsed.events]:[parsed];}
    const result=await post('/api/import',isFortigate?{fortigate_logs:events}:{events});
    notify(`Imported ${result.inserted} events`);
    await refreshData();
    await loadIndexStatus();
  }catch(error){notify(error.message,true);}
}
async function loadCollectors() {
  try {
    const info=await api('/api/collectors/status');
    for(const name of ['syslog','files','windows']) {
      const item=info.collectors[name],stateElement=$(`state-${name}`),control=$(`control-${name}`);
      stateElement.textContent=item.active?'Collecting':'Stopped';
      stateElement.classList.toggle('running',item.active);
      $(`count-${name}`).textContent=`${item.events.toLocaleString()} events collected this session`;
      $(`error-${name}`).textContent=item.error||'';
      control.textContent=item.active?'Stop collection':`Start ${name==='syslog'?'listener':name==='files'?'watcher':'Windows logs'}`;
      control.dataset.active=String(item.active);
      control.classList.toggle('primary',!item.active);
      control.classList.toggle('secondary',item.active);
      if(name==='windows')control.disabled=!info.windows_supported;
    }
    $('syslog-bind').textContent=`${info.syslog.host}:${info.syslog.port}`;
  } catch(error) { notify(error.message,true); }
}
async function toggleCollector(name,button) {
  button.disabled=true;
  try {
    const active=button.dataset.active==='true';
    await post(`/api/collectors/${active?'stop':'start'}`,{type:name});
    await loadCollectors();
    notify(`${name==='syslog'?'Syslog':name==='files'?'Log folder':'Windows events'} collector ${active?'stopped':'started'}`);
  } catch(error) {notify(error.message,true);await loadCollectors();}
  finally {if(name!=='windows'||navigator.platform.startsWith('Win')) button.disabled=false;}
}
window.addEventListener('DOMContentLoaded',()=>{
  document.querySelectorAll('[data-view]').forEach(button=>button.addEventListener('click',()=>displayView(button.dataset.view)));
  document.querySelectorAll('[data-go]').forEach(button=>button.addEventListener('click',()=>displayView(button.dataset.go)));
  document.querySelectorAll('[data-status]').forEach(button=>button.addEventListener('click',()=>{
    state.status=button.dataset.status;
    document.querySelectorAll('[data-status]').forEach(node=>node.classList.toggle('active',node===button));
    loadAlerts();
  }));
  let debounce;
  ['event-search','filter-source','filter-severity','filter-type'].forEach(id=>$(id).addEventListener(id==='event-search'?'input':'change',()=>{
    clearTimeout(debounce);state.page=1;debounce=setTimeout(loadEvents,180);
  }));
  $('page-prev').addEventListener('click',()=>{state.page=Math.max(1,state.page-1);loadEvents();});
  $('page-next').addEventListener('click',()=>{state.page++;loadEvents();});
  $('demo-top').addEventListener('click',generateDemo);
  $('demo-import').addEventListener('click',generateDemo);
  $('import-button').addEventListener('click',importFile);
  $('rebuild-index').addEventListener('click',rebuildIndex);
  $('collector-refresh').addEventListener('click',loadCollectors);
  $('test-syslog').addEventListener('click',async()=>{try{await post('/api/collectors/test-syslog',{});notify('Test syslog event sent. Check Event Explorer.');setTimeout(()=>{loadCollectors();refreshData();},500);}catch(error){notify(error.message,true);}});
  document.querySelectorAll('[data-collector]').forEach(button=>button.addEventListener('click',()=>toggleCollector(button.dataset.collector,button)));
  $('event-file').addEventListener('change',()=>{$('filename').textContent=$('event-file').files[0]?.name||'No file selected';});
  $('refresh').addEventListener('click',async()=>{if(state.timeMode==='relative')applyRelative();else if(['24h','7d','30d'].includes(state.timeMode))applyPreset(state.timeMode);else await refreshData();notify('Dashboard refreshed');});
  $('reset-button').addEventListener('click',async()=>{
    if(!window.confirm('Delete all local events and alerts?'))return;
    try{await post('/api/reset',{confirm:'RESET'});state.page=1;await refreshData();notify('Workspace cleared');}
    catch(error){notify(error.message,true);}
  });
  document.querySelectorAll('[data-range]').forEach(button=>button.addEventListener('click',()=>applyPreset(button.dataset.range)));
  $('apply-range').addEventListener('click',applyCustom);
  $('relative-form').addEventListener('submit',event=>{event.preventDefault();applyRelative();});
  $('trend-series').addEventListener('change',()=>{state.trendSeries=$('trend-series').value;state.hoverIndex=-1;$('chart-tooltip').classList.add('hidden');$('trend-total').textContent=`${state.timeline.reduce((sum,point)=>sum+point[state.trendSeries],0).toLocaleString()} matching ${$('trend-series').selectedOptions[0].textContent.toLowerCase()}`;drawTrend(state.timeline);});
  const chart=$('trend-chart');
  chart.addEventListener('mousemove',event=>showChartTooltip(nearestIndex(event)));
  chart.addEventListener('mouseleave',()=>showChartTooltip(-1));
  chart.addEventListener('click',event=>drilldown(state.timeline[nearestIndex(event)],state.trendSeries==='denied'?'firewall_deny':state.trendSeries==='failed'?'login_failed':''));
  chart.addEventListener('keydown',event=>{
    if(['ArrowLeft','ArrowRight'].includes(event.key)){
      event.preventDefault();
      const next=state.hoverIndex<0?0:state.hoverIndex+(event.key==='ArrowRight'?1:-1);
      showChartTooltip(Math.max(0,Math.min(state.timeline.length-1,next)));
    }
    if(['Enter',' '].includes(event.key)){
      event.preventDefault();
      drilldown(state.timeline[state.hoverIndex<0?0:state.hoverIndex],state.trendSeries==='denied'?'firewall_deny':state.trendSeries==='failed'?'login_failed':'');
    }
  });
  window.addEventListener('resize',()=>drawTrend(state.timeline));
  applyRelative();
  loadIndexStatus();
  loadCollectors();
  setInterval(()=>{if(state.view==='sources')loadCollectors();},5000);
  setInterval(()=>{
    if(document.visibilityState==='hidden')return;
    if(state.timeMode==='relative') {
      const amount=Number($('relative-count').value),unit=$('relative-unit').value;
      if(Number.isInteger(amount)&&amount>=1&&amount<=1000) {
        const end=new Date();state.end=end.toISOString();state.start=subtractCalendar(end,amount,unit).toISOString();
      }
    }
    updateExports();
    if(state.view==='overview')loadOverview();
    if(state.view==='events')loadEvents();
    if(state.view==='alerts')loadAlerts();
    if(state.view==='email')window.EmailDesk?.load();
  },12000);
});
