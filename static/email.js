(() => {
  const emailState = {page:1, size:25, total:0, mode:'eml', timeline:[], selected:-1, lastDetail:null, bucketDate:'', previousWindow:''};
  const filters = ['email-q','email-sender','email-ip','email-category','email-severity','email-status'];
  const node = (name, className='', content='') => {
    const element = document.createElement(name);
    if(className) element.className=className;
    element.textContent=content==null?'':String(content);
    return element;
  };
  const dateText = value => value ? value.replace('T',' ').slice(0,19) : 'Unknown';
  const formQuery = () => {
    const params=timeParameters();
    const map={'email-q':'q','email-sender':'sender','email-ip':'ip','email-category':'category','email-severity':'severity','email-status':'status'};
    Object.entries(map).forEach(([field,name])=>{const value=$(field).value.trim();if(value)params.set(name,value);});
    params.set('date_field',$('email-date-field').value);
    if(emailState.bucketDate){
      const from = new Date(emailState.bucketDate+'T00:00:00Z');
      const until = new Date(from.getTime()+86400000);
      const boundaryStart=state.start?new Date(state.start):null;
      const boundaryEnd=state.end?new Date(state.end):null;
      if(boundaryStart && boundaryStart>from)from.setTime(boundaryStart.getTime());
      if(boundaryEnd && boundaryEnd<until)until.setTime(boundaryEnd.getTime());
      params.set('from',from.toISOString());params.set('to',until.toISOString());
    }
    params.set('page',String(emailState.page));
    params.set('size',String(emailState.size));
    return params;
  };
  const metric = (id,value) => { $(id).textContent=Number(value||0).toLocaleString(); };
  async function snapshot(){
    try{
      const info=await api(`/api/email/stats?${timeParameters()}`);
      metric('email-overview-total',info.total);
      metric('email-overview-suspicious',info.suspicious);
      metric('email-overview-high',info.high_risk);
    }catch(error){notify(error.message,true);}
  }
  async function load(){
    const currentWindow=(state.start||'')+'|'+(state.end||'');
    if(emailState.previousWindow!==currentWindow){
      emailState.bucketDate='';emailState.previousWindow=currentWindow;
      emailState.page=1;
    }
    await Promise.all([loadStats(),loadCases()]);
  }
  async function loadStats(){
    try{
      const parameters=timeParameters();
      parameters.set('date_field',$('email-date-field').value);
      const info=await api('/api/email/stats?'+parameters);
      metric('email-total',info.total);
      metric('email-suspicious',info.suspicious);
      metric('email-high',info.high_risk);
      emailState.timeline=info.timeline;
      emailState.selected=-1;
      drawChart();
      const root=$('email-categories');root.replaceChildren();
      if(!info.categories.length){root.append(node('div','empty','No email investigations in this range.'));return;}
      const top=Math.max(...info.categories.map(x=>x.value),1);
      for(const category of info.categories){
        const button=node('button','source-button');button.type='button';button.title='Filter investigations: '+category.name;
        const heading=node('div','bar-head');heading.append(node('span','',category.name),node('span','',category.value));
        const track=node('div','bar-track'),fill=node('div','bar-fill');fill.style.width=`${category.value/top*100}%`;
        track.append(fill);button.append(heading,track);root.append(button);
        button.addEventListener('click',()=>{$('email-category').value=category.name;emailState.page=1;loadCases();});
      }
    }catch(error){notify(error.message,true);}
  }
  async function loadCases(){
    try{
      const data=await api(`/api/email/investigations?${formQuery()}`);
      emailState.total=data.total;
      $('email-count').textContent=`${data.total.toLocaleString()} investigations${emailState.bucketDate?' · '+emailState.bucketDate+' (UTC)':''}`;
      $('email-clear-day').hidden=!emailState.bucketDate;
      $('email-page').textContent=String(emailState.page);
      $('email-prev').disabled=emailState.page<=1;
      $('email-next').disabled=emailState.page*emailState.size>=data.total;
      const tbody=$('email-body');tbody.replaceChildren();
      if(!data.items.length){const row=node('tr'),cell=node('td','','No email investigations match your filters');cell.colSpan=8;row.append(cell);tbody.append(row);return;}
      for(const item of data.items){
        const row=node('tr'),sender=node('td');
        const senderName=node('strong','',item.sender||'Unknown sender');
        sender.append(senderName,node('small','table-subtext',item.originating_ip||'Origin IP unavailable'));
        const risk=node('td');risk.append(node('span',`tag ${item.severity.toLowerCase()}`,`${item.severity} · ${item.score}/100`));
        const status=node('td','',item.status);
        const action=node('td');const button=node('button','button secondary','Investigate');button.type='button';
        button.addEventListener('click',()=>openCase(item.id));action.append(button);
        row.append(node('td','',`EM-${String(item.id).padStart(6,'0')}`),node('td','',dateText(item.analysed_at)),sender,node('td','',item.subject||'(No subject)'),node('td','',item.categories.join(' · ')),risk,status,action);
        tbody.append(row);
      }
    }catch(error){notify(error.message,true);}
  }
  function card(title,content,secondary=''){
    const section=node('section','email-detail-section');section.append(node('h3','',title));
    if(secondary)section.append(node('p','email-muted',secondary));
    if(content instanceof Node)section.append(content);
    else section.append(node('p','',content));
    return section;
  }
  function definition(items){
    const root=node('dl','email-definitions');
    for(const [label,value] of items){root.append(node('dt','',label),node('dd','',value==null||value===''?'Not reported':value));}
    return root;
  }
  function blocks(values){
    const root=node('div','email-lines');
    if(!values.length)root.append(node('p','email-muted','No entries supplied.'));
    values.forEach((value,index)=>{const line=node('div','email-line');line.append(node('strong','',String(index+1)),node('code','',value));root.append(line);});
    return root;
  }
  function renderDetail(item){
    emailState.lastDetail=item;
    $('email-investigation-title').textContent=`EM-${String(item.id).padStart(6,'0')} · ${item.subject||'(No subject)'}`;
    const root=$('email-detail-content');root.replaceChildren();
    const summary=node('div','email-assessment');
    summary.append(node('span',`tag ${item.severity.toLowerCase()}`,`${item.severity} · ${item.score}/100`),node('strong','',item.categories.join(' · ')),node('p','',item.assessment_note));
    root.append(summary);
    const statusRow=node('div','email-case-actions');statusRow.append(node('label','',`Status · ${item.status}`));
    const dropdown=node('select');dropdown.setAttribute('aria-label','Case investigation status');
    for(const status of ['New','Investigating','Resolved','False Positive']){
      const option=node('option','',status);option.value=status;dropdown.append(option);
    }
    dropdown.value=item.status;
    const save=node('button','button primary','Save status');
    save.addEventListener('click',async()=>{
      save.disabled=true;
      try{await post(`/api/email/investigations/${item.id}/status`,{status:dropdown.value});notify('Investigation status updated');await openCase(item.id);await loadCases();}
      catch(error){notify(error.message,true);}finally{save.disabled=false;}
    });
    statusRow.append(dropdown,save);root.append(statusRow);
    root.append(card('Email metadata',definition([
      ['From',item.sender],['To',item.recipient],['Sender domain',item.sender_domain],['Originating IP (unverified)',item.originating_ip],
      ['SMTP HELO (unverified)',item.helo],['Return-Path domain',item.envelope_domain],['Reply-To domain',item.reply_domain],
      ['Message-ID',item.message_id],['Original Date header (UTC)',dateText(item.received_at)],['Analysed at (UTC)',dateText(item.analysed_at)]
    ])));
    root.append(card('Reported authentication',definition(Object.entries(item.auth).map(([key,value])=>[key.toUpperCase(),String(value).toUpperCase()])), 'These values appear in uploaded headers and have not been confirmed by a trusted mail server.'));
    const evidence=node('div','email-evidence');
    if(!item.evidence.length)evidence.append(node('p','email-muted','No configured detection rules triggered. This does not prove that the email is safe.'));
    item.evidence.forEach(entry=>{
      const row=node('div','email-evidence-item');const header=node('div','email-evidence-title');header.append(node('strong','',entry.title),node('span','email-points',`+${entry.points}`));
      row.append(header,node('p','',entry.explanation),node('small','',`${entry.rule} · ${entry.basis}`));evidence.append(row);
    });
    root.append(card('Detection evidence',evidence));
    root.append(card('Email routing · Received headers',blocks(item.routing),'Routing headers may have been prepended or forged before reaching a trusted receiver.'));
    root.append(card('Reported authentication header lines',blocks(item.auth_reports)));
    root.append(card('Extracted URLs · not opened',blocks(item.urls)));
    const raw=node('pre','email-raw',item.raw_headers);root.append(card('Original supplied headers',raw));
    if(item.body_excerpt)root.append(card('Plain-text content preview',node('pre','email-raw',item.body_excerpt)));
    if(item.defects.length)root.append(card('Parser warnings',blocks(item.defects)));
  }
  async function openCase(id){
    try{
      const detail=await api(`/api/email/investigations/${id}`);
      renderDetail(detail);$('email-modal').hidden=false;$('email-close').focus();
    }catch(error){notify(error.message,true);}
  }
  async function submit(){
    const button=$('email-analyse');button.disabled=true;button.textContent='Analysing…';
    try{
      let content;
      if(emailState.mode==='eml'){
        const file=$('email-file').files[0];
        if(!file)throw new Error('Select an .eml file first');
        if(!file.name.toLowerCase().endsWith('.eml'))throw new Error('Only .eml files are supported');
        if(file.size>1000000 || file.size===0)throw new Error('Email must be between 1 byte and 1 MB');
        const bytes=new Uint8Array(await file.arrayBuffer());
        let binary='';for(let i=0;i<bytes.length;i+=32768)binary+=String.fromCharCode(...bytes.subarray(i,i+32768));
        content=btoa(binary);
      }else{
        content=$('email-header-text').value;
        if(!content.trim())throw new Error('Paste raw email headers first');
        if(new TextEncoder().encode(content).length>1000000)throw new Error('Headers exceed 1 MB');
      }
      const response=await post('/api/email/analyse',{mode:emailState.mode,content});
      notify(response.duplicate?'Existing investigation reopened':'Email analysis completed');
      if(state.timeMode==='relative'){
        const end=new Date();
        const count=Number($('relative-count').value),unit=$('relative-unit').value;
        if(Number.isInteger(count)&&count>0){
          state.end=end.toISOString();state.start=subtractCalendar(end,count,unit).toISOString();
        }
      }
      emailState.bucketDate='';emailState.page=1;await load();await snapshot();await openCase(response.id);
    }catch(error){notify(error.message,true);}finally{button.disabled=false;button.textContent='Analyse Email';}
  }
  function drawChart(){
    const canvas=$('email-trend');if(!canvas || !$('view-email') || $('view-email').classList.contains('hidden'))return;
    const width=canvas.clientWidth||600;
    const height=200, ratio=window.devicePixelRatio||1;
    canvas.width=Math.round(width*ratio);canvas.height=Math.round(height*ratio);
    const context=canvas.getContext('2d');context.setTransform(ratio,0,0,ratio,0,0);
    context.clearRect(0,0,width,height);
    const data=emailState.timeline;
    context.strokeStyle='#34445f';context.lineWidth=1;
    for(let i=0;i<=4;i++){const y=15+i*40;context.beginPath();context.moveTo(24,y);context.lineTo(width-10,y);context.stroke();}
    if(!data.length){context.font='12px system-ui';context.fillStyle='#9fb2d1';context.fillText('No email investigations for this date range',25,110);return;}
    const max=Math.max(1,...data.map(x=>x.value));const usable=width-48;const band=usable/data.length;
    data.forEach((item,index)=>{
      const barWidth=Math.max(3,Math.min(45,band*.72));const h=Math.max(3,145*item.value/max);
      const x=24+index*band+(band-barWidth)/2, y=180-h;
      context.fillStyle=index===emailState.selected?'#4fd6cc':'#718cfc';
      context.fillRect(x,y,barWidth,h);
    });
    const value=emailState.selected>=0?data[emailState.selected]:data[data.length-1];
    $('email-trend-tip').textContent=`${value.date} · ${value.value} email${value.value===1?'':'s'}${emailState.selected<0?' (latest)':''}`;
  }
  function bucketIndex(event){
    const canvas=$('email-trend'),items=emailState.timeline;
    if(!items.length)return -1;
    const rect=canvas.getBoundingClientRect();const x=event.clientX-rect.left-24;
    return Math.min(items.length-1,Math.max(0,Math.floor(x/((rect.width-48)/items.length))));
  }
  function selectBucket(index,investigate=false){
    if(index<0||index>=emailState.timeline.length)return;
    emailState.selected=index;drawChart();
    if(investigate){
      emailState.bucketDate=emailState.timeline[index].date;
      emailState.page=1;
      loadCases();
    }
  }
  document.addEventListener('DOMContentLoaded',()=>{
    $('email-mode-file').addEventListener('click',()=>setMode('eml'));
    $('email-mode-headers').addEventListener('click',()=>setMode('headers'));
    function setMode(mode){emailState.mode=mode; $('email-file-panel').classList.toggle('hidden',mode!=='eml');$('email-headers-panel').classList.toggle('hidden',mode!=='headers');$('email-mode-file').classList.toggle('active',mode==='eml');$('email-mode-headers').classList.toggle('active',mode==='headers');}
    $('email-analyse').addEventListener('click',submit);
    $('email-close').addEventListener('click',()=>{$('email-modal').hidden=true;});
    $('email-overlay').addEventListener('click',()=>{$('email-modal').hidden=true;});
    document.addEventListener('keydown',event=>{if(event.key==='Escape'&&!$('email-modal').hidden)$('email-modal').hidden=true;});
    let debounce;
    filters.forEach(id=>$(id).addEventListener(id==='email-q'||id==='email-sender'||id==='email-ip'?'input':'change',()=>{clearTimeout(debounce);emailState.page=1;debounce=setTimeout(loadCases,220);}));
    $('email-date-field').addEventListener('change',()=>{emailState.page=1;load();});
    $('email-prev').addEventListener('click',()=>{emailState.page=Math.max(1,emailState.page-1);loadCases();});
    $('email-next').addEventListener('click',()=>{emailState.page++;loadCases();});
    $('email-reset-filters').addEventListener('click',()=>{filters.forEach(id=>$(id).value='');emailState.bucketDate='';emailState.page=1;load();});
    $('email-clear-day').addEventListener('click',()=>{emailState.bucketDate='';emailState.page=1;loadCases();});
    $('email-trend').addEventListener('mousemove',event=>selectBucket(bucketIndex(event)));
    $('email-trend').addEventListener('click',event=>selectBucket(bucketIndex(event),true));
    $('email-trend').addEventListener('keydown',event=>{if(event.key==='ArrowRight'||event.key==='ArrowLeft'){event.preventDefault();selectBucket(Math.max(0,Math.min(emailState.timeline.length-1,emailState.selected+(event.key==='ArrowRight'?1:-1))));}if(event.key==='Enter'||event.key===' '){event.preventDefault();selectBucket(emailState.selected<0?0:emailState.selected,true);}});
    window.addEventListener('resize',()=>{if(state.view==='email')drawChart();});
  });
  window.EmailDesk={load,snapshot};
})();
