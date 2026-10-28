(() => {
  let lastResult = null;
  let saved = [];
  let buckets = [];
  let busy = false;
  const el = id => document.getElementById(id);
  const element = (tag, text, cls = '') => {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (cls) node.className = cls;
    return node;
  };
  async function run() {
    if (busy) return;
    busy = true;
    const button = el('lab-run');
    button.disabled = true;
    button.textContent = 'Searching…';
    try {
      const query = el('lab-query').value.trim();
      const params = timeParameters();
      params.set('q', query);
      const result = await api(`/api/search/run?${params}`);
      lastResult = result;
      render(result);
    } catch (error) {
      notify(error.message, true);
      el('lab-summary').textContent = error.message;
    } finally {
      button.disabled = false;
      button.textContent = '⌕ Run search';
      busy = false;
    }
  }
  function render(result) {
    el('lab-mode').textContent = result.mode.toUpperCase();
    el('lab-summary').textContent = `${result.matched_events.toLocaleString()} matching events · ${result.result_count.toLocaleString()} results · ${result.candidates.toLocaleString()} candidate records`;
    el('lab-warning').hidden = !result.truncated;
    el('lab-warning').textContent = result.truncated ? 'Search evaluated the first 15,000 records matching the indexed prefilter. Narrow the date range or add indexed fields for complete results.' : '';
    const headings = el('lab-table-head');
    const body = el('lab-table-body');
    headings.replaceChildren();
    body.replaceChildren();
    const headRow = element('tr');
    result.columns.forEach(field => headRow.append(element('th', field)));
    headings.append(headRow);
    result.items.forEach((item, n) => {
      const row = element('tr', null, 'lab-result-row');
      if (result.mode === 'events') {
        row.tabIndex = 0;
        row.setAttribute('role', 'button');
        row.setAttribute('aria-label', `Inspect event ${item.id}`);
        const open = () => {
          el('lab-json').textContent = JSON.stringify(item, null, 2);
          el('lab-inspector').hidden = false;
          el('lab-inspector').scrollIntoView({behavior:'smooth',block:'nearest'});
        };
        row.addEventListener('click', open);
        row.addEventListener('keydown', event => { if (event.key === 'Enter') open(); });
      }
      result.columns.forEach(field => {
        const value = item[field];
        const cell = element('td', value === null || value === undefined || value === '' ? '—' : typeof value === 'object' ? JSON.stringify(value) : value);
        if (field === 'message') cell.classList.add('lab-message');
        row.append(cell);
      });
      body.append(row);
    });
    if (!result.items.length) {
      const row = element('tr'), cell = element('td', 'No results for this search.');
      cell.colSpan = result.columns.length;
      row.append(cell);
      body.append(row);
    }
    el('lab-result-note').textContent = result.result_count > result.items.length ? `Showing the first ${result.items.length} results. Narrow the query for more detail.` : result.mode === 'events' ? 'Select an event row to inspect all indexed and extracted fields.' : 'Run a new query or select an index to investigate further.';
    el('lab-inspector').hidden = true;
    displayFacets(result.index_facets, result.field_facets);
    drawChart(result);
  }
  function displayFacets(facets, fields) {
    const area = el('lab-facets');
    area.replaceChildren();
    if (!facets.length) area.append(element('p','No indexed events in the selected time range.'));
    facets.forEach(item => {
      const button = element('button', null, 'lab-facet');
      button.type = 'button';
      button.append(element('span', item.index), element('strong', item.count.toLocaleString()));
      button.addEventListener('click', () => {
        const query = el('lab-query').value.replace(/\bindex(?:_name)?=("[^"]*"|\S+)/gi, '').trim();
        el('lab-query').value = `index=${item.index}${query ? ' ' + query : ''}`;
        run();
      });
      area.append(button);
    });
    const fieldArea=el('lab-field-facets');
    fieldArea.replaceChildren();
    for(const field of ['source','sourcetype','severity']) {
      const title=element('h4',field === 'sourcetype' ? 'Source types' : field==='source' ? 'Sources' : 'Severities');
      fieldArea.append(title);
      const group=element('div',null,'search-facets');
      (fields?.[field] || []).forEach(item=>{
        const button=element('button',null,'lab-facet');
        button.type='button';
        button.append(element('span',item.value || '(empty)'),element('strong',item.count.toLocaleString()));
        button.addEventListener('click',()=>{
          const escapedField=field.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
          const without=el('lab-query').value.replace(new RegExp('\\b'+escapedField+'=("[^"\\n]*"|\\S+)','gi'),'').trim();
          el('lab-query').value=`${field}=${item.value}${without?' '+without:''}`;
          run();
        });
        group.append(button);
      });
      fieldArea.append(group);
    }
  }
  function drawChart(result) {
    const wrap = el('lab-chart-wrap');
    wrap.hidden = result.mode !== 'timechart';
    if (wrap.hidden) return;
    buckets = result.chart;
    const canvas = el('lab-chart');
    const width = Math.max(340, canvas.parentElement.clientWidth - 10);
    const height = 195;
    const dpr = window.devicePixelRatio || 1;
    canvas.style.width = '100%';
    canvas.style.height = `${height}px`;
    canvas.width = Math.round(width*dpr);
    canvas.height = Math.round(height*dpr);
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr,dpr);
    ctx.clearRect(0,0,width,height);
    const pad = {left:35,right:10,top:14,bottom:30};
    const chartWidth = width-pad.left-pad.right, chartHeight=height-pad.top-pad.bottom;
    const max = Math.max(1,...buckets.map(item=>item.count));
    ctx.lineWidth=1;
    ctx.strokeStyle='#354964';
    for(let n=0;n<=4;n++) {
      const y=pad.top+chartHeight*n/4;
      ctx.beginPath();ctx.moveTo(pad.left,y);ctx.lineTo(width-pad.right,y);ctx.stroke();
      ctx.fillStyle='#94a9c6';ctx.font='10px system-ui';ctx.textAlign='right';
      ctx.fillText(String(Math.round(max*(4-n)/4)),pad.left-7,y+3);
    }
    if (!buckets.length) return;
    const slot=chartWidth/buckets.length;
    for(let i=0;i<buckets.length;i++) {
      const b=buckets[i];
      const bar=Math.max(1,(b.count/max)*chartHeight);
      ctx.fillStyle=i%2 ? '#4bd2c7' : '#6481f6';
      ctx.fillRect(pad.left+i*slot+slot*.13,pad.top+chartHeight-bar,Math.max(1,slot*.74),bar);
    }
    ctx.fillStyle='#9caeca';ctx.textAlign='left';ctx.font='10px system-ui';
    ctx.fillText(buckets[0].timestamp.slice(0,16).replace('T',' '),pad.left,height-7);
    ctx.textAlign='right';
    ctx.fillText(buckets[buckets.length-1].timestamp.slice(0,16).replace('T',' '),width-pad.right,height-7);
  }
  function bucketFromPointer(evt) {
    const canvas=el('lab-chart');
    const rect=canvas.getBoundingClientRect();
    const x=(evt.clientX-rect.left)*(canvas.width/(window.devicePixelRatio || 1))/rect.width;
    const usable=(canvas.width/(window.devicePixelRatio || 1))-45;
    return Math.max(0,Math.min(buckets.length-1,Math.floor((x-35)/usable*buckets.length)));
  }
  async function fetchSaved() {
    try {
      saved = (await api('/api/search/saved')).items;
      const root=el('lab-saved');root.replaceChildren();
      if (!saved.length) root.append(element('p', 'No saved searches yet.'));
      saved.forEach(item => {
        const box=element('div',null,'lab-saved-entry');
        const use=element('button',item.name,'lab-saved-use');
        use.title=item.query;
        use.addEventListener('click',()=>{el('lab-query').value=item.query;run();});
        const remove=element('button','×','lab-saved-remove');
        remove.title='Delete saved search';remove.setAttribute('aria-label',`Delete ${item.name}`);
        remove.addEventListener('click',async()=>{
          try { await post('/api/search/saved/delete',{id:item.id});await fetchSaved();notify('Search deleted'); }
          catch(error){notify(error.message,true);}
        });
        box.append(use,remove);root.append(box);
      });
    } catch(error) { notify(error.message,true); }
  }
  function csvExport() {
    if (!lastResult) return notify('Run a search first',true);
    const clean = value => {
      let text=typeof value === 'object' && value!==null ? JSON.stringify(value) : String(value ?? '');
      if (/^[=+\-@]/.test(text)) text="'"+text;
      return `"${text.replace(/"/g,'""')}"`;
    };
    const lines=[lastResult.columns.map(clean).join(',')];
    lastResult.items.forEach(row=>lines.push(lastResult.columns.map(f=>clean(row[f])).join(',')));
    const blob=new Blob(['\uFEFF'+lines.join('\r\n')],{type:'text/csv;charset=utf-8'});
    const url=URL.createObjectURL(blob), anchor=document.createElement('a');
    anchor.href=url;anchor.download='sentinel-search-results.csv';anchor.click();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  function setup() {
    el('lab-form').addEventListener('submit',event=>{event.preventDefault();run();});
    el('lab-help').addEventListener('click',()=>{el('lab-guide').hidden=!el('lab-guide').hidden;});
    document.querySelectorAll('[data-lab-example]').forEach(button=>button.addEventListener('click',()=>{el('lab-query').value=button.dataset.labExample;run();}));
    el('lab-save').addEventListener('click',async()=>{
      const name=prompt('Name this saved search:');
      if(name===null)return;
      try { await post('/api/search/saved',{name,query:el('lab-query').value});await fetchSaved();notify('Search saved'); }
      catch(error){notify(error.message,true);}
    });
    el('lab-export').addEventListener('click',csvExport);
    el('lab-close-inspector').addEventListener('click',()=>{el('lab-inspector').hidden=true;});
    el('lab-chart').addEventListener('mousemove',event=>{
      if(!buckets.length)return;
      const b=buckets[bucketFromPointer(event)];
      el('lab-chart-label').textContent=`${b.timestamp.replace('T',' ').slice(0,19)} UTC · ${b.count} events · Click to focus this bucket`;
    });
    el('lab-chart').addEventListener('click',event=>{
      if(!buckets.length)return;
      const b=buckets[bucketFromPointer(event)];
      const span=/span=(1h|6h|1d|1w)/.exec(el('lab-query').value)?.[1] || '1h';
      const duration={'1h':3600000,'6h':21600000,'1d':86400000,'1w':604800000}[span];
      const start=new Date(b.timestamp);
      state.start=start.toISOString();state.end=new Date(start.getTime()+duration).toISOString();state.timeMode='custom';
      document.querySelectorAll('[data-range]').forEach(node=>node.classList.toggle('active',node.dataset.range==='custom'));
      el('range-custom').classList.remove('hidden');
      el('time-from').value=localInput(state.start);el('time-to').value=localInput(state.end);
      el('range-summary').textContent=`Focused search · ${start.toLocaleString()} to ${new Date(state.end).toLocaleString()}`;
      run();
    });
    window.addEventListener('resize',()=>{if(lastResult?.mode==='timechart')drawChart(lastResult);});
    fetchSaved();
  }
  window.SearchLab={load:run};
  window.addEventListener('DOMContentLoaded',setup);
})();
