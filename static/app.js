const $ = (id) => document.getElementById(id);
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const hexOffset = (n) => `0x${Number(n).toString(16).toUpperCase().padStart(4, '0')}`;
const formatBytes = (n) => Number(n).toLocaleString();
const storeLocal = (k, v) => { try { localStorage.setItem(k, v); } catch {} };
const readLocal = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const state = {history: [], active: null, bytes: [], selected: new Set(), comparison: null, view: 'tree',
  range: null, anchor: 0, cursor: 0, node: null, collapsed: new Set(), visibleRows: [], drag: false,
  busy: false, request: 0, menuReturn: null, maxBytes: 262144, dirty: false};
const sampleJson = JSON.stringify({device: 'sensor-01', seq: 42, status: 'online', readings: {temperature: 23.75, voltage: 3.3, current: 0.125}, channels: [120,118,121,119], enabled: true}, null, 2);
const sampleHex = 'ff1cff1ca6666465766963656973656e736f722d303163736571182a66737461747573666f6e6c696e656872656164696e6773a36b74656d7065726174757265f94df067766f6c74616765fb400a6666666666666763757272656e74f93000686368616e6e656c7384187818761879187767656e61626c6564f5ffff';

class VirtualList {
  constructor(element, height, render) {
    this.element = element; this.height = height; this.renderRow = render; this.data = [];
    element.innerHTML = '<div class="virtual-spacer"><div class="virtual-items"></div></div>';
    this.spacer = element.firstElementChild; this.items = this.spacer.firstElementChild;
    element.addEventListener('scroll', () => this.render(), {passive:true});
    new ResizeObserver(() => this.render()).observe(element);
  }
  set(data, preserve = false) {
    this.data = data; this.spacer.style.height = `${data.length * this.height}px`;
    if (!preserve) this.element.scrollTop = 0;
    this.render();
  }
  render() {
    const first = Math.max(0, Math.floor(this.element.scrollTop / this.height) - 5);
    const last = Math.min(this.data.length, first + Math.ceil(this.element.clientHeight / this.height) + 12);
    this.items.style.transform = `translateY(${first * this.height}px)`;
    this.items.innerHTML = this.data.slice(first,last).map((r, i) => this.renderRow(r, first+i)).join('');
  }
  scrollTo(index) {
    const top = index * this.height;
    if (top < this.element.scrollTop || top + this.height > this.element.scrollTop + this.element.clientHeight) {
      this.element.scrollTop = Math.max(0, top - this.element.clientHeight * .35);
    }
    this.render();
  }
}

function status(text, error = false) {
  $('statusMessage').textContent = text;
  $('statusMessage').classList.toggle('error', error);
}
let toastTimer;
function toast(message) {
  $('toast').textContent = message; $('toast').hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => $('toast').hidden = true, 2600);
}
async function api(path, body, method = body === undefined ? 'GET' : 'POST') {
  const response = await fetch(path, {method, headers:body === undefined ? {} : {'Content-Type':'application/json'}, body:body === undefined ? undefined : JSON.stringify(body)});
  if (!response.ok) {
    const result = await response.json().catch(() => ({}));
    throw new Error(result.error || `HTTP ${response.status}`);
  }
  return response.status === 204 ? null : response.json();
}
function safely(fn) {
  return (...args) => Promise.resolve().then(() => fn(...args)).catch(error => {status(error.message, true); toast(error.message); console.error(error);});
}
async function copy(text) {
  const value = String(text);
  try {
    if (!navigator.clipboard?.writeText) throw new Error('Clipboard API unavailable');
    await navigator.clipboard.writeText(value);
  } catch {
    // Clipboard API is often unavailable on self-hosted LAN HTTP origins.
    const el = document.createElement('textarea'); el.value = value;
    el.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0'; document.body.append(el);
    const previous = document.activeElement; el.focus(); el.select();
    const ok = document.execCommand('copy'); el.remove(); previous?.focus?.();
    if (!ok) throw new Error('コピーできませんでした。ブラウザーの権限を確認してください');
  }
  toast('コピーしました');
}
function hexText(start = 0, end = state.bytes.length, spaced = true) {
  return state.bytes.slice(start, end).join(spaced ? ' ' : '').toUpperCase();
}
function selectedHex(spaced = true) {
  return state.range ? hexText(state.range[0], state.range[1], spaced) : hexText(0, state.bytes.length, spaced);
}
function base64FromHex(hex) {
  let binary = '';
  for (let p=0;p<hex.length;p+=2) binary += String.fromCharCode(parseInt(hex.slice(p,p+2),16));
  return btoa(binary);
}
function download(path) {
  const link = document.createElement('a'); link.href = path; link.download = ''; document.body.append(link); link.click(); link.remove();
}
function exportRecord(record, format) {
  download(`/api/history/${record.id}/export?format=${format}`);
}

const hexList = new VirtualList($('hexView'), 24, (_, index) => {
  const start = index * 16, selected = state.active?.result.selected;
  let bytes = '';
  for (let i=start;i<Math.min(start+16,state.bytes.length);i++) {
    const active = state.range && i>=state.range[0] && i<state.range[1];
    const parsed = selected && i>=selected.offset && i<selected.end;
    const header = active && state.node && i>=state.node.start && i<state.node.header;
    bytes += `<span class="hex-byte${parsed?' parsed':''}${active?' selected':''}${header?' header':''}" data-byte="${i}">${state.bytes[i].toUpperCase()}</span>`;
  }
  const ascii = state.bytes.slice(start,start+16).map(v => {const n=parseInt(v,16); return n>=32 && n<127 ? String.fromCharCode(n) : '·';}).join('');
  return `<div class="hex-row"><span class="hex-offset">${start.toString(16).toUpperCase().padStart(8,'0')}</span><span class="hex-bytes">${bytes}</span><span class="hex-ascii">${escape(ascii)}</span></div>`;
});
const treeList = new VirtualList($('treeView'), 26, row => {
  const active = state.node?.id === row.id;
  const toggle = row.children ? (state.collapsed.has(row.id) ? '▸' : '▾') : '';
  return `<div class="tree-row${active?' active':''}" data-node="${row.id}" role="treeitem" tabindex="${active?0:-1}" aria-level="${row.depth+1}" aria-selected="${active}"${row.children?` aria-expanded="${!state.collapsed.has(row.id)}"`:''}>
    <span class="tree-main" style="--depth:${row.depth}"><button class="tree-toggle" tabindex="-1" data-toggle="${row.id}" aria-label="${state.collapsed.has(row.id)?'展開':'折りたたむ'}">${toggle}</button><span class="tree-name" title="${escape(row.display_path || row.path)}">${escape(row.label)}</span><span class="tree-value ${row.type}" title="${escape(row.value)}">${escape(row.value)}</span></span>
    <span class="type-badge ${row.type}">${row.type}${row.indefinite?' ∞':''}</span><span class="tree-offset">${hexOffset(row.start).slice(2)}</span><span class="tree-bytes">${row.end-row.start}</span></div>`;
});
const candidateList = new VirtualList($('candidateList'), 24, (row,index) => {
  const active = state.active?.result.selected.offset === row.offset;
  return `<div class="candidate-row${active?' active':''}" data-candidate="${row.offset}" role="button" tabindex="0" title="${hexOffset(row.offset)}から${row.consumed}バイト / ${row.hits}ヒット"><span>${index===0?'★':index+1}</span><span>${hexOffset(row.offset)}</span><span>${formatBytes(row.hits)}</span><span>${formatBytes(row.consumed)}</span><span>${row.items}</span><span>${row.complete?'✓':'—'}</span></div>`;
});
const diffLabels = {added:'追加',removed:'削除',changed:'変更',encoding:'符号',same:'一致'};
const compareList = new VirtualList($('compareView'), 26, row => {
  let left, right, path;
  if (row.byte) {
    path = hexOffset(row.offset); left = row.left; right = row.right;
  } else if (row.line) {
    path = `L${row.index+1}`; left = row.left; right = row.right;
  } else {
    path = row.left?.display_path || row.right?.display_path || row.path;
    left = row.left ? `${row.left.value}  · ${row.left.type} @${hexOffset(row.left.start)}` : '—';
    right = row.right ? `${row.right.value}  · ${row.right.type} @${hexOffset(row.right.start)}` : '—';
  }
  return `<div class="compare-row ${row.status}" data-diff="${escape(path)}"><span title="${escape(path)}"><span class="diff-symbol">${diffLabels[row.status]}</span><span class="diff-path">${escape(path)}</span></span><span title="${escape(left)}">${escape(left)}</span><span title="${escape(right)}">${escape(right)}</span></div>`;
});

function renderHistory() {
  const query = $('historySearch').value.toLowerCase();
  const history = state.history.filter(r => `${r.title} ${r.format} ${r.size} ${r.hits}`.toLowerCase().includes(query));
  $('historyCount').textContent = state.history.length;
  $('historyList').innerHTML = history.length ? history.map(r => {
    const date = new Date(r.created);
    const time = date.toLocaleTimeString('ja-JP',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
    const day = date.toLocaleDateString('ja-JP',{month:'2-digit',day:'2-digit'});
    return `<div class="history-item${state.active?.id===r.id?' active':''}${state.selected.has(r.id)?' checked':''}" data-history="${r.id}" tabindex="0" title="${escape(r.title)} · ${escape(date.toLocaleString())}">
      <input type="checkbox" data-check="${r.id}" aria-label="${escape(r.title)}を比較に選択" ${state.selected.has(r.id)?'checked':''}>
      <div><div class="history-title">${r.pinned?'<span class="pin-mark">◆</span>':''}<strong>${escape(r.title)}</strong></div><div class="history-meta"><span>${day} ${time}</span><span>${formatBytes(r.size)} B</span></div><div class="history-meta"><span>${r.format.toUpperCase()} · ${hexOffset(r.offset)}</span><span class="hit">${r.hits} hits</span></div></div></div>`;
  }).join('') : `<div class="history-empty">${query?'一致する履歴はありません':'解析結果はここに保存されます。'}</div>`;
  $('compareButton').disabled = state.selected.size !== 2;
  $('compareHint').textContent = state.selected.size ? `${state.selected.size} 件選択` : '2件選択して比較';
}
async function refreshHistory() {
  state.history = await api('/api/history');
  const ids = new Set(state.history.map(x=>x.id));
  for (const id of state.selected) if (!ids.has(id)) state.selected.delete(id);
  renderHistory();
}
function toggleCompare(id, checked = !state.selected.has(id)) {
  if (checked) {
    if (state.selected.size === 2) state.selected.delete(state.selected.values().next().value);
    state.selected.add(id);
  } else state.selected.delete(id);
  renderHistory();
}
function setCompareSlot(id, side) {
  const ids = [...state.selected];
  const other = ids[side === 0 ? 1 : 0];
  state.selected = new Set(side === 0 ? [id, ...(other && other!==id?[other]:[])] : [...(other&&other!==id?[other]:[]),id]);
  renderHistory();
  toast(`${side===0?'比較元 A':'比較先 B'}に設定しました`);
}

function markDirty() {
  state.dirty = true;
  if (state.active) { $('resultState').textContent = '前回の結果 · 入力変更あり'; $('resultState').classList.remove('good'); }
  updateInputInfo();
}
function updateInputInfo() {
  const text = $('sourceInput').value;
  $('inputInfo').textContent = `${$('inputFormat').selectedOptions[0].text} · ${formatBytes(text.length)} 文字${state.dirty?' · 未解析':''}`;
  storeLocal('cbor.draft', JSON.stringify({text,format:$('inputFormat').value,title:$('analysisTitle').value,scan:$('scanToggle').checked,sequence:$('sequenceToggle').checked,offset:$('manualOffset').value}));
}
function setSource(text, format = 'hex', title = '', {scan=true, sequence=false, offset=0} = {}) {
  $('sourceInput').value = text; $('sourceInput').scrollTop = 0; $('inputFormat').value = format; $('analysisTitle').value = title;
  $('scanToggle').checked = scan; $('sequenceToggle').checked = sequence; $('manualOffset').value = offset;
  $('manualOffset').disabled = scan; markDirty();
}
function setRecord(record, updateInput = true) {
  state.active = record; state.bytes = record.hex.match(/../g) || [];
  state.range = null; state.node = null; state.collapsed.clear();
  if (updateInput) {
    setSource(record.source, record.format, record.title, {scan:record.mode==='scan', sequence:!!record.result.sequence, offset:record.requested_offset});
    state.dirty = false; updateInputInfo();
  }
  const s = record.result.selected;
  $('metricOffset').textContent = hexOffset(s.offset);
  $('metricHits').textContent = formatBytes(s.hits);
  $('metricBytes').textContent = `${formatBytes(s.consumed)} B`;
  $('metricItems').textContent = s.items;
  $('resultState').textContent = !s.hits ? '一致なし' : record.result.best?.offset===s.offset ? '最多ヒット' : '選択候補';
  $('resultState').classList.toggle('good', !!s.hits);
  if (state.dirty) { $('resultState').textContent = '前回の結果 · 入力変更あり'; $('resultState').classList.remove('good'); }
  $('byteCount').textContent = `${formatBytes(record.result.size)} B`;
  $('treeCount').textContent = `${s.rows.length} 要素`;
  $('candidateCount').textContent = record.result.candidates.length;
  $('exportButton').disabled = false;
  $('emptyResult').hidden = true;
  $('scanInfo').textContent = `${formatBytes(record.result.tested)} OFFSET${record.result.tested!==1?'S':''} · ${record.result.elapsed_ms} ms`;
  const warnings = [];
  if (s.offset) warnings.push(`先頭 ${s.offset} B は対象外`);
  if (s.end < record.result.size) warnings.push(`末尾 ${record.result.size-s.end} B は未解析`);
  if (s.error) warnings.push(`@${hexOffset(s.error.offset)}: ${s.error.message}`);
  warnings.push(...s.warnings);
  $('parseWarning').hidden = warnings.length===0;
  $('parseWarning').textContent = warnings.join(' / ');
  $('parseWarning').title = warnings.join('\n');
  hexList.set(Array(Math.ceil(state.bytes.length/16)).fill(null));
  candidateList.set(record.result.candidates);
  renderTree(); renderView(); renderHistory(); updateSelectionInfo();
}
async function loadRecord(id) {
  const request = ++state.request;
  const record = await api(`/api/history/${id}`);
  if (request !== state.request) return;
  setRecord(record);
  status(`${record.title} · 保存済みの解析を表示`);
  $('historyList').closest('aside').classList.remove('open');
}
async function runAnalysis() {
  if (state.busy) return;
  const payload = {text:$('sourceInput').value,format:$('inputFormat').value,title:$('analysisTitle').value,
    mode:$('scanToggle').checked?'scan':'exact', offset:$('manualOffset').value,sequence:$('sequenceToggle').checked};
  const request = ++state.request;
  state.busy = true; document.body.classList.add('busy'); $('analyzeButton').disabled = true;
  status('解析中…');
  try {
    const record = await api('/api/analyze',payload);
    if (request === state.request) {
      setRecord(record, $('sourceInput').value===payload.text);
      const s = record.result.selected;
      status(`${formatBytes(record.result.tested)} オフセットを検証 · ${s.hits} ヒット · ${hexOffset(s.offset)} · 履歴に保存しました`);
    }
    await refreshHistory();
  } finally {
    state.busy=false;document.body.classList.remove('busy');$('analyzeButton').disabled=false;
  }
}
async function chooseCandidate(offset) {
  if (!state.active) return;
  const id = state.active.id, request = ++state.request;
  const record = await api(`/api/history/${id}/candidate`, {offset});
  if (request !== state.request || state.active?.id !== id) return;
  setRecord(record, false); await refreshHistory();
  candidateList.scrollTo(record.result.candidates.findIndex(c=>c.offset===offset));
  status(`${hexOffset(offset)} の解析結果を表示 · 選択候補を履歴に保存しました`);
}
function newAnalysis() {
  ++state.request; state.active=null; state.bytes=[];state.range=null;state.node=null;state.collapsed.clear();state.dirty=false;
  setSource('','hex',''); hexList.set([]);treeList.set([]);candidateList.set([]);
  for (const id of ['metricOffset','metricHits','metricBytes','metricItems','byteCount']) $(id).textContent='—';
  $('resultState').textContent='未解析';$('resultState').classList.remove('good');$('candidateCount').textContent='0';
  $('treeCount').textContent='0 要素';$('textResult').textContent='';$('emptyResult').hidden=false;$('parseWarning').hidden=true;
  $('exportButton').disabled=true;renderHistory();updateSelectionInfo();$('sourceInput').focus();status('新しい解析');
}

function renderTree() {
  const rows = state.active?.result.selected.rows || [];
  const query = $('treeSearch').value.toLowerCase();
  let matching;
  if (query) {
    matching = new Set();
    for (const row of rows) if (`${row.label} ${row.value} ${row.type} ${row.path}`.toLowerCase().includes(query)) {
      matching.add(row.id); let p=row.parent;
      while(p!==null && p!==undefined) { matching.add(p); p=rows[p].parent; }
    }
  }
  const hidden = new Set();
  state.visibleRows = rows.filter(row => {
    if (matching) return matching.has(row.id);
    if (row.parent!==null && (hidden.has(row.parent) || state.collapsed.has(row.parent))) { hidden.add(row.id); return false; }
    return true;
  });
  treeList.set(state.visibleRows, true);
}
function renderView() {
  const tree = state.view === 'tree';
  $('treeView').hidden=!tree;$('treeToolbar').hidden=!tree;$('treeLabels').hidden=!tree;
  $('textResult').hidden=tree;$('collapseButton').hidden=!tree;$('expandButton').hidden=!tree;
  document.querySelectorAll('[data-view]').forEach(button=>button.setAttribute('aria-selected',String(button.dataset.view===state.view)));
  if (state.active) {
    const selected=state.active.result.selected;
    const jsonValue=state.active.result.sequence ? selected.json : selected.json[0];
    $('textResult').textContent=state.view==='json'?JSON.stringify(jsonValue??null,null,2):selected.diagnostic;
  }
  treeList.render();
}
function updateSelectionInfo() {
  $('selectionInfo').textContent=state.range?`${hexOffset(state.range[0])}–${hexOffset(state.range[1]-1)} · ${state.range[1]-state.range[0]} B`:'選択なし';
}
function highlightNode(row, scroll=true) {
  state.node=row; state.range=[row.start,row.end];state.anchor=row.start;
  updateSelectionInfo();hexList.render();treeList.render();
  if (scroll) hexList.scrollTo(Math.floor(row.start/16));
}
function nodeForByte(pos) {
  let best=null;
  for (const row of state.active?.result.selected.rows||[]) if (row.start<=pos && pos<row.end && (!best||row.end-row.start<best.end-best.start)) best=row;
  return best;
}
function selectByte(pos, extend=false) {
  if (!extend) state.anchor=pos;
  state.cursor=pos; state.range=[Math.min(state.anchor,pos),Math.max(state.anchor,pos)+1];
  state.node=nodeForByte(pos);
  if (state.node) {
    const rows=state.active.result.selected.rows;let parent=state.node.parent;
    while(parent!==null) { state.collapsed.delete(parent);parent=rows[parent].parent; }
    renderTree();treeList.scrollTo(state.visibleRows.findIndex(r=>r.id===state.node.id));
  }
  hexList.render();updateSelectionInfo();
}

async function compareSelected() {
  const ids=[...state.selected];
  if (ids.length!==2) return;
  state.comparison=await api('/api/compare',{left:ids[0],right:ids[1]});
  $('compareDock').hidden=false;$('compareSplitter').hidden=false;
  const c=state.comparison;
  $('compareNames').textContent=`A ${c.left.title}  →  B ${c.right.title}`;
  $('compareNames').title=$('compareNames').textContent;
  $('compareStats').innerHTML=`<span class="added">＋ ${c.counts.added} 追加</span><span class="removed">− ${c.counts.removed} 削除</span><span class="changed">~ ${c.counts.changed} 変更</span><span>${c.counts.encoding} 符号差</span><span>${c.counts.same} 一致</span><span>元入力 ${formatBytes(c.byte_differences)} B差</span>`;
  renderComparison();status('履歴を比較中');
}
function renderComparison() {
  if (!state.comparison) return;
  const c=state.comparison, mode=$('compareMode').value,only=$('diffOnly').checked;
  let rows=[];
  if (mode==='structure') rows=c.rows;
  else if(mode==='bytes'||mode==='decoded-bytes') {
    const sa=c.left.result.selected,sb=c.right.result.selected;
    const ah=mode==='decoded-bytes'?c.left.hex.slice(sa.offset*2,sa.end*2):c.left.hex;
    const bh=mode==='decoded-bytes'?c.right.hex.slice(sb.offset*2,sb.end*2):c.right.hex;
    const a=ah.match(/../g)||[],b=bh.match(/../g)||[];
    for(let pos=0;pos<Math.max(a.length,b.length);pos+=16) {
      const left=a.slice(pos,pos+16).join(' ').toUpperCase(),right=b.slice(pos,pos+16).join(' ').toUpperCase();
      rows.push({byte:true,offset:pos,left:left||'—',right:right||'—',status:!left?'added':!right?'removed':left===right?'same':'changed'});
    }
  } else {
    const a=c.left.result.selected.diagnostic.split('\n'),b=c.right.result.selected.diagnostic.split('\n');
    for(let i=0;i<Math.max(a.length,b.length);i++) rows.push({line:true,index:i,left:a[i]??'—',right:b[i]??'—',status:a[i]===undefined?'added':b[i]===undefined?'removed':a[i]===b[i]?'same':'changed'});
  }
  if(only) rows=rows.filter(r=>r.status!=='same');
  compareList.set(rows);
  const labels=$('compareLabels').children;
  labels[0].textContent=mode==='bytes'?'状態 / 絶対オフセット':mode==='decoded-bytes'?'状態 / 解析先頭からの位置':mode==='diagnostic'?'状態 / 行':'状態 / パス';
  labels[1].textContent=`A · ${c.left.title}`;labels[2].textContent=`B · ${c.right.title}`;
  if(!rows.length) compareList.items.innerHTML='<div class="compare-empty">差分はありません</div>';
}

function closeMenu(focus=false) {
  $('contextMenu').hidden=true;
  if(focus) state.menuReturn?.focus?.();
}
function menu(event, heading, actions) {
  event?.preventDefault?.();event?.stopPropagation?.();
  state.menuReturn=document.activeElement;
  const el=$('contextMenu');el.replaceChildren();
  if(heading) {const h=document.createElement('div');h.className='menu-heading';h.textContent=heading;el.append(h);}
  for(const action of actions) {
    if(!action) {el.append(document.createElement('hr'));continue;}
    const button=document.createElement('button');button.type='button';button.setAttribute('role','menuitem');
    button.textContent=action.label;button.disabled=!!action.disabled;
    if(action.danger) button.classList.add('danger');
    if(action.shortcut) {const shortcut=document.createElement('span');shortcut.className='menu-shortcut';shortcut.textContent=action.shortcut;button.append(shortcut);}
    button.addEventListener('click',safely(async()=>{closeMenu();await action.run();}));el.append(button);
  }
  el.hidden=false;el.style.left='0px';el.style.top='0px';
  const target=event?.currentTarget?.getBoundingClientRect?.();
  const x=event?.clientX || target?.left || 30,y=event?.clientY || target?.bottom || 60;
  el.style.left=`${Math.max(5,Math.min(x,innerWidth-el.offsetWidth-5))}px`;
  el.style.top=`${Math.max(5,Math.min(y,innerHeight-el.offsetHeight-5))}px`;
  el.querySelector('button:not(:disabled)')?.focus();
}
async function nodeData(row) {return api(`/api/history/${state.active.id}/node?offset=${row.start}`);}
async function extract(hex,title,options={}) {
  setSource(hex.match(/.{1,32}/g)?.join('\n')||hex,'hex',title,options);await runAnalysis();
}
function nodeMenu(event,row) {
  highlightNode(row);
  const record=state.active;
  menu(event,`${row.label} · ${row.type} · ${hexOffset(row.start)}`, [
    {label:'値をコピー',run:async()=>{const n=await nodeData(row);const v=n.json;await copy(typeof v==='string'?v:v?.$integer??JSON.stringify(v,null,2));}},
    {label:'表示値をコピー',run:()=>copy(row.value)},
    {label:'Diagnostic をコピー',run:async()=>copy((await nodeData(row)).diagnostic)},
    {label:'パスをコピー',run:()=>copy(row.display_path || row.path)},
    {label:'要素の HEX のみコピー',run:()=>copy(hexText(row.start,row.end))},null,
    {label:'この要素を新しく解析',run:()=>extract(record.hex.slice(row.start*2,row.end*2),`${record.title} / ${row.label}`)},
    {label:'バイト文字列の中身を解析',disabled:row.type!=='bytes',run:async()=>extract((await nodeData(row)).payload,`${record.title} / payload`)},
    {label:'この位置から解析',run:()=>extract(record.hex,`${record.title} / @${hexOffset(row.start)}`,{scan:false,offset:row.start,sequence:record.result.sequence})},null,
    {label:state.collapsed.has(row.id)?'子要素を展開':'子要素を折りたたむ',disabled:!row.children,run:()=>{state.collapsed.has(row.id)?state.collapsed.delete(row.id):state.collapsed.add(row.id);renderTree();}}
  ]);
}
function hexMenu(event) {
  const hit=event.target.closest?.('[data-byte]');
  if(hit) {const pos=Number(hit.dataset.byte);if(!state.range||pos<state.range[0]||pos>=state.range[1])selectByte(pos);}
  const record=state.active, range=state.range, data=selectedHex(false);
  menu(event,range?`${hexOffset(range[0])} · ${range[1]-range[0]} B`:'バイト表示',[
    {label:'HEX のみコピー',disabled:!data,run:()=>copy(selectedHex())},
    {label:'HEX のみコピー（区切りなし）',disabled:!data,run:()=>copy(data)},
    {label:'Base64 をコピー',disabled:!data,run:()=>copy(base64FromHex(data))},null,
    {label:'選択範囲を新しく解析',disabled:!range,run:()=>extract(data,`${record.title} / ${hexOffset(range[0])}`)},
    {label:'この位置から解析',disabled:!range,run:()=>extract(record.hex,`${record.title} / @${hexOffset(range[0])}`,{scan:false,offset:range[0],sequence:record.result.sequence})},
    {label:'対応する要素を表示',disabled:!state.node,run:()=>{state.view='tree';renderView();treeList.scrollTo(state.visibleRows.findIndex(r=>r.id===state.node.id));}},null,
    {label:'すべて選択',disabled:!state.bytes.length,shortcut:'Ctrl+A',run:()=>{state.range=[0,state.bytes.length];hexList.render();updateSelectionInfo();}},
    {label:'選択を解除',disabled:!range,run:()=>{state.range=null;state.node=null;hexList.render();treeList.render();updateSelectionInfo();}}
  ]);
}
async function renameRecord(record) {
  const title=prompt('履歴名',record.title);
  if(title===null||!title.trim())return;
  const updated=await api(`/api/history/${record.id}`,{title},'PATCH');
  if(state.active?.id===record.id){state.active.title=updated.title;$('analysisTitle').value=updated.title;}
  await refreshHistory();
}
function historyMenu(event,record) {
  menu(event,record.title,[
    {label:'開く',run:()=>loadRecord(record.id)},
    {label:'名前を変更',run:()=>renameRecord(record)},
    {label:record.pinned?'固定を解除':'履歴を固定',run:async()=>{await api(`/api/history/${record.id}`,{pinned:!record.pinned},'PATCH');await refreshHistory();}},null,
    {label:'比較元 A に設定',run:()=>setCompareSlot(record.id,0)},
    {label:'比較先 B に設定',run:()=>setCompareSlot(record.id,1)},
    {label:'現在の解析と比較',disabled:!state.active||record.id===state.active.id,run:async()=>{state.selected=new Set([state.active.id,record.id]);renderHistory();await compareSelected();}},null,
    {label:'バイナリを保存 (.cbor)',run:()=>exportRecord(record,'cbor')},
    {label:'解析データを保存 (.json)',run:()=>exportRecord(record,'json')},null,
    {label:'履歴を削除',danger:true,run:async()=>{if(!confirm(`「${record.title}」を削除しますか？`))return;await api(`/api/history/${record.id}`,undefined,'DELETE');state.selected.delete(record.id);if(state.active?.id===record.id)newAnalysis();await refreshHistory();}}
  ]);
}
function inputMenu(event) {
  const input=$('sourceInput'),selected=input.value.slice(input.selectionStart,input.selectionEnd);
  menu(event,'入力',[
    {label:'選択テキストをコピー',disabled:!selected,shortcut:'Ctrl+C',run:()=>copy(selected)},
    {label:'すべてコピー',disabled:!input.value,run:()=>copy(input.value)},
    {label:'貼り付け',shortcut:'Ctrl+V',run:async()=>{try {const text=await navigator.clipboard.readText();input.setRangeText(text,input.selectionStart,input.selectionEnd,'end');markDirty();}catch{input.focus();toast('Ctrl+V / 長押しで貼り付けてください（HTTPでは直接貼付APIが使えない場合があります）');}}},
    {label:'すべて選択',shortcut:'Ctrl+A',run:()=>{input.focus();input.select();}},null,
    {label:'HEX を整形（16 B / 行）',disabled:$('inputFormat').value!=='hex',run:()=>{const raw=input.value.replace(/0x/gi,'').replace(/[\s,:_-]/g,'');if(!/^(?:[0-9a-fA-F]{2})*$/.test(raw))throw new Error('不正な HEX です');input.value=(raw.match(/.{1,32}/g)||[]).map(line=>(line.match(/../g)||[]).join(' ').toUpperCase()).join('\n');markDirty();}},
    {label:'入力をクリア',run:()=>{input.value='';markDirty();input.focus();}}
  ]);
}
function sampleMenu(event) {
  menu(event,'サンプル',[
    {label:'テレメトリ · JSON → CBOR',run:()=>setSource(sampleJson,'json','Telemetry / 42')},
    {label:'ヘッダー + CBOR + ノイズ · HEX',run:()=>setSource((sampleHex.match(/.{1,32}/g)||[]).join('\n'),'hex','Framed telemetry')},
    {label:'タグ・バイト列・不定長 · Diagnostic',run:()=>setSource('{"time": 1(1700000000), "payload": h\'01020304\', "values": [_ 1, 2, 3], "big": 18446744073709551615, "state": true}','diagnostic','CBOR types')},
    {label:'CBOR Sequence · 連続した3項目',run:()=>setSource('{"seq": 1}, {"seq": 2}, {"seq": 3}','diagnostic','Sequence',{sequence:true})}
  ]);
}

async function openFile(file) {
  if(!file)return;
  if(file.size>state.maxBytes*8)throw new Error('ファイルが大きすぎます');
  const ext=file.name.split('.').pop().toLowerCase();
  const formats={json:'json',diag:'diagnostic',edn:'diagnostic',hex:'hex',txt:'hex',b64:'base64',base64:'base64'};
  if(formats[ext])setSource(await file.text(),formats[ext],file.name);
  else {
    if(file.size>state.maxBytes)throw new Error(`入力上限は ${formatBytes(state.maxBytes)} B です`);
    const data=new Uint8Array(await file.arrayBuffer());
    const hex=Array.from(data,b=>b.toString(16).padStart(2,'0')).join('');
    setSource((hex.match(/.{1,32}/g)||[]).join('\n'),'hex',file.name);
  }
  status(`${file.name} を読み込みました。解析ボタンで実行します`);
}

function splitter(id,variable,axis,getValue,min,max,direction=1) {
  const el=$(id);
  const saved=Number(readLocal(`cbor.${variable}`));
  if(Number.isFinite(saved)&&saved>0)document.documentElement.style.setProperty(variable,`${saved}px`);
  const apply=(value)=>{const limit=typeof max==='function'?max():max;const v=Math.round(Math.max(min,Math.min(limit,value)));document.documentElement.style.setProperty(variable,`${v}px`);storeLocal(`cbor.${variable}`,v);};
  el.addEventListener('pointerdown',event=>{
    if(event.button!==0)return;event.preventDefault();el.setPointerCapture(event.pointerId);
    const start=axis==='x'?event.clientX:event.clientY, initial=getValue();
    el.classList.add('dragging');document.body.classList.add('resizing');
    const move=e=>apply(initial+direction*((axis==='x'?e.clientX:e.clientY)-start));
    const end=()=>{el.removeEventListener('pointermove',move);el.removeEventListener('pointerup',end);el.removeEventListener('pointercancel',end);el.classList.remove('dragging');document.body.classList.remove('resizing');};
    el.addEventListener('pointermove',move);el.addEventListener('pointerup',end);el.addEventListener('pointercancel',end);
  });
  el.addEventListener('keydown',event=>{const negative=axis==='x'?'ArrowLeft':'ArrowUp',positive=axis==='x'?'ArrowRight':'ArrowDown';if(event.key===negative||event.key===positive){event.preventDefault();apply(getValue()+direction*(event.key===positive?10:-10));}});
  el.addEventListener('dblclick',()=>{document.documentElement.style.removeProperty(variable);storeLocal(`cbor.${variable}`,'');});
}

$('analyzeButton').addEventListener('click',safely(runAnalysis));
$('newButton').addEventListener('click',newAnalysis);
$('inputFormat').addEventListener('change',markDirty);
$('sourceInput').addEventListener('input',markDirty);
$('analysisTitle').addEventListener('input',updateInputInfo);
$('scanToggle').addEventListener('change',()=>{$('manualOffset').disabled=$('scanToggle').checked;markDirty();});
$('sequenceToggle').addEventListener('change',markDirty);$('manualOffset').addEventListener('input',markDirty);
$('sourceInput').addEventListener('contextmenu',inputMenu);
$('sampleButton').addEventListener('click',sampleMenu);
$('emptySampleButton').addEventListener('click',safely(async()=>{setSource((sampleHex.match(/.{1,32}/g)||[]).join('\n'),'hex','Framed telemetry');await runAnalysis();}));
$('fileButton').addEventListener('click',()=>$('fileInput').click());
$('fileInput').addEventListener('change',safely(async e=>{await openFile(e.target.files[0]);e.target.value='';}));
$('historySearch').addEventListener('input',renderHistory);
$('historyList').addEventListener('click',safely(async event=>{const check=event.target.closest('[data-check]');if(check){toggleCompare(check.dataset.check,check.checked);return;}const row=event.target.closest('[data-history]');if(row)await loadRecord(row.dataset.history);}));
$('historyList').addEventListener('dblclick',safely(async event=>{const row=event.target.closest('[data-history]');if(!row)return;const r=state.history.find(r=>r.id===row.dataset.history);await api(`/api/history/${r.id}`,{pinned:!r.pinned},'PATCH');await refreshHistory();}));
$('historyList').addEventListener('contextmenu',event=>{const row=event.target.closest('[data-history]');if(row)historyMenu(event,state.history.find(r=>r.id===row.dataset.history));});
$('historyList').addEventListener('keydown',safely(async event=>{const row=event.target.closest('[data-history]');if(row&&event.key==='Enter'){event.preventDefault();await loadRecord(row.dataset.history);}else if(row&&event.key===' '){event.preventDefault();toggleCompare(row.dataset.history);}}));
$('compareButton').addEventListener('click',safely(compareSelected));
$('closeCompareButton').addEventListener('click',()=>{$('compareDock').hidden=true;$('compareSplitter').hidden=true;});
$('swapCompareButton').addEventListener('click',safely(async()=>{state.selected=new Set([...state.selected].reverse());await compareSelected();}));
$('compareMode').addEventListener('change',renderComparison);$('diffOnly').addEventListener('change',renderComparison);
$('compareView').addEventListener('contextmenu',event=>{const selection=window.getSelection()?.toString();menu(event,'比較',[
  {label:'選択テキストをコピー',disabled:!selection,run:()=>copy(selection)},
  {label:'差分一覧をコピー',disabled:!state.comparison,run:()=>copy(compareList.data.map(r=>r.byte?`${hexOffset(r.offset)}\t${r.left}\t${r.right}`:r.line?`${r.index+1}\t${r.left}\t${r.right}`:`${r.status}\t${r.path}\t${r.left?.value??''}\t${r.right?.value??''}`).join('\n'))}
]);});
$('treeView').addEventListener('click',event=>{const row=event.target.closest('[data-node]');if(!row||!state.active)return;const r=state.active.result.selected.rows[Number(row.dataset.node)];if(event.target.closest('[data-toggle]')&&r.children){state.collapsed.has(r.id)?state.collapsed.delete(r.id):state.collapsed.add(r.id);renderTree();}else highlightNode(r);});
$('treeView').addEventListener('contextmenu',event=>{const row=event.target.closest('[data-node]');if(row)nodeMenu(event,state.active.result.selected.rows[Number(row.dataset.node)]);});
$('treeView').addEventListener('keydown',event=>{
  if(!state.visibleRows.length)return;
  let index=state.visibleRows.findIndex(r=>r.id===state.node?.id);index=Math.max(0,index);
  if(event.key==='ArrowDown'||event.key==='ArrowUp'){event.preventDefault();index=Math.max(0,Math.min(state.visibleRows.length-1,index+(event.key==='ArrowDown'?1:-1)));highlightNode(state.visibleRows[index]);treeList.scrollTo(index);$('treeView').querySelector(`[data-node="${state.visibleRows[index].id}"]`)?.focus();}
  else if(event.key==='ArrowRight'||event.key==='ArrowLeft'){event.preventDefault();const row=state.visibleRows[index];if(event.key==='ArrowRight')state.collapsed.delete(row.id);else if(row.children)state.collapsed.add(row.id);else if(row.parent!==null)highlightNode(state.active.result.selected.rows[row.parent]);renderTree();}
});
$('treeSearch').addEventListener('input',renderTree);
$('collapseButton').addEventListener('click',()=>{for(const r of state.active?.result.selected.rows||[])if(r.children)state.collapsed.add(r.id);renderTree();});
$('expandButton').addEventListener('click',()=>{state.collapsed.clear();renderTree();});
document.querySelectorAll('[data-view]').forEach(button=>button.addEventListener('click',()=>{state.view=button.dataset.view;renderView();}));
$('copyResultButton').addEventListener('click',safely(()=>copy(state.view==='json'?$('textResult').textContent:state.active?.result.selected.diagnostic||'')));
$('textResult').addEventListener('contextmenu',event=>{const selected=window.getSelection()?.toString();menu(event,state.view==='json'?'JSON':'Diagnostic',[
  {label:'選択部分をコピー',disabled:!selected,run:()=>copy(selected)},
  {label:'すべてコピー',disabled:!state.active,run:()=>copy($('textResult').textContent)},
  {label:'Diagnostic を入力に戻す',disabled:!state.active,run:()=>setSource(state.active.result.selected.diagnostic,'diagnostic',`${state.active.title} / edit`,{sequence:state.active.result.sequence})}
]);});
$('candidateList').addEventListener('click',safely(async event=>{const row=event.target.closest('[data-candidate]');if(row)await chooseCandidate(Number(row.dataset.candidate));}));
$('candidateList').addEventListener('keydown',safely(async event=>{const row=event.target.closest('[data-candidate]');if(row&&(event.key==='Enter'||event.key===' ')){event.preventDefault();await chooseCandidate(Number(row.dataset.candidate));}}));
$('candidateList').addEventListener('contextmenu',event=>{const row=event.target.closest('[data-candidate]');if(!row)return;const offset=Number(row.dataset.candidate);menu(event,`候補 ${hexOffset(offset)}`,[{label:'この候補を表示',run:()=>chooseCandidate(offset)},{label:'オフセットをコピー',run:()=>copy(hexOffset(offset))}]);});
$('hexView').addEventListener('pointerdown',event=>{const byte=event.target.closest('[data-byte]');if(!byte||event.button!==0)return;event.preventDefault();state.drag=true;selectByte(Number(byte.dataset.byte),event.shiftKey);$('hexView').focus();});
window.addEventListener('pointermove',event=>{if(!state.drag)return;const byte=document.elementFromPoint(event.clientX,event.clientY)?.closest('[data-byte]');if(byte)selectByte(Number(byte.dataset.byte),true);});
window.addEventListener('pointerup',()=>state.drag=false);window.addEventListener('pointercancel',()=>state.drag=false);
$('hexView').addEventListener('contextmenu',hexMenu);
$('hexView').addEventListener('keydown',safely(async event=>{
  if(!state.bytes.length)return;
  if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='a'){event.preventDefault();state.range=[0,state.bytes.length];hexList.render();updateSelectionInfo();}
  else if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='c'){event.preventDefault();await copy(selectedHex());}
  else if(['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(event.key)){event.preventDefault();const delta={ArrowLeft:-1,ArrowRight:1,ArrowUp:-16,ArrowDown:16}[event.key];const origin=state.range?state.cursor:0;const next=Math.max(0,Math.min(state.bytes.length-1,origin+delta));selectByte(next,event.shiftKey);hexList.scrollTo(Math.floor(next/16));}
}));
$('byteGoto').addEventListener('keydown',event=>{if(event.key!=='Enter')return;const value=event.target.value.trim();const pos=/^0x[\da-f]+$/i.test(value)?parseInt(value,16):/^\d+$/.test(value)?Number(value):NaN;if(!Number.isSafeInteger(pos)||pos<0||pos>=state.bytes.length){toast('入力データ範囲内のオフセットを指定してください');return;}selectByte(pos);hexList.scrollTo(Math.floor(pos/16));});
$('copyHexButton').addEventListener('click',safely(()=>copy(selectedHex())));
$('exportButton').addEventListener('click',event=>{if(!state.active)return;const record=state.active;menu(event,'書き出し',[
  {label:'元バイナリ (.cbor)',run:()=>exportRecord(record,'cbor')},
  {label:'Diagnostic (.diag)',run:()=>exportRecord(record,'diagnostic')},
  {label:'解析結果・入力・候補 (.json)',run:()=>exportRecord(record,'json')}
]);});
$('themeButton').addEventListener('click',()=>{const value=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=value;storeLocal('cbor.theme',value);});
$('helpButton').addEventListener('click',()=>$('helpDialog').showModal());$('closeHelp').addEventListener('click',()=>$('helpDialog').close());
$('historyToggle').addEventListener('click',()=>document.querySelector('.history-pane').classList.toggle('open'));
$('contextMenu').addEventListener('keydown',event=>{const buttons=[...$('contextMenu').querySelectorAll('button:not(:disabled)')];let index=buttons.indexOf(document.activeElement);if(event.key==='ArrowDown'||event.key==='ArrowUp'){event.preventDefault();buttons[(index+(event.key==='ArrowDown'?1:-1)+buttons.length)%buttons.length]?.focus();}else if(event.key==='Home'){event.preventDefault();buttons[0]?.focus();}else if(event.key==='End'){event.preventDefault();buttons.at(-1)?.focus();}});
document.addEventListener('pointerdown',event=>{if(!$('contextMenu').contains(event.target))closeMenu();});
document.addEventListener('keydown',safely(async event=>{
  if((event.ctrlKey||event.metaKey)&&event.key==='Enter'){event.preventDefault();await runAnalysis();}
  else if(event.key==='Escape'){closeMenu(true);}
  else if((event.shiftKey&&event.key==='F10')||event.key==='ContextMenu'){
    const target=document.activeElement;
    const supported=target.closest('#historyList,#treeView,#hexView,#candidateList,#compareView')||target.id==='sourceInput'||target.id==='textResult';
    if(supported){event.preventDefault();const rect=target.getBoundingClientRect();target.dispatchEvent(new MouseEvent('contextmenu',{bubbles:true,cancelable:true,clientX:rect.left+20,clientY:rect.top+20}));}
  }
}));
let dragDepth=0;
window.addEventListener('dragenter',event=>{if(event.dataTransfer?.types.includes('Files')){event.preventDefault();dragDepth++;$('dropOverlay').hidden=false;}});
window.addEventListener('dragover',event=>{if(event.dataTransfer?.types.includes('Files')){event.preventDefault();event.dataTransfer.dropEffect='copy';}});
window.addEventListener('dragleave',()=>{dragDepth=Math.max(0,dragDepth-1);if(!dragDepth)$('dropOverlay').hidden=true;});
window.addEventListener('drop',safely(async event=>{event.preventDefault();dragDepth=0;$('dropOverlay').hidden=true;await openFile(event.dataTransfer?.files[0]);}));

splitter('sidebarSplitter','--sidebar-width','x',()=>document.querySelector('.history-pane').getBoundingClientRect().width,150,()=>Math.min(440,innerWidth*.35));
splitter('mainSplitter','--source-width','x',()=>$('sourceColumn').getBoundingClientRect().width,200,()=>$('analysisGrid').clientWidth-240);
splitter('sourceSplitter','--source-height','y',()=>$('sourcePanel').getBoundingClientRect().height,105,()=>$('sourceColumn').clientHeight-135);
splitter('candidateSplitter','--candidates-height','y',()=>$('candidatesPanel').getBoundingClientRect().height,80,()=>document.querySelector('.result-column').clientHeight-240,-1);
splitter('compareSplitter','--compare-height','y',()=>$('compareDock').getBoundingClientRect().height,130,()=>innerHeight*.6,-1);
// A saved pixel split must not make the right pane disappear on a smaller screen.
new ResizeObserver(()=>{const grid=$('analysisGrid'),w=parseFloat(document.documentElement.style.getPropertyValue('--source-width'));if(w>grid.clientWidth-200&&grid.clientWidth>400)document.documentElement.style.removeProperty('--source-width');}).observe($('analysisGrid'));

await safely(async()=>{
  const theme=readLocal('cbor.theme');if(theme==='light'||theme==='dark')document.documentElement.dataset.theme=theme;
  const health=await api('/api/health');state.maxBytes=health.max_bytes;
  $('serverState').textContent='SQLite · 接続済み';
  $('limitHelp').textContent=`入力上限 ${formatBytes(state.maxBytes)} B（CBOR_MAX_BYTESで設定）。ネスト128段。上限を超えた項目は明示的にエラー表示されます。履歴はこのサーバーの利用者間で共有されます。`;
  await refreshHistory();
  let draft;try{draft=JSON.parse(readLocal('cbor.draft')||'null');}catch{}
  if(state.history.length)await loadRecord(state.history[0].id);
  else if(draft?.text)setSource(draft.text,draft.format,draft.title,{scan:draft.scan,sequence:draft.sequence,offset:draft.offset});
  else setSource((sampleHex.match(/.{1,32}/g)||[]).join('\n'),'hex','Framed telemetry');
  status('準備完了 · 入力、またはサンプルを解析してください');
})();
