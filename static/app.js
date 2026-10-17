// Portal-proxy POC frontend logic (vanilla JS, no build step).
async function jfetch(url, opts) {
  const r = await fetch(url, opts);
  const body = await r.json().catch(() => ({}));
  if (!r.ok || body.success === false) throw new Error(body.error ? body.error.message : 'HTTP ' + r.status);
  return body.data;
}

// ── KB detail: hybrid search ──
async function doSearch(kbId) {
  const q = document.getElementById('q').value.trim();
  if (!q) return;
  const box = document.getElementById('results');
  box.innerHTML = '<div class="card muted">检索中…</div>';
  try {
    const data = await jfetch(`/kb/${kbId}/search`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({query_text: q, match_count: 5})
    });
    const items = (data && (data.result || data.results || data)) || [];
    const arr = Array.isArray(items) ? items : [];
    box.innerHTML = arr.length ? '<div class="card">' + arr.map(h =>
      `<div class="search-hit"><b>${h.title || h.knowledge_title || ''}</b>
       <div class="muted">${(h.content || h.chunk_content || h.text || '').slice(0, 260)}…</div>
       <div>score: ${h.score != null ? h.score.toFixed(3) : '-'}</div></div>`).join('') + '</div>'
      : '<div class="card muted">无结果</div>';
  } catch (e) { box.innerHTML = `<div class="card" style="color:#dc2626">检索失败：${e.message}</div>`; }
}

// ── KB detail: upload (editor only; server enforces) ──
async function doUpload(kbId) {
  const f = document.getElementById('upfile').files[0];
  const msg = document.getElementById('upmsg');
  if (!f) { msg.textContent = '请先选择文件'; return; }
  msg.textContent = '上传中…';
  const fd = new FormData(); fd.append('file', f);
  try {
    const r = await fetch(`/kb/${kbId}/upload`, {method: 'POST', body: fd});
    const body = await r.json().catch(() => ({}));
    if (!r.ok || body.success === false) throw new Error(body.error ? body.error.message : r.status);
    msg.textContent = '已提交，解析进行中'; setTimeout(() => location.reload(), 1500);
  } catch (e) { msg.textContent = '失败：' + e.message; }
}

// ── Chat ──
let curSess = null;
async function newSession() {
  try {
    const data = await jfetch('/chat/session', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'});
    curSess = data.session_id;
    document.getElementById('messages').innerHTML = '';
    const li = document.createElement('li');
    li.innerHTML = `<a href="javascript:void(0)" onclick="loadSession('${curSess}')">${curSess.slice(0, 8)}…</a>`;
    document.getElementById('sesslist').prepend(li);
  } catch (e) { alert('建会话失败：' + e.message); }
}
function loadSession(id) { curSess = id; document.getElementById('messages').innerHTML = '<div class="muted centered">历史消息拉取略（POC）；可直接继续提问。</div>'; }
function pickedKBs() { return Array.from(document.querySelectorAll('.kbchk:checked')).map(c => c.value); }
async function sendChat() {
  const q = document.getElementById('chatq').value.trim();
  if (!q) return;
  if (!curSess) { await newSession(); }
  const box = document.getElementById('messages');
  box.insertAdjacentHTML('beforeend', `<div class="msg user">🧑 ${q}</div><div class="msg bot" id="ans"></div>`);
  document.getElementById('chatq').value = '';
  const ans = document.getElementById('ans');
  ans.textContent = '…';
  const resp = await fetch(`/chat/${curSess}`, {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({query_text: q, kb_ids: pickedKBs()})
  });
  if (!resp.ok || !resp.body) { ans.textContent = '请求失败 HTTP ' + resp.status; return; }
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  let buf = '', text = '', refs = [];
  while (true) {
    const {done, value} = await reader.read();
    if (done) break;
    buf += dec.decode(value, {stream: true});
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).trim(); buf = buf.slice(idx + 1);
      if (!line.startsWith('data:')) continue;
      let ev; try { ev = JSON.parse(line.slice(5)); } catch { continue; }
      if (ev.response_type === 'answer' && ev.content) { text += ev.content; ans.textContent = text; }
      else if (ev.response_type === 'thinking' && ev.content) { ans.textContent = '💭 ' + ev.content; }
      else if (ev.response_type === 'references' || ev.type === 'references') { refs = ev.references || ev.data || refs; }
      else if (ev.response_type === 'error') { ans.textContent += '\n[错误] ' + (ev.error || ev.content || ''); }
    }
    box.scrollTop = box.scrollHeight;
  }
  if (refs && refs.length) {
    ans.insertAdjacentHTML('beforeend', `<div class="ref">引用：${refs.slice(0,5).map(r => `《${r.title || r.knowledge_title || r.name || ''}》`).join(' ')}</div>`);
  }
}
if (window.HAS_SESS) { curSess = window.INIT_SESS; }

// ── Admin ──
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  ['grant','overview','audit'].forEach(n => document.getElementById('tab-' + n).hidden = (n !== t.dataset.tab));
}));
async function saveGrant() {
  const days = document.getElementById('g_days').value;
  const body = {
    uum_user_id: document.getElementById('g_user').value,
    kb_id: document.getElementById('g_kb').value,
    permission: document.getElementById('g_perm').value,
    category: document.getElementById('g_cat').value,
  };
  if (days) body.valid_until = new Date(Date.now() + days * 86400000).toISOString();
  try {
    await jfetch('/api/admin/permissions', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    location.reload();
  } catch (e) { alert('保存失败：' + e.message); }
}
async function revokeGrant(id) {
  if (!confirm('确认回收该授权？回收后用户下次访问即失效。')) return;
  try {
    await jfetch('/api/admin/permissions/' + id, {method: 'DELETE'});
    location.reload();
  } catch (e) { alert('回收失败：' + e.message); }
}
function filterGrants(q) {
  document.querySelectorAll('#grant_table tr[data-user]').forEach(tr => {
    tr.style.display = !q || tr.dataset.user.includes(q) ? '' : 'none';
  });
}
