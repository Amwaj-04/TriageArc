(() => {
  'use strict';
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const state = { alerts: [], events: [], stats: {}, selectedId: null, view: 'overview', toastTimer: null };
  const RULES = [
    {id:'AUTH-001',title:'Repeated authentication failures',severity:'HIGH',description:'Five or more failed logins for the same user and source within 10 minutes.',technique:'T1110.001',mitre:'Password Guessing',rationale:'A burst of failed authentication attempts may indicate password guessing. Validate the source, account context, and any subsequent successful login.'},
    {id:'AUTH-002',title:'Successful login after repeated failures',severity:'HIGH',description:'A successful login follows at least three failures from the same source for the same user within 15 minutes.',technique:'T1078',mitre:'Valid Accounts',rationale:'A successful authentication following repeated failures may indicate credential compromise. Correlate with identity and endpoint telemetry before concluding.'},
    {id:'PROC-001',title:'Suspicious PowerShell execution',severity:'HIGH',description:'PowerShell command lines contain explicit execution or download indicators such as EncodedCommand, DownloadString, or ExecutionPolicy Bypass.',technique:'T1059.001',mitre:'PowerShell',rationale:'The rule matches explicit command-line indicators rather than treating all PowerShell use as malicious. Review parent process, user, script block logs, and destination context.'},
    {id:'IAM-001',title:'New privileged account',severity:'CRITICAL',description:'A newly created account is granted an administrative role within 30 minutes.',technique:'T1098',mitre:'Account Manipulation',rationale:'A new identity followed by a privilege grant can be a persistence or privilege-establishment pattern. Confirm the request, approver, and intended account owner.'},
    {id:'DATA-001',title:'Sensitive file access outside normal pattern',severity:'MEDIUM',description:'A user accesses a defined sensitive file from a workstation outside the synthetic expected-host mapping.',technique:'T1005',mitre:'Data from Local System',rationale:'An unexpected workstation is a contextual anomaly, not proof of data theft. Confirm business travel, approved device changes, and surrounding file-access events.'}
  ];
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const titleCase = value => String(value || '').toLowerCase().replace(/(^|_)([a-z])/g, (_,p,c) => (p ? ' ' : '') + c.toUpperCase());
  const statusClass = value => `status-${String(value || '').toLowerCase()}`;
  const severityClass = value => `severity-${String(value || '').toLowerCase()}`;
  const fmtTime = value => { if (!value) return '—'; const d = new Date(value); return Number.isNaN(d.getTime()) ? value : d.toLocaleString('en-GB',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit',hour12:false,timeZone:'UTC'}) + ' UTC'; };
  const fmtDate = value => { if (!value) return '—'; const d = new Date(value); return Number.isNaN(d.getTime()) ? value : d.toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric',timeZone:'UTC'}); };
  const short = (value, max=60) => { const s=String(value ?? '—'); return s.length>max ? `${s.slice(0,max-1)}…` : s; };
  async function api(url, options={}) {
    const response = await fetch(url, {headers:{'Content-Type':'application/json', ...(options.headers || {})}, ...options});
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
    return payload;
  }
  function notify(message) {
    const toast = $('#toast'); toast.textContent = message; toast.classList.add('show');
    clearTimeout(state.toastTimer); state.toastTimer = setTimeout(() => toast.classList.remove('show'), 2800);
  }
  function alertRow(alert, mode='overview') {
    const confidence = Number(alert.confidence || 0);
    const name = alert.username || alert.host || 'Unknown entity';
    if (mode === 'overview') return `<tr data-alert-id="${esc(alert.alert_uid)}"><td><span class="alert-title">${esc(alert.title)}</span><span class="alert-subtitle">${esc(alert.rule_id)} · ${esc(alert.alert_uid)}</span></td><td><span class="severity-badge ${severityClass(alert.severity)}">${esc(titleCase(alert.severity))}</span></td><td><span class="status-badge ${statusClass(alert.status)}">${esc(titleCase(alert.status))}</span></td><td><div class="confidence"><span class="confidence-track"><span class="confidence-fill" style="display:block;width:${confidence}%"></span></span><span class="confidence-number">${confidence}%</span></div></td><td><span class="text-button">Review →</span></td></tr>`;
    return `<tr data-alert-id="${esc(alert.alert_uid)}"><td><span class="alert-title">${esc(alert.title)}</span><span class="alert-subtitle">${esc(alert.rule_id)} · ${esc(alert.alert_uid)}</span></td><td><span class="severity-badge ${severityClass(alert.severity)}">${esc(titleCase(alert.severity))}</span></td><td><span class="alert-title">${esc(name)}</span><span class="alert-subtitle">${esc(alert.host || 'Host unavailable')}${alert.source_ip ? ` · ${esc(alert.source_ip)}` : ''}</span></td><td><span class="status-badge ${statusClass(alert.status)}">${esc(titleCase(alert.status))}</span></td><td><div class="confidence"><span class="confidence-track"><span class="confidence-fill" style="display:block;width:${confidence}%"></span></span><span class="confidence-number">${confidence}%</span></div></td><td>${esc(fmtTime(alert.first_seen))}</td><td><span class="text-button">Open →</span></td></tr>`;
  }
  function renderMetrics() {
    const s=state.stats; $('#metric-alerts').textContent=s.alerts ?? state.alerts.length; $('#metric-critical').textContent=s.critical ?? 0;
    $('#metric-new').textContent=(s.new||0)+(s.in_review||0); $('#metric-events').textContent=s.events ?? state.events.length;
    $('#nav-alert-count').textContent=state.alerts.length;
    const total=Math.max(1, Number(s.alerts || state.alerts.length || 0));
    $('#severity-chart').innerHTML = `<span class="chart-segment critical-bg" style="width:${(100*(s.critical||0)/total)}%"></span><span class="chart-segment high-bg" style="width:${(100*(s.high||0)/total)}%"></span><span class="chart-segment medium-bg" style="width:${(100*(s.medium||0)/total)}%"></span>`;
    $('#coverage-rule-count').textContent=RULES.length; $('#rules-total').textContent=RULES.length;
  }
  function renderAlerts() {
    const sorted=[...state.alerts].sort((a,b)=>({CRITICAL:0,HIGH:1,MEDIUM:2}[a.severity]??3)-({CRITICAL:0,HIGH:1,MEDIUM:2}[b.severity]??3));
    $('#overview-alert-rows').innerHTML=sorted.slice(0,5).map(a=>alertRow(a)).join('') || '<tr><td colspan="5" class="empty-cell">No alerts found. Run the demo scenario to populate the lab.</td></tr>';
    const q=($('#alert-search')?.value||'').trim().toLowerCase(), status=$('#status-filter')?.value||'ALL', sev=$('#severity-filter')?.value||'ALL';
    const filtered=sorted.filter(a => (status==='ALL'||a.status===status)&&(sev==='ALL'||a.severity===sev)&&(!q||[a.title,a.rule_id,a.alert_uid,a.username,a.host,a.source_ip,a.summary].some(v=>String(v||'').toLowerCase().includes(q))));
    $('#all-alert-rows').innerHTML=filtered.map(a=>alertRow(a,'all')).join('') || '<tr><td colspan="7" class="empty-cell">No alerts match the selected filters.</td></tr>';
    $('#alert-results-count').textContent=`Showing ${filtered.length} of ${state.alerts.length} alerts`;
    $('#queue-footnote').textContent=`${state.alerts.filter(a=>a.status==='NEW').length} new alerts awaiting review`;
  }
  function renderEvents() {
    const q=($('#event-search')?.value||'').trim().toLowerCase();
    const filtered=state.events.filter(e=>[e.event_uid,e.event_type,e.action,e.username,e.host,e.source_ip,e.detail,e.command_line,e.target].some(v=>String(v||'').toLowerCase().includes(q)));
    $('#event-rows').innerHTML=filtered.map(e=>`<tr><td>${esc(fmtTime(e.timestamp))}</td><td><span class="alert-title">${esc(e.event_uid)}</span></td><td><span class="alert-title">${esc(titleCase(e.event_type))}</span><span class="alert-subtitle">${esc(titleCase(e.action))}${e.status ? ` · ${esc(titleCase(e.status))}`:''}</span></td><td>${esc(e.username||'—')}</td><td>${esc(e.host||'—')}</td><td>${esc(e.source_ip||'—')}</td><td title="${esc(e.detail)}">${esc(short(e.command_line||e.target||e.detail,52))}</td></tr>`).join('') || '<tr><td colspan="7" class="empty-cell">No events match your search.</td></tr>';
    $('#event-results-count').textContent=`Showing ${filtered.length} of ${state.events.length} event records`;
  }
  function renderRules() {
    $('#rules-grid').innerHTML=RULES.map(r=>`<article class="rule-card"><div class="rule-card-top"><span class="rule-id">${esc(r.id)}</span><span class="severity-badge ${severityClass(r.severity)}">${esc(titleCase(r.severity))}</span></div><h3>${esc(r.title)}</h3><p>${esc(r.description)}</p><div class="rule-meta"><span>MITRE ATT&amp;CK</span><span><span class="mitre-code">${esc(r.technique)}</span> · ${esc(r.mitre)}</span></div></article>`).join('');
  }
  async function refresh(showNotice=false) {
    try {
      const [alerts,events,stats]=await Promise.all([api('/api/alerts'),api('/api/events'),api('/api/stats')]);
      state.alerts=alerts.alerts||[]; state.events=events.events||[]; state.stats=stats;
      renderMetrics(); renderAlerts(); renderEvents();
      if(showNotice) notify('Workspace refreshed.');
    } catch(error) { notify(`Could not load workspace: ${error.message}`); }
  }
  function showView(view) {
    if(!['overview','alerts','events','rules'].includes(view)) view='overview';
    state.view=view;
    $$('.view-section').forEach(el=>el.classList.add('hidden'));
    $(`#${view}-view`).classList.remove('hidden');
    $$('.nav-item').forEach(el=>el.classList.toggle('active',el.dataset.view===view));
    const titles={overview:['Analyst overview','A clear path from raw security signals to an evidence-based decision.'],alerts:['Alert queue','Review detections, compare evidence, and record an analyst decision.'],events:['Event explorer','Inspect the synthetic activity behind the detections.'],rules:['Detection rules','Explicit, explainable detection logic and MITRE ATT&CK context.']};
    $('#crumb-current').textContent=titles[view][0]; $('#page-title').textContent=titles[view][0]; $('#page-subtitle').textContent=titles[view][1];
    $('#page-head').classList.toggle('hidden',view==='rules');
    window.scrollTo({top:0,behavior:'smooth'});
  }
  function eventCard(e) {
    const details=[e.command_line,e.target,e.detail].filter(Boolean).join(' · ');
    return `<article class="evidence-item"><div class="evidence-top"><span class="evidence-id">${esc(e.event_uid||`EVENT-${e.id}`)} · ${esc(titleCase(e.event_type))}</span><span class="evidence-time">${esc(fmtTime(e.timestamp))}</span></div><strong>${esc(titleCase(e.action))}${e.status?` · ${esc(titleCase(e.status))}`:''}</strong><p>${esc(details||'No additional detail')}</p><p style="margin-top:6px">${esc(e.username||'Unknown user')} · ${esc(e.host||'Unknown host')}${e.source_ip?` · ${esc(e.source_ip)}`:''}</p></article>`;
  }
  async function openAlert(alertId) {
    try {
      const payload=await api(`/api/alerts/${encodeURIComponent(alertId)}`); const a=payload.alert; const events=payload.events||[]; state.selectedId=alertId;
      $('#detail-title').textContent=a.title; $('#detail-rule').textContent=a.rule_id; $('#detail-uid').textContent=`${a.alert_uid} · First seen ${fmtTime(a.first_seen)}`;
      $('#detail-content').innerHTML=`<div class="detail-badges"><span class="severity-badge ${severityClass(a.severity)}">${esc(titleCase(a.severity))} severity</span><span class="status-badge ${statusClass(a.status)}">${esc(titleCase(a.status))}</span>${a.verdict?`<span class="verdict-badge status-closed">${esc(titleCase(a.verdict))} verdict</span>`:''}</div>
      <div class="detail-summary"><h3>Detection summary</h3><p>${esc(a.summary)}</p><div class="rationale"><strong>Why this alert fired</strong><br>${esc(a.rationale)}</div></div>
      <div class="detail-facts"><div class="fact-card"><span>Observed user</span><strong>${esc(a.username||'—')}</strong></div><div class="fact-card"><span>Host</span><strong>${esc(a.host||'—')}</strong></div><div class="fact-card"><span>Source IP</span><strong>${esc(a.source_ip||'—')}</strong></div><div class="fact-card"><span>First seen</span><strong>${esc(fmtTime(a.first_seen))}</strong></div><div class="fact-card"><span>Last seen</span><strong>${esc(fmtTime(a.last_seen))}</strong></div><div class="fact-card"><span>Confidence</span><strong>${Number(a.confidence||0)}%</strong></div></div>
      <section class="drawer-section"><h3>Evidence timeline <span class="section-count">${events.length} events</span></h3><div class="evidence-list">${events.map(eventCard).join('')||'<p>No linked event records were returned.</p>'}</div></section>
      <section class="drawer-section"><h3>MITRE ATT&amp;CK context</h3><div class="mitre-panel"><div class="mitre-icon">⌘</div><div><strong>${esc(a.mitre_name||'Technique mapping')}</strong><small>${esc(a.mitre_technique||'No technique ID')} · ATT&amp;CK reference</small><p>This mapping provides investigative context only. Validate the behavior and surrounding telemetry before assigning intent.</p></div></div></section>
      <section class="drawer-section triage-form"><h3>Analyst decision</h3><form id="triage-form"><div class="form-grid"><div class="form-field"><label for="triage-status">Case status</label><select id="triage-status" name="status"><option value="NEW">New</option><option value="IN_REVIEW">In review</option><option value="ESCALATED">Escalated</option><option value="CLOSED">Closed</option></select></div><div class="form-field"><label for="triage-verdict">Verdict</label><select id="triage-verdict" name="verdict"><option value="">Not set</option><option value="BENIGN">Benign</option><option value="SUSPICIOUS">Suspicious</option><option value="MALICIOUS">Malicious</option></select></div></div><div class="form-field"><label for="triage-confidence">Analyst confidence</label><div class="range-row"><input id="triage-confidence" name="confidence" type="range" min="0" max="100" step="5" value="${Number(a.confidence||80)}"><span class="range-value" id="confidence-value">${Number(a.confidence||80)}%</span></div></div><div class="form-field"><label for="response-note">Response note / next action</label><textarea id="response-note" name="response_note" maxlength="2000" placeholder="Record what you validated, what remains uncertain, and the next step…">${esc(a.response_note||'')}</textarea></div><div class="form-actions"><button type="button" class="button button-secondary" id="cancel-triage">Cancel</button><button type="submit" class="button button-primary">Save analyst decision <span>✓</span></button></div></form></section>`;
      $('#triage-status').value=a.status||'NEW'; $('#triage-verdict').value=a.verdict||'';
      $('#detail-overlay').classList.remove('hidden'); $('#detail-overlay').setAttribute('aria-hidden','false'); document.body.style.overflow='hidden';
      $('#confidence-value').textContent=`${Number(a.confidence||80)}%`;
      $('#triage-confidence').addEventListener('input',e=>$('#confidence-value').textContent=`${e.target.value}%`);
      $('#triage-form').addEventListener('submit',saveTriage); $('#cancel-triage').addEventListener('click',closeDetail);
    } catch(error) { notify(`Could not open alert: ${error.message}`); }
  }
  async function saveTriage(event) {
    event.preventDefault(); const form=event.currentTarget; const button=$('button[type="submit"]',form); button.disabled=true; button.textContent='Saving…';
    const payload={status:$('#triage-status').value,verdict:$('#triage-verdict').value||null,confidence:Number($('#triage-confidence').value),response_note:$('#response-note').value};
    try { await api(`/api/alerts/${encodeURIComponent(state.selectedId)}/triage`,{method:'POST',body:JSON.stringify(payload)}); closeDetail(); await refresh(); notify('Analyst decision saved.'); }
    catch(error) { notify(`Could not save decision: ${error.message}`); button.disabled=false; button.innerHTML='Save analyst decision <span>✓</span>'; }
  }
  function closeDetail() { $('#detail-overlay').classList.add('hidden'); $('#detail-overlay').setAttribute('aria-hidden','true'); document.body.style.overflow=''; state.selectedId=null; }
  async function runDemo() {
    if (!window.confirm('Reload the synthetic scenario? This will reset analyst decisions in the local demo.')) return;
    const button=$('#run-demo-btn'); button.disabled=true; const old=button.innerHTML; button.textContent='Loading scenario…';
    try { await api('/api/demo/run',{method:'POST',body:'{}'}); await refresh(); notify('Demo scenario loaded with synthetic events.'); }
    catch(error) { notify(`Demo failed: ${error.message}`); }
    finally { button.disabled=false; button.innerHTML=old; }
  }
  function setTheme(theme) { document.documentElement.dataset.theme=theme; try{localStorage.setItem('triagearc-theme',theme)}catch(_){} }
  function initTheme() { let theme='light'; try{theme=localStorage.getItem('triagearc-theme')||'light'}catch(_){} if(theme!=='dark'&&theme!=='light')theme='light'; setTheme(theme); }
  function bind() {
    $$('.nav-item').forEach(button=>button.addEventListener('click',()=>showView(button.dataset.view)));
    $$('[data-open-view]').forEach(button=>button.addEventListener('click',()=>showView(button.dataset.openView)));
    $('#theme-toggle').addEventListener('click',()=>setTheme(document.documentElement.dataset.theme==='dark'?'light':'dark'));
    $('#refresh-btn').addEventListener('click',()=>refresh(true)); $('#run-demo-btn').addEventListener('click',runDemo);
    $('#alert-search').addEventListener('input',renderAlerts); $('#status-filter').addEventListener('change',renderAlerts); $('#severity-filter').addEventListener('change',renderAlerts); $('#event-search').addEventListener('input',renderEvents);
    document.body.addEventListener('click',e=>{const row=e.target.closest('[data-alert-id]');if(row)openAlert(row.dataset.alertId)});
    $('#close-detail').addEventListener('click',closeDetail); $('#detail-overlay').addEventListener('click',e=>{if(e.target===$('#detail-overlay'))closeDetail()});
    document.addEventListener('keydown',e=>{if(e.key==='Escape')closeDetail()}); $('#notice-dismiss').addEventListener('click',()=>$('.notice-bar').classList.add('hidden'));
  }
  initTheme(); renderRules(); bind(); refresh();
})();
