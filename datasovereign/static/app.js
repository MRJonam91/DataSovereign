let ownerToken = new URLSearchParams(window.location.hash.slice(1)).get('access');
if (ownerToken) history.replaceState(null, '', location.pathname + location.search);
try {
  if (ownerToken) {
    sessionStorage.setItem('datasovereign-owner', ownerToken);
  } else {
    ownerToken = sessionStorage.getItem('datasovereign-owner');
  }
} catch (_) { /* In-memory access still works if browser storage is unavailable. */ }
const $ = (id) => document.getElementById(id);
let snapshot = {collections: [], resources: [], grants: [], audit: []};
let auditRows = [];
let auditCursor = null;
let visibleGrant = null;
let scopePage = 0;
let scopeResults = [];
const scopeSelection = new Set();
const scopePageSize = 50;
const maxScope = 1000;
const eventLabels = {collection: 'Raccolta creata', import: 'Documento importato', grant: 'Delega creata', read: 'Lettura app', list: 'Elenco app', revoke: 'Delega revocata', trash: 'Documento nel cestino', restore_document: 'Documento ripristinato', export: 'Export in chiaro', backup: 'Backup cifrato', restore_backup: 'Backup ripristinato', owner_read: 'Download proprietario'};

function element(tag, text, className) {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) node.className = className;
  return node;
}
function notice(message, type = 'ok') {
  $('notice').textContent = message;
  $('notice').className = 'notice ' + type;
}
function empty(container, message) {
  container.replaceChildren(element('div', message, 'empty'));
}
function date(value) { return new Date(value * 1000).toLocaleString('it-IT'); }
function activeResources() { return snapshot.resources.filter((r) => r.deleted_at === null); }
function selectedDocuments() {
  return [...scopeSelection];
}
function clearToken() {
  $('token-value').value = '';
  $('new-token').hidden = true;
  visibleGrant = null;
}
function lockSession() {
  try { sessionStorage.removeItem('datasovereign-owner'); } catch (_) {}
  ownerToken = null;
  clearToken();
  $('workspace').hidden = true;
  $('auth-note').hidden = false;
  notice('Sessione bloccata. Riapri il collegamento completo dal terminale.');
}
async function call(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', 'Bearer ' + ownerToken);
  const response = await fetch(path, {...options, headers, cache: 'no-store'});
  if (!response.ok) {
    let detail = 'Errore ' + response.status;
    try {
      const payload = await response.json();
      if (typeof payload.detail === 'string') detail = payload.detail;
    } catch (_) {}
    if (response.status === 401) lockSession();
    throw new Error(detail);
  }
  return response;
}
function option(select, value, label) {
  const entry = element('option', label);
  entry.value = value;
  select.append(entry);
}
function fillCollections(id, all = false) {
  const select = $(id);
  const selected = select.value;
  select.replaceChildren();
  if (all) option(select, '', 'Tutte le raccolte');
  for (const collection of snapshot.collections) option(select, collection.id, collection.name);
  if (all || snapshot.collections.some((c) => c.id === selected)) select.value = selected;
}
function controls() {
  const imports = $('import-form').querySelector('button[type=submit]');
  imports.disabled = Boolean(imports.dataset.busy) || !snapshot.collections.length;
  const grants = $('grant-form').querySelector('button[type=submit]');
  grants.disabled = Boolean(grants.dataset.busy) || !selectedDocuments().length;
  const restore = $('restore-form').querySelector('button[type=submit]');
  const occupied = snapshot.collections.length || snapshot.resources.length || snapshot.grants.length;
  restore.disabled = Boolean(restore.dataset.busy) || Boolean(occupied);
  $('restore-note').textContent = occupied ? 'Questo vault contiene dati. Per ripristinare usa un vault vuoto con --data-dir.' : 'Vault vuoto: il ripristino è disponibile.';
}
async function busy(button, action) {
  if (button.dataset.busy) return;
  button.dataset.busy = 'true';
  button.disabled = true;
  try { await action(); }
  catch (error) { notice(error.message, 'error'); }
  finally { delete button.dataset.busy; button.disabled = false; controls(); }
}
function renderScope() {
  const docs = activeResources().filter((r) => r.collection_id === $('grant-collection').value);
  const available = new Set(docs.map((doc) => doc.id));
  for (const id of scopeSelection) if (!available.has(id)) scopeSelection.delete(id);
  const query = $('scope-search').value.trim().toLocaleLowerCase('it-IT');
  scopeResults = docs.filter((doc) => doc.name.toLocaleLowerCase('it-IT').includes(query));
  const pageCount = Math.max(1, Math.ceil(scopeResults.length / scopePageSize));
  scopePage = Math.min(scopePage, pageCount - 1);
  $('scope-prev').disabled = scopePage === 0;
  $('scope-next').disabled = scopePage >= pageCount - 1;
  $('scope-page').textContent = (scopePage + 1) + ' / ' + pageCount + ' · ' + scopeResults.length + ' risultati';
  const container = $('grant-documents');
  container.replaceChildren();
  if (!docs.length) empty(container, 'Importa documenti prima di creare una delega.');
  else if (!scopeResults.length) empty(container, 'Nessun documento corrispondente.');
  const offset = scopePage * scopePageSize;
  for (const doc of scopeResults.slice(offset, offset + scopePageSize)) {
    const label = element('label', '', 'checkbox-label');
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.value = doc.id;
    input.checked = scopeSelection.has(doc.id);
    input.addEventListener('change', () => {
      if (input.checked) scopeSelection.add(doc.id);
      else scopeSelection.delete(doc.id);
      scopeCount();
    });
    label.append(input, element('span', doc.name));
    container.append(label);
  }
  scopeCount();
}
function scopeCount() {
  const count = scopeSelection.size;
  const additions = scopeResults.filter((doc) => !scopeSelection.has(doc.id)).length;
  $('select-all-documents').disabled = !additions || count + additions > maxScope;
  $('clear-documents').disabled = count === 0;
  $('grant-documents').querySelectorAll('input').forEach((input) => {
    input.disabled = !input.checked && count >= maxScope;
  });
  $('scope-count').textContent = count + ' / ' + maxScope + ' documenti selezionati. I documenti futuri restano esclusi.';
  controls();
}
function renderGrants() {
  const now = Date.now() / 1000;
  $('count-grants').textContent = snapshot.grants.filter((g) => g.revoked_at === null && g.expires_at > now).length;
  const list = $('grants-list');
  list.replaceChildren();
  if (!snapshot.grants.length) empty(list, 'Nessuna delega creata.');
  const collectionNames = new Map(snapshot.collections.map((c) => [c.id, c.name]));
  const resourceNames = new Map(snapshot.resources.map((r) => [r.id, r.name]));
  for (const grant of snapshot.grants) {
    const collection = collectionNames.get(grant.collection_id);
    const status = grant.revoked_at !== null ? 'Revocata' : grant.expires_at <= now ? 'Scaduta' : 'Attiva';
    const record = element('div', '', 'record');
    const info = document.createElement('div');
    info.append(element('strong', grant.app_name));
    info.append(element('small', (collection || 'Raccolta') + ' · ' + grant.purpose));
    info.append(element('small', (grant.resource_ids || []).length + ' documenti · ' + status + ' · Scadenza ' + date(grant.expires_at)));
    const details = document.createElement('details');
    details.append(element('summary', 'Documenti autorizzati'));
    const scoped = (grant.resource_ids || []).map((id) => resourceNames.get(id) || id);
    details.append(element('small', scoped.length ? scoped.join(', ') : 'Nessun documento attualmente autorizzato'));
    info.append(details);
    record.append(info);
    if (status === 'Attiva') {
      const button = element('button', 'Revoca');
      button.type = 'button';
      button.addEventListener('click', () => busy(button, async () => {
        await call('/admin/grants/' + grant.id + '/revoke', {method: 'POST'});
        if (visibleGrant === grant.id) clearToken();
        notice('Delega revocata. Le nuove richieste sono rifiutate.');
        await refresh();
      }));
      record.append(button);
    }
    list.append(record);
  }
}
async function download(path, filename) {
  const response = await call(path);
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}
function renderDocuments() {
  const list = $('resources-list');
  list.replaceChildren();
  const query = $('resource-search').value.toLocaleLowerCase('it-IT');
  const collection = $('resource-collection').value;
  const trashed = $('show-trash').checked;
  const rows = snapshot.resources.filter((r) => (r.deleted_at !== null) === trashed && (!collection || r.collection_id === collection) && r.name.toLocaleLowerCase('it-IT').includes(query));
  $('resource-count').textContent = rows.length + ' documenti trovati' + (rows.length > 200 ? ' · Mostrati i primi 200: affina la ricerca.' : '');
  if (!rows.length) empty(list, trashed ? 'Il cestino è vuoto.' : 'Nessun documento corrisponde alla ricerca.');
  for (const resource of rows.slice(0, 200)) {
    const record = element('div', '', 'record');
    const info = document.createElement('div');
    const col = snapshot.collections.find((c) => c.id === resource.collection_id);
    info.append(element('strong', resource.name), element('small', (col ? col.name : '') + ' · ' + Math.ceil(resource.size / 1024) + ' KiB'));
    const actions = element('div', '', 'actions');
    if (!trashed) {
      const get = element('button', 'Scarica');
      get.type = 'button';
      get.addEventListener('click', () => busy(get, () => download('/admin/resources/' + resource.id + '/content', resource.name)));
      actions.append(get);
    }
    const change = element('button', trashed ? 'Ripristina' : 'Cestina');
    change.type = 'button';
    change.addEventListener('click', () => busy(change, async () => {
      await call('/admin/resources/' + resource.id + (trashed ? '/restore' : '/trash'), {method: 'POST'});
      notice(trashed ? 'Documento ripristinato. Crea una nuova delega per autorizzare le app.' : 'Documento nel cestino e rimosso da tutte le deleghe.');
      await refresh();
    }));
    actions.append(change);
    record.append(info, actions);
    list.append(record);
  }
}
function renderAudit() {
  const list = $('audit-list');
  list.replaceChildren();
  if (!auditRows.length) empty(list, 'Nessun evento per questo filtro.');
  for (const item of auditRows) {
    const record = element('div', '', 'record');
    const grant = snapshot.grants.find((g) => g.id === item.grant_id);
    const resource = snapshot.resources.find((r) => r.id === item.resource_id);
    const outcome = {allowed: 'Consentito', denied: 'Negato', error: 'Errore'}[item.outcome] || item.outcome;
    record.append(element('strong', (eventLabels[item.event] || item.event) + ' · ' + outcome));
    record.append(element('small', date(item.at) + (grant ? ' · ' + grant.app_name : '') + (resource ? ' · ' + resource.name : '')));
    list.append(record);
  }
  $('audit-more').hidden = auditCursor === null;
}
async function loadAudit(reset = true) {
  const params = new URLSearchParams({limit: '25'});
  if ($('audit-outcome').value) params.set('outcome', $('audit-outcome').value);
  if (!reset && auditCursor) params.set('before', auditCursor);
  const page = await (await call('/admin/audit?' + params)).json();
  auditRows = reset ? page.items : auditRows.concat(page.items);
  auditCursor = page.next_before;
  renderAudit();
}
function render() {
  $('count-collections').textContent = snapshot.collections.length;
  $('count-resources').textContent = activeResources().length;
  const list = $('collections-list');
  list.replaceChildren();
  if (!snapshot.collections.length) empty(list, 'Nessuna raccolta creata.');
  for (const collection of snapshot.collections) {
    const record = element('div', '', 'record');
    const info = document.createElement('div');
    info.append(element('strong', collection.name), element('small', activeResources().filter((r) => r.collection_id === collection.id).length + ' documenti attivi'));
    record.append(info);
    list.append(record);
  }
  fillCollections('import-collection');
  fillCollections('grant-collection');
  fillCollections('resource-collection', true);
  renderScope();
  renderDocuments();
  renderGrants();
  controls();
}
async function refresh() {
  snapshot = await (await call('/admin/state')).json();
  render();
  await loadAudit();
}
$('collection-form').addEventListener('submit', (event) => {
  event.preventDefault();
  busy(event.submitter, async () => {
    await call('/admin/collections', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({name: $('collection-name').value})});
    $('collection-form').reset();
    notice('Raccolta creata.');
    await refresh();
  });
});
$('import-form').addEventListener('submit', (event) => {
  event.preventDefault();
  busy(event.submitter, async () => {
    const files = [...$('import-files').files];
    const collection = $('import-collection').value;
    let completed = 0;
    try {
      for (const file of files) {
        if (file.size > 10 * 1024 * 1024) throw new Error(file.name + ' supera 10 MiB.');
        notice('Importazione ' + (completed + 1) + '/' + files.length + ': ' + file.name);
        await call('/admin/collections/' + collection + '/resources', {method: 'POST', headers: {'X-File-Name': encodeURIComponent(file.name), 'Content-Type': 'application/octet-stream'}, body: file});
        completed++;
      }
      $('import-files').value = '';
      notice(completed + ' documenti importati. Le deleghe precedenti non li includono.');
    } catch (error) {
      notice(completed + '/' + files.length + ' importati. ' + error.message, 'error');
    }
    await refresh();
  });
});
$('grant-collection').addEventListener('change', () => {
  scopeSelection.clear();
  $('scope-search').value = '';
  scopePage = 0;
  renderScope();
});
$('scope-search').addEventListener('input', () => { scopePage = 0; renderScope(); });
$('scope-prev').addEventListener('click', () => { scopePage--; renderScope(); });
$('scope-next').addEventListener('click', () => { scopePage++; renderScope(); });
$('select-all-documents').addEventListener('click', () => {
  for (const doc of scopeResults) scopeSelection.add(doc.id);
  renderScope();
});
$('clear-documents').addEventListener('click', () => { scopeSelection.clear(); renderScope(); });
$('grant-form').addEventListener('submit', (event) => {
  event.preventDefault();
  busy(event.submitter, async () => {
    const payload = {app_name: $('grant-app').value, purpose: $('grant-purpose').value, collection_id: $('grant-collection').value, duration_minutes: Number($('grant-duration').value), resource_ids: selectedDocuments()};
    const grant = await (await call('/admin/grants', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)})).json();
    visibleGrant = grant.id;
    $('token-value').value = grant.token;
    $('new-token').hidden = false;
    $('api-address').textContent = 'API app: ' + location.origin + '/v1/resources';
    notice('Delega creata per ' + grant.resource_ids.length + ' documenti. Copia il token.');
    await refresh();
  });
});
$('copy-token').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('token-value').value); notice('Token copiato.'); }
  catch (_) { $('token-value').select(); notice('Copia il token selezionato con Ctrl+C.', 'error'); }
});
$('hide-token').addEventListener('click', clearToken);
$('resource-search').addEventListener('input', renderDocuments);
$('resource-collection').addEventListener('change', renderDocuments);
$('show-trash').addEventListener('change', renderDocuments);
$('audit-outcome').addEventListener('change', () => loadAudit().catch((error) => notice(error.message, 'error')));
$('audit-more').addEventListener('click', (event) => busy(event.currentTarget, () => loadAudit(false)));
$('export-button').addEventListener('click', (event) => busy(event.currentTarget, async () => {
  await download('/admin/export', 'datasovereign-export.zip');
  notice('Export scaricato. Lo ZIP contiene documenti in chiaro.');
  await loadAudit();
}));
$('backup-button').addEventListener('click', (event) => busy(event.currentTarget, async () => {
  await download('/admin/backup', 'datasovereign-backup.zip');
  notice('Backup scaricato: documenti e metadati cifrati. Richiede lo stesso account Windows e dispositivo.');
  await loadAudit();
}));
$('health-button').addEventListener('click', (event) => busy(event.currentTarget, async () => {
  const health = await (await call('/admin/health')).json();
  const names = health.unreadable_resource_ids.map((id) => snapshot.resources.find((r) => r.id === id)?.name || id);
  $('health-result').textContent = health.ok ? 'Verifica completata: ' + (health.active_count + health.trashed_count) + ' documenti integri.' : 'Verifica richiesta. Documenti non leggibili: ' + (names.join(', ') || 'nessuno') + '. File orfani: ' + health.orphan_blob_count;
}));
$('restore-form').addEventListener('submit', (event) => {
  event.preventDefault();
  busy(event.submitter, async () => {
    const file = $('restore-file').files[0];
    if (!file || file.size > 64 * 1024 * 1024) throw new Error('Seleziona un backup ZIP di massimo 64 MiB.');
    const result = await (await call('/admin/backup/restore', {method: 'POST', headers: {'Content-Type': 'application/zip'}, body: file})).json();
    notice('Ripristinati ' + result.resources + ' documenti. Tutte le deleghe recuperate sono revocate.');
    $('restore-form').reset();
    await refresh();
  });
});
$('refresh-button').addEventListener('click', (event) => busy(event.currentTarget, refresh));
$('lock-button').addEventListener('click', lockSession);
if (!ownerToken) {
  $('auth-note').hidden = false;
} else {
  $('workspace').hidden = false;
  refresh().catch((error) => { $('workspace').hidden = true; notice(error.message, 'error'); });
}
setInterval(() => { if (ownerToken) renderGrants(); }, 30000);
