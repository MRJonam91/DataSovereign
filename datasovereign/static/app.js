const ownerToken = new URLSearchParams(window.location.hash.slice(1)).get('access');
const $ = (id) => document.getElementById(id);
let snapshot = {collections: [], resources: [], grants: [], audit: []};

function notice(message, type = 'ok') {
  const box = $('notice');
  box.textContent = message;
  box.className = `notice ${type}`;
}

async function call(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${ownerToken}`);
  const response = await fetch(path, {...options, headers, cache: 'no-store'});
  if (!response.ok) {
    let detail = `Errore ${response.status}`;
    try { detail = (await response.json()).detail || detail; } catch (_) { /* Preserve status. */ }
    throw new Error(detail);
  }
  return response;
}

function element(tag, text, className = '') {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) node.className = className;
  return node;
}

function empty(container, message) {
  container.replaceChildren(element('div', message, 'empty'));
}

function option(select, value, label) {
  const entry = document.createElement('option');
  entry.value = value;
  entry.textContent = label;
  select.append(entry);
}

function date(value) { return new Date(value * 1000).toLocaleString('it-IT'); }

function render() {
  const now = Date.now() / 1000;
  const active = snapshot.grants.filter((g) => !g.revoked_at && g.expires_at > now);
  $('count-collections').textContent = snapshot.collections.length;
  $('count-resources').textContent = snapshot.resources.length;
  $('count-grants').textContent = active.length;

  const collectionList = $('collections-list');
  collectionList.replaceChildren();
  if (!snapshot.collections.length) empty(collectionList, 'Nessuna raccolta creata.');
  for (const collection of snapshot.collections) {
    const record = element('div', '', 'record');
    const info = document.createElement('div');
    info.append(element('strong', collection.name));
    const count = snapshot.resources.filter((r) => r.collection_id === collection.id).length;
    info.append(element('small', `${count} documenti`));
    record.append(info);
    collectionList.append(record);
  }

  for (const id of ['import-collection', 'grant-collection']) {
    const select = $(id);
    const selected = select.value;
    select.replaceChildren();
    for (const collection of snapshot.collections) option(select, collection.id, collection.name);
    if (snapshot.collections.some((c) => c.id === selected)) select.value = selected;
  }
  $('import-form').querySelector('button').disabled = !snapshot.collections.length;
  $('grant-form').querySelector('button').disabled = !snapshot.collections.length;

  const grantList = $('grants-list');
  grantList.replaceChildren();
  if (!snapshot.grants.length) empty(grantList, 'Nessuna delega creata.');
  for (const grant of snapshot.grants) {
    const collection = snapshot.collections.find((c) => c.id === grant.collection_id);
    const status = grant.revoked_at ? 'Revocata' : grant.expires_at <= now ? 'Scaduta' : 'Attiva';
    const record = element('div', '', 'record');
    const info = document.createElement('div');
    info.append(element('strong', grant.app_name));
    info.append(element('small', `${collection?.name || 'Raccolta rimossa'} · ${grant.purpose}`));
    info.append(element('small', `${status} · Scadenza ${date(grant.expires_at)}`));
    record.append(info);
    if (status === 'Attiva') {
      const button = element('button', 'Revoca');
      button.type = 'button';
      button.addEventListener('click', async () => {
        if (!window.confirm(`Revocare l'accesso a ${grant.app_name}?`)) return;
        try {
          await call(`/admin/grants/${grant.id}/revoke`, {method: 'POST'});
          notice('Delega revocata. Le nuove richieste verranno rifiutate.');
          await refresh();
        } catch (error) { notice(error.message, 'error'); }
      });
      record.append(button);
    }
    grantList.append(record);
  }

  const auditList = $('audit-list');
  auditList.replaceChildren();
  if (!snapshot.audit.length) empty(auditList, 'Nessun evento registrato.');
  for (const item of snapshot.audit.slice(0, 50)) {
    const record = element('div', '', 'record');
    const grant = snapshot.grants.find((g) => g.id === item.grant_id);
    const result = item.outcome === 'allowed' ? 'Consentito' : 'Negato';
    record.append(element('strong', `${item.event} · ${result}`));
    record.append(element('small', `${date(item.at)}${grant ? ` · ${grant.app_name}` : ''}`));
    auditList.append(record);
  }
}

async function refresh() {
  snapshot = await (await call('/admin/state')).json();
  render();
}

$('collection-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const name = $('collection-name').value;
    await call('/admin/collections', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({name})});
    $('collection-form').reset();
    notice('Raccolta creata.');
    await refresh();
  } catch (error) { notice(error.message, 'error'); }
});

$('import-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const files = [...$('import-files').files];
  const collection = $('import-collection').value;
  try {
    for (const file of files) {
      await call(`/admin/collections/${collection}/resources`, {
        method: 'POST', headers: {'X-File-Name': encodeURIComponent(file.name), 'Content-Type': 'application/octet-stream'}, body: file,
      });
    }
    $('import-files').value = '';
    notice(`${files.length} ${files.length === 1 ? 'documento importato' : 'documenti importati'}.`);
    await refresh();
  } catch (error) { notice(`Importazione interrotta: ${error.message}`, 'error'); await refresh(); }
});

$('grant-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const payload = {
      app_name: $('grant-app').value,
      purpose: $('grant-purpose').value,
      collection_id: $('grant-collection').value,
      duration_minutes: Number($('grant-duration').value),
    };
    const grant = await (await call('/admin/grants', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)})).json();
    $('new-token').hidden = false;
    $('token-value').value = grant.token;
    notice('Delega creata. Copia il token: verrà mostrato solo adesso.');
    await refresh();
  } catch (error) { notice(error.message, 'error'); }
});

$('copy-token').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('token-value').value); notice('Token copiato.'); }
  catch (_) { $('token-value').select(); notice('Seleziona e copia il token manualmente.', 'error'); }
});

$('export-button').addEventListener('click', async () => {
  try {
    const response = await call('/admin/export');
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement('a');
    link.href = url;
    link.download = 'datasovereign-export.zip';
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 60000);
    notice('Export scaricato. Il file ZIP contiene documenti in chiaro.');
    await refresh();
  } catch (error) { notice(error.message, 'error'); }
});

if (!ownerToken) {
  $('auth-note').hidden = false;
} else {
  $('workspace').hidden = false;
  refresh().catch((error) => { $('workspace').hidden = true; notice(error.message, 'error'); });
}
