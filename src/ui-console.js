// Interface de la tablette (console de commandement)
import * as db from './db.js';
import { icon } from './icons.js';
import { $, $$, esc, fmtDur, fmtClock, fmtDate, fmtStamp, fmtFileStamp, fmtSize, fmtGo, extFor, download, toast, drawQR, scanQR, VERSION, kv } from './util.js';

const resLabel = (w, h) => { const m = Math.min(w || 0, h || 0); if (!m) return '—'; if (m >= 1000) return `${m}p (FHD)`; if (m >= 700) return `${m}p (HD)`; return `${m}p`; };
const mbps = (k) => (k >= 1000 ? `${(k / 1000).toFixed(1).replace('.', ',')} Mb/s` : `${Math.round(k)} kb/s`);
const slug = (s) => String(s || 'CAM').normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^\w-]+/g, '_');
const vname = (r) => `HXC_${slug(r.camName)}_${fmtFileStamp(new Date(r.t0))}`;

export function mountConsole(root, hub, app) {
  let view = 'live', lib = 'videos', mosaic = false, speaker = true, urgArm = 0, urls = [], pairCtl = null;

  root.innerHTML = `
  <div class="console" id="console">
    <header class="top">
      <div class="brand"><img src="img/logo-mark.png" alt="" width="56" height="52"><div class="wordmark"><span class="b1">HEXACORE</span><span class="b2">BODYCAM</span></div></div>
      <div class="stat rec" id="st-rec"><i class="dot"></i><div><div class="lbl" id="rec-l">Prêt à enregistrer</div><div class="val tnum" id="rec-t">00:00:00</div></div></div>
      <div class="stat" id="st-cam"><i class="dot" id="cam-d"></i><div><div class="lbl" id="cam-l">Aucune caméra</div><div class="sub" id="cam-s">Associez un téléphone</div></div></div>
      <div class="stat bat"><div><div class="lbl">Batterie caméra</div><div class="batrow"><span class="bar" id="bat-bar"><i style="width:0"></i></span><span class="val tnum" id="bat-v">—</span></div></div></div>
      <div class="clock"><div class="time tnum" id="clk-t">--:--</div><div class="date" id="clk-d"></div></div>
    </header>
    <nav class="side" aria-label="Navigation principale">
      <div class="nav">
        <button data-a="nav" data-v="live">${icon('videoFill')}<span>Live view</span></button>
        <button data-a="nav" data-v="rec">${icon('play')}<span>Enregistrements</span></button>
        <button data-a="nav" data-v="arch">${icon('folder')}<span>Archives</span></button>
        <button data-a="nav" data-v="status">${icon('bars')}<span>Statut système</span></button>
        <button data-a="nav" data-v="settings">${icon('gear')}<span>Paramètres</span></button>
      </div>
      <div class="sig"><div class="n">HEXACORE</div><div class="f">FIELD SOLUTIONS</div></div>
    </nav>
    <main class="view" id="view"></main>
    <footer class="foot"><div class="ok" id="foot-s">${icon('shield')}<span>Système opérationnel</span></div><div>HEXACORE BODYCAM v${VERSION}</div></footer>
  </div>
  <div id="overlays"></div>`;

  const view$ = $('#view');
  const revoke = () => { urls.forEach(URL.revokeObjectURL); urls = []; };
  const objUrl = (b) => { const u = URL.createObjectURL(b); urls.push(u); return u; };

  // ---------- Navigation ----------
  function go(v) {
    view = v; revoke();
    $$('.nav button').forEach((b) => b.setAttribute('aria-current', b.dataset.v === v ? 'page' : 'false'));
    ({ live: renderLive, rec: () => renderLib(false), arch: () => renderLib(true), status: renderStatus, settings: renderSettings })[v]();
    tick();
  }

  // ---------- LIVE VIEW ----------
  function renderLive() {
    view$.innerHTML = `
    <section class="live">
      <div class="stagewrap">
        <div class="camstrip" id="strip"></div>
        <div class="stage" id="stage"></div>
      </div>
      <aside class="info" aria-label="Informations caméra">
        <h3>${icon('info')}Informations caméra</h3>
        <dl class="kv"><dt>Modèle :</dt><dd id="i-model">—</dd><dt>Résolution :</dt><dd id="i-res">—</dd><dt>FPS :</dt><dd id="i-fps">—</dd><dt>Orientation :</dt><dd id="i-ori">—</dd><dt>Stockage libre :</dt><dd id="i-sto">—</dd></dl>
        <dl class="kv sep"><dt>${icon('wifi')}Connexion :</dt><dd id="i-con" class="off">—</dd><dt>&nbsp;&nbsp;&nbsp;&nbsp;Latence :</dt><dd id="i-lat">—</dd><dt>&nbsp;&nbsp;&nbsp;&nbsp;Débit :</dt><dd id="i-br">—</dd></dl>
        <div class="gpsh">${icon('pin')}<span>GPS (si disponible)</span></div>
        <dl class="kv"><dt>Latitude :</dt><dd id="i-lat1">—</dd><dt>Longitude :</dt><dd id="i-lon">—</dd></dl>
      </aside>
      <div class="actions">
        <button class="act rec" data-a="rec" id="b-rec"></button><span class="sep"></span>
        <button class="act photo" data-a="photo" id="b-photo">${icon('camera')}<span>Capture<br>photo</span></button><span class="sep"></span>
        <button class="act mic" data-a="mic" id="b-mic" aria-pressed="true"><span class="on">${icon('mic')}</span><span class="off">${icon('micOff')}</span><span id="b-mic-t">Micro<br>(on)</span></button><span class="sep"></span>
        <button class="act mark" data-a="mark" id="b-mark">${icon('flag')}<span>Repère</span></button><span class="sep"></span>
        <button class="act urg" data-a="urg" id="b-urg">${icon('warn')}<span id="b-urg-t">Urgence</span></button>
      </div>
    </section>`;
    renderStrip(); renderStage();
  }

  function renderStrip() {
    const el = $('#strip'); if (!el) return;
    const sel = hub.selected;
    const html = hub.any.map((l) => `<button class="chip" data-a="cam" data-k="${l.key}" aria-pressed="${sel === l}"><i class="dot ${l.state === 'connected' ? 'green' : l.state === 'unstable' ? 'amber' : 'red'}"></i>${esc(l.name)}${l.recording ? '<span class="rc">● REC</span>' : ''}</button>`).join('')
      + `<button class="chip add" data-a="add">${icon('plus')}Caméra</button>`
      + (hub.ready.length > 1 ? `<button class="chip" data-a="mosaic" aria-pressed="${mosaic}" style="margin-left:auto">${icon('grid')}Mosaïque</button>` : '');
    if (el.dataset.h !== html) { el.dataset.h = html; el.innerHTML = html; }
  }

  let stageKey = '';
  function renderStage() {
    const st = $('#stage'); if (!st) return;
    const sel = hub.selected, ready = hub.ready;
    const key = [sel?.key, mosaic && ready.length > 1, ready.map((l) => l.key).join()].join('|');
    if (key === stageKey && st.children.length) return;
    stageKey = key;
    if (!hub.any.length) {
      st.innerHTML = `<div class="empty"><div class="ring">${icon('videoFill')}</div><h3>Aucune caméra liée</h3>
        <p>Lancez HEXACORE sur le téléphone du joueur (rôle Caméra), touchez « Associer », puis scannez son QR code ici. Aucun Internet n’est nécessaire.</p>
        <div class="btnrow" style="display:flex;gap:.8rem;flex-wrap:wrap;justify-content:center"><button class="btn pri" data-a="add">${icon('qr')}Ajouter une caméra</button><button class="btn" data-a="demo">${icon('phone')}Tester avec cet appareil</button></div></div>`;
      return;
    }
    if (mosaic && ready.length > 1) {
      const n = ready.length, cols = n <= 2 ? n : n <= 4 ? 2 : 3;
      st.innerHTML = `<div class="mosaic" style="grid-template-columns:repeat(${cols},1fr)">${ready.map((l) => `<div class="tile ${l.recording ? 'rec' : ''}" data-a="tile" data-k="${l.key}" aria-current="${l === sel}"><video autoplay playsinline muted data-k="${l.key}"></video><span class="cap">${esc(l.name)}</span></div>`).join('')}</div>`;
      $$('video', st).forEach((v) => { const l = hub.links.find((x) => x.key === v.dataset.k); v.srcObject = l.stream; v.play().catch(() => {}); });
      return;
    }
    st.innerHTML = `<video id="sv" autoplay playsinline></video>
      <div class="hud tl"><span class="tag" id="h-res">—</span><span class="tag" id="h-fps">—</span></div>
      <div class="hud tr"><span class="live-tag off" id="h-live"><i></i><span>LIVE</span></span></div>
      <div class="hud bl"><span class="camname" id="h-name"></span></div>
      <div class="hud" style="right:.8rem;bottom:.8rem;gap:.5rem"><button class="ib" data-a="speaker" id="b-spk" aria-label="Son du flux" aria-pressed="${speaker}">${icon(speaker ? 'speaker' : 'speakerOff')}</button></div>
      <div class="empty" id="wait" style="display:none"><div class="ring">${icon('videoFill')}</div><h3 id="wait-t">Réception du flux…</h3><p id="wait-p"></p></div>`;
    const v = $('#sv'); v.muted = !speaker;
    if (sel) { v.srcObject = sel.stream; v.play().catch(() => { v.muted = true; v.play().catch(() => {}); }); }
  }

  // ---------- Boucle d'actualisation ----------
  function tick() {
    const now = new Date();
    $('#clk-t').textContent = fmtClock(now); $('#clk-d').textContent = fmtDate(now);
    const l = hub.selected, tel = l?.tel;
    const recOn = !!(l && (l.recording || tel?.rec));
    const sr = $('#st-rec'); sr.classList.toggle('on', recOn);
    $('#rec-l').textContent = recOn ? 'Enregistrement en cours' : 'Prêt à enregistrer';
    $('#rec-t').textContent = fmtDur(recOn ? (l.rec?.active ? l.rec.elapsed : tel?.recMs || 0) : 0);
    $('.dot', sr).className = 'dot ' + (recOn ? 'red' : '');
    // caméra
    const cd = $('#cam-d'), cl = $('#cam-l'), cs = $('#cam-s');
    if (!hub.any.length) { cd.className = 'dot'; cl.textContent = 'Aucune caméra'; cs.textContent = 'Associez un téléphone'; }
    else if (l) {
      const extra = hub.ready.length > 1 ? ` · ${hub.ready.length} caméras` : '';
      if (l.state === 'lost') { cd.className = 'dot red'; cl.textContent = 'Liaison perdue'; cs.textContent = `${l.name} · ré-associez la caméra`; }
      else if (l.state === 'unstable') { cd.className = 'dot amber'; cl.textContent = 'Liaison instable'; cs.textContent = l.name; }
      else { cd.className = 'dot green'; cl.textContent = 'Caméra connectée'; cs.textContent = `${l.name}${extra}${l.rtt != null ? ` · ${Math.round(l.rtt)} ms` : ''}`; }
    }
    const bat = tel?.bat, bb = $('#bat-bar');
    $('#bat-v').textContent = bat != null ? `${bat} %` : '—';
    bb.className = 'bar ' + (bat != null && bat < 20 ? 'low' : bat != null && bat < 40 ? 'mid' : '');
    $('i', bb).style.width = (bat ?? 0) + '%';
    // pied de page
    const fs = $('#foot-s'), alerting = hub.alerts.length;
    fs.className = 'ok ' + (alerting ? 'alert' : !hub.any.length || (l && l.state !== 'connected') ? 'warn' : '');
    $('span', fs).textContent = alerting ? 'Alerte urgence active' : !hub.any.length ? 'En attente de caméra' : l?.state === 'lost' ? 'Liaison perdue' : l?.state === 'unstable' ? 'Liaison instable' : 'Système opérationnel';

    if (view === 'live') tickLive(l, tel, recOn);
    else if (view === 'status') renderStatus();
  }

  function tickLive(l, tel, recOn) {
    renderStrip(); renderStage();
    const set = (id, t, cls) => { const e = $('#' + id); if (e) { e.textContent = t; if (cls != null) e.className = cls; } };
    const w = tel?.w || l?.w, h = tel?.h || l?.h;
    set('i-model', l?.model || '—'); set('i-res', l ? resLabel(w, h) : '—'); set('i-fps', tel ? `${tel.fps} ips` : '—');
    set('i-ori', w && h ? (h > w ? 'Portrait' : 'Paysage') : '—');
    set('i-sto', tel?.st?.quota ? `${fmtGo(Math.max(0, tel.st.quota - tel.st.usage))} / ${fmtGo(tel.st.quota)}` : '—');
    const q = l?.quality || { label: '—', cls: 'off' };
    set('i-con', q.label, q.cls); set('i-lat', l?.rtt != null ? `${Math.round(l.rtt)} ms` : '—'); set('i-br', l?.connected ? mbps(l.kbps) : '—');
    set('i-lat1', tel?.gps ? tel.gps.lat.toFixed(4) : 'Indisponible'); set('i-lon', tel?.gps ? tel.gps.lon.toFixed(4) : 'Indisponible');
    set('h-res', l ? `${Math.min(w || 0, h || 0) || '—'}p` : '—'); set('h-fps', l?.fps || tel?.fps ? `${l?.fps || tel?.fps} FPS` : '—');
    const live = $('#h-live'); if (live) { live.className = 'live-tag' + (l?.connected && l.kbps > 20 ? '' : ' off'); }
    set('h-name', l?.name || '');
    const wait = $('#wait');
    if (wait && l) {
      const noVideo = !l.stream.getVideoTracks().length || (l.connected && l.kbps < 5 && !l.fps);
      wait.style.display = l.state === 'lost' || noVideo ? '' : 'none';
      if (l.state === 'lost') { set('wait-t', 'Liaison perdue'); set('wait-p', 'La caméra continue d’enregistrer en local. Rapprochez-vous puis ré-associez-la (Caméra → Associer).'); }
      else if (noVideo) { set('wait-t', 'Réception du flux…'); set('wait-p', ''); }
    }
    // boutons
    const br = $('#b-rec'), connected = !!l?.connected;
    br.disabled = !connected;
    br.className = 'act rec' + (recOn ? ' on' : '');
    br.innerHTML = `<span class="rcirc ${recOn ? 'sq' : ''}"></span><span>${recOn ? 'Arrêter<br>l’enregistrement' : 'Démarrer<br>l’enregistrement'}</span>`;
    for (const id of ['b-photo', 'b-mic', 'b-mark', 'b-urg']) $('#' + id).disabled = !connected;
    const mic = tel?.mic ?? true; const bm = $('#b-mic'); bm.setAttribute('aria-pressed', mic); $('#b-mic-t').innerHTML = `Micro<br>(${mic ? 'on' : 'off'})`;
    if (urgArm && Date.now() > urgArm) { urgArm = 0; }
    const bu = $('#b-urg'); bu.classList.toggle('armed', !!urgArm); $('#b-urg-t').textContent = urgArm ? 'Confirmer ?' : 'Urgence';
  }

  // ---------- Bibliothèque (enregistrements / archives) ----------
  async function renderLib(archived) {
    revoke();
    view$.innerHTML = `<div class="page"><div class="page-h"><div><h2>${archived ? 'Archives' : 'Enregistrements'}</h2><div class="sub">${archived ? 'Éléments conservés hors de la liste courante.' : 'Copies enregistrées sur la tablette. Chaque fichier est horodaté et référence ses repères.'}</div></div>
      <div class="seg"><button data-a="lib" data-t="videos" aria-pressed="${lib === 'videos'}">Vidéos</button><button data-a="lib" data-t="photos" aria-pressed="${lib === 'photos'}">Photos</button></div></div><div id="lib"></div></div>`;
    const host = $('#lib');
    if (lib === 'videos') {
      const all = (await db.getAll('recordings')).filter((r) => r.origin === 'console' && !!r.archived === archived && r.t1 != null).sort((a, b) => b.t0 - a.t0);
      if (view !== (archived ? 'arch' : 'rec')) return;
      if (!all.length) { host.innerHTML = emptyList(archived ? 'Aucune archive' : 'Aucun enregistrement', archived ? 'Archivez un enregistrement pour le retrouver ici.' : 'Démarrez un enregistrement depuis le Live view : une copie sera conservée sur cette tablette.', 'play'); return; }
      host.innerHTML = `<div class="grid">${all.map((r) => `<article class="card"><button class="th" data-a="play" data-id="${r.id}" aria-label="Lire ${esc(vname(r))}" style="${r.thumb ? `background-image:url(${r.thumb})` : ''}">${r.thumb ? '' : icon('videoFill')}<span class="pl">${icon('play', 'fill')}</span><span class="du tnum">${fmtDur(r.dur)}</span></button>
        <div class="bd"><div class="nm">${esc(r.camName)}${r.recovered ? ' · récupéré' : ''}</div><div class="mt"><span>${fmtStamp(new Date(r.t0))}</span><span>${fmtSize(r.size)}</span>${r.markers?.length ? `<span>${r.markers.length} repère${r.markers.length > 1 ? 's' : ''}</span>` : ''}</div></div>
        <div class="ac"><button class="btn sm" data-a="play" data-id="${r.id}">${icon('play')}Lire</button><button class="btn sm" data-a="export" data-id="${r.id}">${icon('download')}Exporter</button><button class="btn sm" data-a="arc" data-id="${r.id}">${icon(archived ? 'unarchive' : 'archive')}${archived ? 'Restaurer' : 'Archiver'}</button><button class="btn sm danger" data-a="del" data-id="${r.id}">${icon('trash')}</button></div></article>`).join('')}</div>`;
    } else {
      const all = (await db.getAll('photos')).filter((p) => p.origin === 'console' && !!p.archived === archived).sort((a, b) => b.t - a.t);
      if (view !== (archived ? 'arch' : 'rec')) return;
      if (!all.length) { host.innerHTML = emptyList('Aucune photo', 'Utilisez « Capture photo » : la photo horodatée est envoyée à la tablette.', 'photo'); return; }
      host.innerHTML = `<div class="grid">${all.map((p) => { const u = objUrl(p.blob); return `<article class="card"><button class="th" data-a="viewphoto" data-id="${p.id}" style="background-image:url(${u})" aria-label="Agrandir la photo"><span class="pl">${icon('photo')}</span></button><div class="bd"><div class="nm">${esc(p.camName)}</div><div class="mt"><span>${fmtStamp(new Date(p.t))}</span><span>${fmtSize(p.size)}</span></div></div>
        <div class="ac"><button class="btn sm" data-a="expphoto" data-id="${p.id}">${icon('download')}Exporter</button><button class="btn sm" data-a="arcphoto" data-id="${p.id}">${icon(archived ? 'unarchive' : 'archive')}${archived ? 'Restaurer' : 'Archiver'}</button><button class="btn sm danger" data-a="delphoto" data-id="${p.id}">${icon('trash')}</button></div></article>`; }).join('')}</div>`;
    }
  }
  const emptyList = (t, d, ic) => `<div class="empty-list">${icon(ic)}<b>${t}</b>${d}</div>`;

  async function openPlayer(id) {
    const r = await db.get('recordings', id); if (!r) return;
    const blob = await db.recordingBlob(r); const u = objUrl(blob);
    const m = modal(`<div class="dlg wide"><h3><span>${esc(vname(r))}</span><button class="x" data-a="close" aria-label="Fermer">${icon('x')}</button></h3>
      <div class="player"><video id="pv" controls playsinline src="${u}"></video>
      <aside><dl class="kv" style="margin:0"><dt>Caméra</dt><dd>${esc(r.camName)}</dd><dt>Début</dt><dd>${fmtStamp(new Date(r.t0))}</dd><dt>Durée</dt><dd class="tnum">${fmtDur(r.dur)}</dd><dt>Taille</dt><dd>${fmtSize(r.size)}</dd><dt>Format</dt><dd>${esc((r.mime || '').split(';')[0])}</dd>${r.gps ? `<dt>Position</dt><dd>${r.gps.lat.toFixed(4)}, ${r.gps.lon.toFixed(4)}</dd>` : ''}</dl>
      <div><div class="lbl" style="margin-bottom:.5rem">Repères (${r.markers?.length || 0})</div><div class="mk">${(r.markers || []).map((k) => `<button data-a="seek" data-s="${k.at / 1000}"><b class="tnum">${fmtDur(k.at)}</b><span>${esc(k.label)}</span></button>`).join('') || '<span class="sub">Aucun repère</span>'}</div></div>
      <button class="btn sm" data-a="hash" id="hashb">${icon('shield')}Empreinte SHA-256</button><code id="hashv" style="font-size:.7rem;word-break:break-all;color:var(--mut)"></code>
      <button class="btn" data-a="export" data-id="${r.id}">${icon('download')}Exporter le fichier</button></aside></div></div>`);
    const v = $('#pv', m);
    v.addEventListener('loadedmetadata', () => { if (v.duration === Infinity) { v.currentTime = 1e101; v.addEventListener('timeupdate', function f() { v.removeEventListener('timeupdate', f); v.currentTime = 0; }); } });
    m.addEventListener('click', async (e) => {
      const b = e.target.closest('[data-a]'); if (!b) return;
      if (b.dataset.a === 'seek') { v.currentTime = +b.dataset.s; v.play(); }
      if (b.dataset.a === 'hash') { $('#hashv', m).textContent = 'Calcul…'; const buf = await blob.arrayBuffer(); const d = await crypto.subtle.digest('SHA-256', buf); $('#hashv', m).textContent = [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, '0')).join(''); }
    });
  }

  // ---------- Statut système ----------
  async function renderStatus() {
    const est = await navigator.storage?.estimate?.().catch(() => null);
    let batt = null; try { const b = await navigator.getBattery?.(); if (b) batt = `${Math.round(b.level * 100)} %${b.charging ? ' (en charge)' : ''}`; } catch { /* ok */ }
    const persistent = await db.isPersistent();
    if (view !== 'status') return;
    const cam = (l) => `<div class="panel"><h3><i class="dot ${l.state === 'connected' ? 'green' : l.state === 'unstable' ? 'amber' : 'red'}"></i>${esc(l.name)}</h3><div class="sub">${esc(l.model)}</div>
      <dl class="kv"><dt>Liaison</dt><dd class="${l.quality.cls}">${l.quality.label}</dd><dt>Latence</dt><dd>${l.rtt != null ? Math.round(l.rtt) + ' ms' : '—'}</dd><dt>Débit vidéo</dt><dd>${l.connected ? mbps(l.kbps) : '—'}</dd><dt>Perte de paquets</dt><dd>${l.lossPct.toFixed(1).replace('.', ',')} %</dd><dt>Flux</dt><dd>${resLabel(l.w, l.h)} · ${l.fps || '—'} ips</dd><dt>Batterie</dt><dd>${l.tel?.bat != null ? l.tel.bat + ' %' + (l.tel.chg ? ' ⚡' : '') : '—'}</dd><dt>Enregistrement</dt><dd>${l.recording || l.tel?.rec ? 'En cours' : 'Arrêté'}</dd><dt>Stockage caméra</dt><dd>${l.tel?.st?.quota ? fmtGo(l.tel.st.quota - l.tel.st.usage) + ' libres' : '—'}</dd></dl></div>`;
    view$.innerHTML = `<div class="page"><div class="page-h"><div><h2>Statut système</h2><div class="sub">État de la tablette, des liaisons et journal horodaté.</div></div></div>
      <div class="cards3"><div class="panel"><h3>${icon('tablet')}Poste · ${esc(hub.s.name)}</h3><dl class="kv"><dt>Batterie tablette</dt><dd>${batt || '—'}</dd><dt>Stockage utilisé</dt><dd>${est ? fmtSize(est.usage) + ' / ' + fmtGo(est.quota) : '—'}</dd><dt>Base locale</dt><dd class="${persistent ? 'good' : 'bad'}">${persistent ? 'Persistante' : 'Mémoire (non persistante)'}</dd><dt>Internet</dt><dd>${navigator.onLine ? 'Disponible (non requis)' : 'Hors ligne (mode normal)'}</dd><dt>Application hors ligne</dt><dd class="${app.offlineReady ? 'good' : 'off'}">${app.offlineReady ? 'Installée' : 'Non installée'}</dd><dt>Version</dt><dd>${VERSION}</dd></dl></div>
      ${hub.any.map(cam).join('')}</div>
      <div class="panel log"><h3>${icon('bars')}Journal d’événements</h3><ol>${hub.logs.slice(0, 40).map((e) => `<li class="${e.type}"><time class="tnum">${fmtStamp(new Date(e.t)).slice(11)}</time><span>${esc(e.text)}</span></li>`).join('') || '<li><span class="sub">Aucun événement</span></li>'}</ol></div></div>`;
  }

  // ---------- Paramètres ----------
  function renderSettings() {
    const s = hub.s;
    const tg = (k, t, d) => `<div class="row"><div><div class="t">${t}</div><div class="d">${d}</div></div><button class="tgl" role="switch" aria-checked="${!!s[k]}" data-a="tgl" data-k="${k}" aria-label="${t}"></button></div>`;
    view$.innerHTML = `<div class="page"><div class="page-h"><div><h2>Paramètres</h2><div class="sub">Réglages du poste de commandement.</div></div></div>
      <div class="set">
      <div class="panel"><h3>Poste</h3><div class="row"><div><div class="t">Nom du poste</div><div class="d">Affiché sur les caméras liées.</div></div><input class="inp" id="s-name" value="${esc(s.name)}" maxlength="24" aria-label="Nom du poste"></div></div>
      <div class="panel"><h3>Enregistrement</h3>
        ${tg('autoRec', 'Enregistrer dès la liaison', 'Démarre automatiquement l’enregistrement quand une caméra se connecte.')}
        ${tg('emergencyRec', 'Urgence : enregistrer automatiquement', 'Le bouton Urgence lance l’enregistrement et pose un repère sur la caméra ciblée.')}
        ${tg('overlay', 'Incrustation horodatée', 'Nom de la caméra, date, heure (synchronisée sur la tablette) et GPS gravés dans la vidéo.')}
      </div>
      <div class="panel"><h3>Alertes</h3>${tg('sound', 'Son d’alerte', 'Bip et vibration à la réception d’une urgence joueur.')}</div>
      <div class="panel"><h3>Qualité de liaison</h3><div class="row"><div><div class="t">Qualité demandée aux caméras</div><div class="d">720p est plus fiable à distance ; 1080p demande une liaison forte. L’enregistrement local de la caméra suit le même réglage.</div></div><select class="sel" id="s-q" aria-label="Qualité">${['480p', '720p', '1080p'].map((q) => `<option ${s.quality === q ? 'selected' : ''}>${q}</option>`).join('')}</select></div><div style="padding-top:.8rem"><button class="btn" data-a="applyq">Appliquer aux caméras liées</button></div></div>
      <div class="panel"><h3>Données</h3><div class="row"><div><div class="t">Tout effacer</div><div class="d">Supprime enregistrements, photos et journal de cette tablette. Irréversible.</div></div><button class="btn danger" data-a="wipe" id="wipeb">${icon('trash')}Effacer</button></div>
        <div class="row"><div><div class="t">Changer de rôle</div><div class="d">Revenir à l’écran de choix Console / Caméra.</div></div><button class="btn" data-a="role">Changer</button></div></div>
      <div class="panel"><h3>${icon('shield')}À savoir</h3><p class="sub" style="line-height:1.55;font-size:.88rem">Le bouton Urgence est une alerte de jeu entre joueurs, pas un appel aux secours : en cas de blessure réelle, appelez le 112. Enregistrez uniquement avec l’accord des participants et de l’organisateur.</p></div>
      </div></div>`;
    $('#s-name').addEventListener('input', (e) => { hub.s.name = e.target.value.trim() || 'POSTE TAC'; hub.saveSettings(); });
    $('#s-q').addEventListener('change', (e) => { hub.s.quality = e.target.value; hub.saveSettings(); });
  }

  // ---------- Modales ----------
  function modal(html) {
    const m = document.createElement('div'); m.className = 'modal'; m.innerHTML = html;
    m.addEventListener('click', (e) => { if (e.target === m || e.target.closest('[data-a=close]')) { m.remove(); pairCleanup(); } });
    $('#overlays').appendChild(m); return m;
  }
  const pairCleanup = () => { if (pairCtl) { pairCtl.stop(); pairCtl = null; } };

  function openPair() {
    const m = modal(`<div class="dlg"><h3><span>Ajouter une caméra</span><button class="x" data-a="close" aria-label="Fermer">${icon('x')}</button></h3>
      <div class="steps"><span class="on" id="ps1"></span><span id="ps2"></span><span id="ps3"></span></div><div id="pair-body"></div></div>`);
    const body = $('#pair-body', m);
    let stream = null, stopScan = null, pending = null;
    const killCam = () => { stopScan?.(); stopScan = null; stream?.getTracks().forEach((t) => t.stop()); stream = null; };
    pairCtl = { stop: () => { killCam(); if (pending && !pending.id) hub.removeLink(pending); } };

    async function accept(code) {
      killCam();
      body.innerHTML = `<div class="wait"><div class="spin"></div>Création de la liaison…</div>`;
      pending = hub.newLink();
      try {
        const answer = await pending.accept(code);
        $('#ps2', m).classList.add('on');
        body.innerHTML = `<p class="lead">Présentez ce QR code à la caméra du téléphone (touchez « Scanner la réponse »). La liaison démarre automatiquement.</p>
          <div class="qrbox"><canvas id="aq" aria-label="QR code de réponse"></canvas></div>
          <div class="wait"><div class="spin"></div>En attente du téléphone…</div>
          <details class="guide" style="margin-top:1rem"><summary>Pas de scan possible ? Copier le code</summary><textarea class="inp" readonly id="acode" style="margin-bottom:12px">${answer}</textarea><button class="btn sm" data-a="copyc">${icon('copy')}Copier</button></details>`;
        drawQR($('#aq', m), answer, 360);
        const link = pending;
        const done = () => { if (!link.id) return; link.removeEventListener('hello', done); $('#ps3', m).classList.add('on'); toast(`${link.name} liée`, 'ok'); hub.select(link.key); pairCtl = null; m.remove(); go('live'); };
        link.addEventListener('hello', done);
        setTimeout(() => { if (!link.id && document.body.contains(m)) { const w = $('.wait', m); if (w) w.innerHTML = '<span style="color:var(--amber)">Toujours en attente. Vérifiez que les deux appareils sont sur le même réseau local (point d’accès de la tablette) puis recommencez.</span>'; } }, 25000);
      } catch (e) {
        hub.removeLink(pending); pending = null;
        toast(e.message || 'Code invalide', 'error'); startScan();
      }
    }

    async function startScan() {
      body.innerHTML = `<p class="lead">Sur le téléphone : rôle Caméra, démarrer, puis « Associer ». Cadrez son QR code avec la tablette.</p>
        <div class="scanbox"><video id="sv2" playsinline muted autoplay></video><div class="ms" id="scanms" style="display:none"></div></div>
        <div style="display:flex;gap:.6rem;margin-top:1rem;flex-wrap:wrap"><button class="btn" data-a="manual">${icon('link')}Saisir un code</button></div>`;
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 } }, audio: false });
        const v = $('#sv2', m); v.srcObject = stream; await v.play();
        stopScan = scanQR(v, accept);
      } catch {
        const ms = $('#scanms', m); ms.style.display = 'grid'; ms.textContent = 'Caméra de la tablette indisponible. Utilisez « Saisir un code ».';
      }
    }
    m.addEventListener('click', (e) => {
      const b = e.target.closest('[data-a]'); if (!b) return;
      if (b.dataset.a === 'manual') { killCam(); body.innerHTML = `<p class="lead">Collez le code affiché par le téléphone (« Copier mon code »).</p><textarea class="inp" id="mcode" placeholder="HXC1.…"></textarea><div style="display:flex;gap:.6rem;margin-top:1rem"><button class="btn pri" data-a="mgo">Valider</button><button class="btn" data-a="mback">${icon('qr')}Scanner</button></div>`; }
      if (b.dataset.a === 'mgo') accept($('#mcode', m).value);
      if (b.dataset.a === 'mback') startScan();
      if (b.dataset.a === 'copyc') { navigator.clipboard?.writeText($('#acode', m).value).then(() => toast('Code copié', 'ok')).catch(() => { $('#acode', m).select(); }); }
    });
    startScan();
    window.__pair = { accept }; // utilisé pour les tests automatisés
  }

  // ---------- Alerte urgence ----------
  function renderAlerts() {
    const host = $('#overlays');
    host.querySelector('.alertov')?.remove();
    const a = hub.alerts[0]; if (!a) return;
    const el = document.createElement('div'); el.className = 'alertov'; el.setAttribute('role', 'alertdialog'); el.setAttribute('aria-label', 'Urgence');
    el.innerHTML = `<div class="box">${icon('warn')}<div class="big">URGENCE</div><div class="who">${esc(a.name)}</div><div class="sub">${fmtStamp(new Date(a.at)).slice(11)}${a.gps ? ` · ${a.gps.lat.toFixed(4)}, ${a.gps.lon.toFixed(4)}` : ''}</div>
      <div class="btns"><button class="btn" data-a="alertview" data-k="${a.key}">${icon('videoFill')}Voir le flux</button><button class="btn pri" data-a="ack" data-k="${a.key}">Acquitter</button></div></div>`;
    $('svg', el).style.cssText = 'width:4rem;height:4rem;color:#fff;margin:auto';
    host.appendChild(el);
  }

  // ---------- Actions ----------
  const confirmTap = (btn, fn) => {
    if (btn.dataset.armed) { fn(); return; }
    btn.dataset.armed = '1'; const o = btn.innerHTML; btn.innerHTML = 'Confirmer ?';
    setTimeout(() => { delete btn.dataset.armed; if (btn.isConnected) btn.innerHTML = o; }, 3000);
  };
  const A = {
    nav: (b) => go(b.dataset.v),
    add: () => openPair(),
    demo: async (b) => { b.disabled = true; try { const l = await hub.startLoopback(); hub.select(l.key); toast('Caméra de test liée (cet appareil)', 'ok'); } catch (e) { toast('Test impossible : ' + (e.message || e), 'error'); b.disabled = false; } },
    cam: (b) => { hub.select(b.dataset.k); stageKey = ''; renderLive(); },
    tile: (b) => { hub.select(b.dataset.k); mosaic = false; stageKey = ''; renderLive(); },
    mosaic: () => { mosaic = !mosaic; stageKey = ''; renderStage(); renderStrip(); },
    speaker: (b) => { speaker = !speaker; const v = $('#sv'); if (v) { v.muted = !speaker; v.play().catch(() => {}); } b.setAttribute('aria-pressed', speaker); b.innerHTML = icon(speaker ? 'speaker' : 'speakerOff'); },
    rec: () => hub.selected?.toggleRec(),
    photo: () => { hub.selected?.cmd('photo'); toast('Photo demandée', 'info', 1500); },
    mic: () => { const l = hub.selected; l?.cmd('mic', !(l.tel?.mic ?? true)); },
    mark: () => { const l = hub.selected; if (!l) return; const n = (l.rec?.meta.markers.length || 0) + 1; l.mark(`Repère ${n}`); toast(`Repère ${n} posé`, 'ok', 1500); },
    urg: () => { if (!urgArm) { urgArm = Date.now() + 3000; tickLive(hub.selected, hub.selected?.tel, false); return; } urgArm = 0; hub.emergency(hub.selected); toast('Urgence envoyée à la caméra', 'warn'); },
    lib: (b) => { lib = b.dataset.t; renderLib(view === 'arch'); },
    play: (b) => openPlayer(b.dataset.id),
    export: async (b) => { const r = await db.get('recordings', b.dataset.id); download(await db.recordingBlob(r), `${vname(r)}.${extFor(r.mime)}`); },
    arc: async (b) => { const r = await db.get('recordings', b.dataset.id); r.archived = !r.archived; await db.put('recordings', r); renderLib(view === 'arch'); toast(r.archived ? 'Archivé' : 'Restauré', 'ok', 1500); },
    del: (b) => confirmTap(b, async () => { await db.del('recordings', b.dataset.id); await db.delChunks(b.dataset.id); renderLib(view === 'arch'); }),
    viewphoto: async (b) => { const p = await db.get('photos', b.dataset.id); modal(`<div class="dlg wide photo-view"><h3><span>${esc(p.camName)} · ${fmtStamp(new Date(p.t))}</span><button class="x" data-a="close">${icon('x')}</button></h3><img src="${objUrl(p.blob)}" alt="Photo horodatée"></div>`); },
    expphoto: async (b) => { const p = await db.get('photos', b.dataset.id); download(p.blob, `HXC_${slug(p.camName)}_${fmtFileStamp(new Date(p.t))}.jpg`); },
    arcphoto: async (b) => { const p = await db.get('photos', b.dataset.id); p.archived = !p.archived; await db.put('photos', p); renderLib(view === 'arch'); },
    delphoto: (b) => confirmTap(b, async () => { await db.del('photos', b.dataset.id); renderLib(view === 'arch'); }),
    tgl: (b) => { const k = b.dataset.k; hub.s[k] = !hub.s[k]; hub.saveSettings(); b.setAttribute('aria-checked', hub.s[k]); if (k === 'overlay') hub.ready.forEach((l) => l.cmd('overlay', hub.s.overlay)); },
    applyq: () => { hub.ready.forEach((l) => l.cmd('quality', { q: hub.s.quality, fps: 30 })); toast(hub.ready.length ? 'Qualité envoyée' : 'Aucune caméra liée', 'ok'); },
    wipe: (b) => confirmTap(b, async () => { await db.clearAll(); hub.logs = []; toast('Données effacées', 'ok'); }),
    role: () => app.chooseRole(),
    ack: (b) => hub.ackAlert(b.dataset.k),
    alertview: (b) => { hub.select(b.dataset.k); go('live'); },
  };
  root.addEventListener('click', (e) => { const b = e.target.closest('[data-a]'); if (b && A[b.dataset.a] && !b.closest('.modal[data-own]')) A[b.dataset.a](b, e); });

  // ---------- Événements du hub ----------
  hub.addEventListener('change', () => { if (view === 'live') { stageKey = ''; renderStrip(); renderStage(); } });
  hub.addEventListener('alert', renderAlerts);
  hub.addEventListener('recsaved', () => { toast('Enregistrement sauvegardé sur la tablette', 'ok'); if (view === 'rec') renderLib(false); });
  hub.addEventListener('photo', () => { toast('Photo reçue', 'ok', 1800); if (view === 'rec' && lib === 'photos') renderLib(false); });
  const timer = setInterval(tick, 500);
  go('live');
  return () => { clearInterval(timer); revoke(); };
}
