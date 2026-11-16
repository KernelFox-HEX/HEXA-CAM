// Interface du téléphone (caméra de terrain)
import * as db from './db.js';
import { icon } from './icons.js';
import { $, $$, esc, fmtDur, fmtStamp, fmtFileStamp, fmtSize, extFor, download, toast, drawQR, scanQR, beep, kv } from './util.js';
import { CameraNode } from './camera.js';

export function mountCamera(root, app) {
  const saved = { name: 'ALPHA-1', quality: '1080p', fps: 30, facing: 'environment', overlay: true, emergencyRec: true, mic: true, ...(kv.get('camSettings') || {}) };
  let node = null, sheet = null, scanStop = null, dimmed = false, lastTap = 0, alarm = null, timer = null;

  root.innerHTML = `
  <div class="cam" id="cam">
    <video class="rawv" id="raw" playsinline muted></video>
    <canvas id="prev" aria-label="Aperçu caméra"></canvas>
    <div class="cam-top"><span class="chipx" id="c-link"><i class="dot"></i><span>Non liée</span></span><span class="chipx rec" id="c-rec" style="display:none"><i class="dot red"></i><span class="tnum">00:00:00</span></span><span class="chipx" id="c-bat"><span class="tnum">—</span></span></div>
    <div class="cam-bot" id="bot" style="visibility:hidden">
      <button class="cb" data-a="pair"><span class="c">${icon('qr')}</span>Associer</button>
      <button class="cb" data-a="photo"><span class="c">${icon('camera')}</span>Photo</button>
      <button class="cb main" data-a="rec" id="b-rec"><span class="c"></span><span id="b-rec-t">REC</span></button>
      <button class="cb" data-a="dim"><span class="c">${icon('eyeOff')}</span>Écran noir</button>
      <button class="cb" data-a="set"><span class="c">${icon('gear')}</span>Réglages</button>
    </div>
    <button class="cb sos" id="sos" style="position:absolute;right:10px;top:calc(env(safe-area-inset-top) + 64px);z-index:6;flex:none;visibility:hidden" aria-label="Urgence : maintenir appuyé"><span class="c"><i id="sos-f"></i>${icon('warn')}</span>SOS</button>
    <div class="start" id="start">
      <div class="logo"><img src="img/logo-mark.png" alt=""><div class="wordmark"><span class="b1">HEXACORE</span><span class="b2">BODYCAM</span></div></div>
      <h2 style="font-family:var(--f-tech);font-size:1.6rem;letter-spacing:.08em">CAMÉRA DE TERRAIN</h2>
      <label for="f-name">Indicatif</label><input class="inp" id="f-name" maxlength="16" value="${esc(saved.name)}" autocapitalize="characters" autocomplete="off">
      <label for="f-q">Qualité</label><select class="sel" id="f-q">${['480p', '720p', '1080p'].map((q) => `<option ${saved.quality === q ? 'selected' : ''}>${q}</option>`).join('')}</select>
      <label for="f-f">Caméra</label><select class="sel" id="f-f"><option value="environment" ${saved.facing === 'environment' ? 'selected' : ''}>Arrière</option><option value="user" ${saved.facing === 'user' ? 'selected' : ''}>Avant</option></select>
      <button class="btn pri" id="go">${icon('videoFill')}Démarrer la caméra</button>
      <p class="note">Autorisez caméra, micro et position quand le téléphone le demande. Laissez l’écran allumé : utilisez « Écran noir » pour économiser la batterie sans interrompre l’enregistrement.</p>
      <button class="link-btn" style="margin-top:1rem;align-self:flex-start;color:var(--mut)" data-a="role">Changer de rôle</button>
    </div>
    <div class="flash" id="flash" role="alertdialog"><div class="big" id="fl-t">ALERTE</div><div id="fl-s" style="font-size:1.1rem"></div><button class="btn" data-a="flashoff" style="background:#fff;color:#900">Compris</button></div>
    <div class="dim" id="dim" style="display:none"><div class="r" id="dim-r">● STANDBY</div><small>Double appui pour réveiller</small></div>
  </div>`;

  const camEl = $('#cam');
  const persist = () => kv.set('camSettings', node ? node.s : saved);

  // ---------- Démarrage ----------
  $('#go').addEventListener('click', async () => {
    const btn = $('#go'); btn.disabled = true; btn.textContent = 'Démarrage…';
    saved.name = ($('#f-name').value.trim() || 'ALPHA-1').toUpperCase(); saved.quality = $('#f-q').value; saved.facing = $('#f-f').value;
    node = new CameraNode({ video: $('#raw'), canvas: $('#prev'), settings: saved });
    try { await node.start(); } catch (e) {
      btn.disabled = false; btn.innerHTML = `${icon('videoFill')}Réessayer`;
      toast(e.name === 'NotAllowedError' ? 'Accès caméra refusé : autorisez-le dans le navigateur' : 'Caméra indisponible : ' + (e.message || e.name), 'error', 6000); return;
    }
    persist();
    node.addEventListener('conn', onConn); node.addEventListener('link', () => { toast(`Liée à ${node.consoleName}`, 'ok'); closeSheet(); });
    node.addEventListener('rec', () => hud()); node.addEventListener('toast', (e) => toast(e.detail.msg, e.detail.kind));
    node.addEventListener('photo', () => toast('Photo enregistrée', 'ok', 1500));
    node.addEventListener('alert', () => showFlash('ALERTE', 'Demande de la console', true));
    node.addEventListener('sos', () => showFlash('SOS ENVOYÉ', 'En attente d’acquittement de la console', false));
    node.addEventListener('ack', () => { hideFlash(); toast('Urgence acquittée par la console', 'ok'); });
    node.addEventListener('settings', persist);
    $('#start').remove(); $('#bot').style.visibility = $('#sos').style.visibility = 'visible';
    timer = setInterval(hud, 500); hud();
    window.__node = node;
  });

  function onConn(e) {
    hud();
    if (e.detail.state === 'connected') { toast('Liaison établie', 'ok'); closeSheet(); }
    if (e.detail.state === 'lost') toast('Liaison perdue : l’enregistrement local continue', 'warn', 4500);
  }

  function hud() {
    if (!node) return;
    const link = $('#c-link'), st = node.state;
    const txt = st === 'connected' ? `Liée · ${node.consoleName || 'console'}` : st === 'unstable' ? 'Liaison instable' : st === 'lost' ? 'Liaison perdue' : 'Non liée';
    $('.dot', link).className = 'dot ' + (st === 'connected' ? 'green' : st === 'unstable' ? 'amber' : st === 'lost' ? 'red' : '');
    $('span', link).textContent = txt;
    const rec = node.recorder?.active, cr = $('#c-rec');
    cr.style.display = rec ? '' : 'none'; if (rec) $('.tnum', cr).textContent = fmtDur(node.recorder.elapsed);
    const b = node.battery.level; $('#c-bat .tnum').textContent = b != null ? `${b} %${node.battery.charging ? ' ⚡' : ''}` : '—';
    $('#b-rec').classList.toggle('on', !!rec); $('#b-rec-t').textContent = rec ? 'STOP' : 'REC';
    const dr = $('#dim-r'); if (dr) { dr.className = 'r' + (rec ? ' on' : ''); dr.textContent = rec ? `● REC ${fmtDur(node.recorder.elapsed)}` : '● STANDBY'; }
  }

  // ---------- Feuilles ----------
  function openSheet(html) { closeSheet(true); sheet = document.createElement('div'); sheet.className = 'sheet'; sheet.innerHTML = html; camEl.appendChild(sheet); return sheet; }
  function closeSheet(keepScan) { sheet?.remove(); sheet = null; if (!keepScan) { scanStop?.(); scanStop = null; $('.reticle')?.remove(); } }

  async function openPair() {
    if (node.linked && node.state === 'connected') {
      const s = openSheet(`<h3>Liaison active<button class="x" data-a="closesheet">${icon('x')}</button></h3><p>Liée à ${esc(node.consoleName || 'la console')}. Les commandes de la tablette (REC, photo, micro, urgence) sont actives.</p><div class="stack"><button class="btn" data-a="repair">Nouvelle association</button></div>`);
      return s;
    }
    const s = openSheet(`<h3>Associer à la tablette<button class="x" data-a="closesheet">${icon('x')}</button></h3><p>Sur la tablette : <b>Ajouter une caméra</b>, puis scannez ce QR code.</p><div class="qrbox"><canvas id="oq" aria-label="QR code d’association"></canvas></div><div class="wait"><div class="spin"></div>Préparation…</div>`);
    let offer;
    try { offer = await node.createOffer(); } catch (e) { toast('Impossible de préparer la liaison', 'error'); return; }
    if (!sheet) return;
    drawQR($('#oq', s), offer, 420);
    $('.wait', s).remove();
    s.insertAdjacentHTML('beforeend', `<div class="stack"><button class="btn pri" data-a="scan">${icon('qr')}2. Scanner la réponse de la tablette</button><button class="btn" data-a="manualpair">${icon('link')}Code manuel</button></div>`);
    s.dataset.offer = offer;
  }

  function startScan() {
    closeSheet(true);
    const hint = openSheet(`<div class="scanhint">Visez le QR code de la tablette</div><div class="stack"><button class="btn" data-a="closesheet">Annuler</button></div>`);
    hint.style.cssText = 'padding-top:.8rem';
    camEl.insertAdjacentHTML('beforeend', '<div class="reticle"></div>');
    scanStop = scanQR(node.video, async (code) => {
      $('.reticle')?.remove(); scanStop = null;
      try { await node.acceptAnswer(code); toast('Réponse reçue, liaison en cours…', 'info'); openSheet(`<div class="wait"><div class="spin"></div>Connexion à la tablette…</div>`); setTimeout(() => { if (node.state !== 'connected' && sheet) { sheet.innerHTML = `<h3>Liaison impossible<button class="x" data-a="closesheet">${icon('x')}</button></h3><p>Vérifiez que téléphone et tablette sont sur le même réseau local (point d’accès de la tablette), puis recommencez.</p><div class="stack"><button class="btn pri" data-a="repair">Recommencer</button></div>`; } }, 15000); }
      catch (e) { toast(e.message || 'QR invalide', 'error'); closeSheet(); }
    });
  }

  function manualPair() {
    const offer = sheet?.dataset.offer || '';
    openSheet(`<h3>Code manuel<button class="x" data-a="closesheet">${icon('x')}</button></h3><p>Copiez ce code vers la tablette (Ajouter une caméra → Saisir un code), puis collez ici le code de réponse.</p>
      <textarea class="inp" readonly id="mo">${offer}</textarea><div class="stack"><button class="btn" data-a="copyo">${icon('copy')}Copier mon code</button></div>
      <p style="margin-top:1rem">Code de réponse :</p><textarea class="inp" id="ma" placeholder="HXC1.…"></textarea><div class="stack"><button class="btn pri" data-a="sendans">Valider</button></div>`);
  }

  async function openSettings() {
    const s = node.s;
    const recs = (await db.getAll('recordings')).filter((r) => r.origin === 'camera' && r.t1 != null).sort((a, b) => b.t0 - a.t0);
    const tg = (k, t) => `<div class="row"><div class="t">${t}</div><button class="tgl" role="switch" aria-checked="${!!s[k]}" data-a="tgl" data-k="${k}" aria-label="${t}"></button></div>`;
    openSheet(`<h3>Réglages<button class="x" data-a="closesheet">${icon('x')}</button></h3>
      <div class="row"><div class="t">Indicatif</div><input class="inp" id="s-n" value="${esc(s.name)}" maxlength="16" style="min-width:0;width:9rem"></div>
      <div class="row"><div class="t">Qualité</div><select class="sel" id="s-q" style="min-width:0">${['480p', '720p', '1080p'].map((q) => `<option ${s.quality === q ? 'selected' : ''}>${q}</option>`).join('')}</select></div>
      ${tg('mic', 'Micro')}${tg('overlay', 'Incrustation date / heure / GPS')}${tg('emergencyRec', 'SOS : enregistrer automatiquement')}
      <div class="stack"><button class="btn" data-a="flip">${icon('flip')}Changer de caméra</button></div>
      <h3 style="margin-top:1.3rem;font-size:1.1rem">Enregistrements sur ce téléphone</h3>
      <div class="rl">${recs.map((r) => `<div class="it"><div><b>${esc(r.camName)}</b> <span>${fmtStamp(new Date(r.t0)).slice(5, 16)} · ${fmtDur(r.dur)} · ${fmtSize(r.size)}</span></div><div style="display:flex;gap:.4rem"><button class="btn sm" data-a="exp" data-id="${r.id}" aria-label="Exporter">${icon('download')}</button><button class="btn sm danger" data-a="rm" data-id="${r.id}" aria-label="Supprimer">${icon('trash')}</button></div></div>`).join('') || '<span class="sub" style="color:var(--mut)">Aucun enregistrement.</span>'}</div>
      <div class="stack"><button class="btn" data-a="role">Changer de rôle / quitter</button></div>`);
    $('#s-n', sheet).addEventListener('change', (e) => { node.s.name = e.target.value.trim().toUpperCase() || 'ALPHA-1'; persist(); node.sendTel(); });
    $('#s-q', sheet).addEventListener('change', (e) => node.setQuality(e.target.value));
  }

  // ---------- Alertes ----------
  function showFlash(t, s, siren) {
    $('#fl-t').textContent = t; $('#fl-s').textContent = s; $('#flash').classList.add('on');
    clearInterval(alarm); const go = () => { beep(); navigator.vibrate?.([400, 150, 400]); };
    go(); if (siren) alarm = setInterval(go, 2500);
    if (dimmed) wake();
  }
  function hideFlash() { clearInterval(alarm); alarm = null; $('#flash').classList.remove('on'); }

  const wake = () => { dimmed = false; $('#dim').style.display = 'none'; };

  // ---------- Actions ----------
  const A = {
    pair: openPair, repair: openPair, scan: startScan, manualpair: manualPair, closesheet: () => closeSheet(),
    set: openSettings, flip: () => node.flip().catch(() => toast('Changement de caméra impossible', 'error')),
    photo: () => node.takePhoto(),
    rec: () => (node.recorder?.active ? node.stopRecording('local') : node.startRecording('local')),
    dim: () => { dimmed = true; $('#dim').style.display = 'flex'; hud(); },
    flashoff: () => { hideFlash(); },
    role: async () => { if (node) { clearInterval(timer); await node.stop(); } app.chooseRole(); },
    copyo: () => { navigator.clipboard?.writeText($('#mo').value).then(() => toast('Code copié', 'ok')).catch(() => $('#mo').select()); },
    sendans: async () => { try { await node.acceptAnswer($('#ma').value.trim()); closeSheet(); toast('Connexion…', 'info'); } catch (e) { toast(e.message || 'Code invalide', 'error'); } },
    tgl: (b) => { const k = b.dataset.k; if (k === 'mic') node.setMic(!node.s.mic); else node.s[k] = !node.s[k]; persist(); b.setAttribute('aria-checked', node.s[k]); },
    exp: async (b) => { const r = await db.get('recordings', b.dataset.id); download(await db.recordingBlob(r), `HXC_${r.camName}_${fmtFileStamp(new Date(r.t0))}.${extFor(r.mime)}`); },
    rm: async (b) => { if (!b.dataset.s) { b.dataset.s = 1; b.textContent = '?'; return; } await db.del('recordings', b.dataset.id); await db.delChunks(b.dataset.id); openSettings(); },
  };
  camEl.addEventListener('click', (e) => { const b = e.target.closest('[data-a]'); if (b && A[b.dataset.a]) A[b.dataset.a](b); });
  // double appui pour réveiller l'écran noir
  $('#dim').addEventListener('pointerup', () => { const n = Date.now(); if (n - lastTap < 450) wake(); lastTap = n; });

  // SOS : maintien 0,8 s
  const sos = $('#sos'), fill = $('#sos-f'); let sosT = null;
  const sosStart = (e) => { e.preventDefault(); fill.style.transition = 'height .8s linear'; fill.style.height = '100%'; sosT = setTimeout(() => { sosT = null; fill.style.transition = 'none'; fill.style.height = '0'; node.sos(); }, 800); };
  const sosCancel = () => { if (sosT) { clearTimeout(sosT); sosT = null; } fill.style.transition = 'height .2s'; fill.style.height = '0'; };
  sos.addEventListener('pointerdown', sosStart); ['pointerup', 'pointerleave', 'pointercancel'].forEach((ev) => sos.addEventListener(ev, sosCancel));
  sos.addEventListener('contextmenu', (e) => e.preventDefault());

  return async () => { clearInterval(timer); clearInterval(alarm); scanStop?.(); await node?.stop(); };
}
