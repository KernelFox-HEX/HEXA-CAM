import { $, kv, VERSION, toast } from './util.js';
import { icon } from './icons.js';
import { ConsoleHub } from './console.js';
import { mountConsole } from './ui-console.js';
import { mountCamera } from './ui-camera.js';
import { recoverOrphans } from './recorder.js';
import * as db from './db.js';

const root = document.getElementById('root');
const setHash = (h) => { try { history.replaceState(null, '', h ? '#' + h : location.pathname + location.search); } catch { /* iframe isolée */ } };
const app = { offlineReady: false, unmount: null, hub: null, chooseRole, install: null };
window.__hxc = app;

async function unmount() { try { await app.unmount?.(); } catch { /* ok */ } app.unmount = null; root.innerHTML = ''; }

async function chooseRole() {
  await unmount();
  if (app.hub) { await app.hub.stopLoopback?.(); app.hub.links.forEach((l) => l.close()); app.hub = null; }
  setHash('');
  root.innerHTML = `<div class="landing"><div class="inner">
    <div class="logo"><img src="img/logo-mark.png" alt="" width="64" height="60"><div class="wordmark"><span class="b1">HEXACORE</span><span class="b2">BODYCAM</span></div></div>
    <h1>Bodycam et poste de commandement pour milsim, polsim et RP airsoft. Liaison directe téléphone vers tablette, sans Wi-Fi public ni 4G/5G.</h1>
    <div class="roles">
      <button class="role" data-r="console"><div class="ic">${icon('tablet')}</div><div class="tag">Tablette · poste TAC</div><h2>CONSOLE</h2><p>Live view, commande à distance, enregistrements horodatés, archives, statut des liaisons et alertes urgence.</p></button>
      <button class="role" data-r="camera"><div class="ic">${icon('phone')}</div><div class="tag">Téléphone · joueur</div><h2>CAMÉRA</h2><p>Transforme le téléphone en bodycam : flux en direct vers la tablette et enregistrement local de secours.</p></button>
    </div>
    <div class="meta"><span class="pill"><i class="d" id="off-d"></i><span id="off-t">Préparation du mode hors ligne…</span></span><span id="inst-w"></span><span>v${VERSION}</span></div>
    <details class="guide"><summary>Guide de terrain en 4 étapes</summary><ol>
      <li><b>Avant la partie, avec Internet :</b> ouvrez cette page une fois sur chaque appareil, puis « Ajouter à l’écran d’accueil ». L’application est alors disponible hors ligne.</li>
      <li><b>Sur le terrain :</b> activez le point d’accès Wi-Fi de la tablette (sans Internet) ou allumez un petit routeur local, et connectez-y les téléphones.</li>
      <li><b>Association :</b> téléphone en rôle Caméra, « Associer » affiche un QR ; la tablette (Ajouter une caméra) le scanne et affiche une réponse que le téléphone scanne à son tour.</li>
      <li><b>Pilotage :</b> la tablette démarre et arrête l’enregistrement, prend des photos, coupe le micro et pose des repères. Chaque vidéo est horodatée et copiée sur la tablette ; le téléphone garde l’original.</li>
    </ol></details></div></div>`;
  root.querySelectorAll('.role').forEach((b) => b.addEventListener('click', () => setRole(b.dataset.r)));
  updateOffline(); renderInstall();
}

async function setRole(r) {
  kv.set('role', r); setHash(r);
  await unmount();
  if (r === 'console') { app.hub = app.hub || new ConsoleHub(); app.unmount = mountConsole(root, app.hub, app); }
  else app.unmount = mountCamera(root, app);
}

function updateOffline() {
  const d = $('#off-d'), t = $('#off-t'); if (!d) return;
  d.classList.toggle('on', app.offlineReady);
  t.textContent = app.offlineReady ? 'Prêt hors ligne' : (location.protocol === 'file:' ? 'Fichier local : hors ligne par nature (installation PWA indisponible)' : 'serviceWorker' in navigator ? 'Mode hors ligne en cours d’installation…' : 'Mode hors ligne non pris en charge');
}
function renderInstall() {
  const w = $('#inst-w'); if (!w) return;
  w.innerHTML = app.install ? `<button class="link-btn" id="inst">Installer l’application</button>` : '';
  $('#inst')?.addEventListener('click', async () => { app.install.prompt(); await app.install.userChoice; app.install = null; renderInstall(); });
}
window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); app.install = e; renderInstall(); });

if ('serviceWorker' in navigator) {
  Promise.resolve().then(() => navigator.serviceWorker.register('sw.js')).then(() => navigator.serviceWorker.ready).then(() => { app.offlineReady = true; updateOffline(); }).catch(() => {});
}
recoverOrphans().then((n) => { if (n) toast(`${n} enregistrement(s) interrompu(s) récupéré(s)`, 'warn', 5000); }).catch(() => {});
db.isPersistent();

const hash = location.hash.slice(1);
if (hash === 'console' || hash === 'camera') setRole(hash);
else chooseRole();
