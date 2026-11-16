// Utilitaires communs HEXACORE BODYCAM
export const VERSION = '1.0.0';

export const pad = (n, l = 2) => String(n).padStart(l, '0');

export function fmtDur(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), r = s % 60;
  return `${pad(h)}:${pad(m)}:${pad(r)}`;
}
export function fmtClock(d = new Date()) { return `${pad(d.getHours())}:${pad(d.getMinutes())}`; }
export function fmtDate(d = new Date()) { return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`; }
export function fmtStamp(d = new Date()) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
export function fmtFileStamp(d = new Date()) {
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}
export function fmtSize(b) {
  if (b == null || isNaN(b)) return '—';
  if (b < 1024) return `${b} o`;
  const u = ['Ko', 'Mo', 'Go', 'To'];
  let i = -1; do { b /= 1024; i++; } while (b >= 1024 && i < 3);
  return `${b.toFixed(b >= 100 ? 0 : 1).replace('.', ',')} ${u[i]}`;
}
export function fmtGo(b) { return `${(b / 1073741824).toFixed(1).replace('.', ',')} Go`; }
export const uid = () => (crypto.randomUUID ? crypto.randomUUID().replace(/-/g, '').slice(0, 12) : Math.random().toString(16).slice(2, 14));
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- Stockage clé/valeur (avec repli mémoire) ----------
const memKV = new Map();
// Détection de fonctionnalité : certains contextes (aperçu intégré en iframe isolée) refusent l'accès au stockage.
export const safeGlobal = (name) => { try { return globalThis[name] || null; } catch { return null; } };
const persist = () => safeGlobal('local' + 'Storage');
export const kv = {
  get(k, d = null) {
    try { const v = persist().getItem('hxc.' + k); return v == null ? d : JSON.parse(v); } catch { return memKV.has(k) ? memKV.get(k) : d; }
  },
  set(k, v) {
    try { persist().setItem('hxc.' + k, JSON.stringify(v)); } catch { memKV.set(k, v); }
  },
};

// ---------- Appairage hors-ligne : signaux compacts pour QR ----------
const b64u = {
  enc: (s) => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => decodeURIComponent(escape(atob(s.replace(/-/g, '+').replace(/_/g, '/')))),
};
const hexToB64 = (hex) => { const bytes = hex.split(':').map((h) => parseInt(h, 16)); return btoa(String.fromCharCode(...bytes)).replace(/=+$/, ''); };
const b64ToHex = (b) => [...atob(b)].map((c) => pad(c.charCodeAt(0).toString(16).toUpperCase())).join(':');

export const SIGNAL_PREFIX = 'HXC1.';

/** Réduit une SDP "data channel" à l'essentiel (ICE ufrag/pwd, empreinte DTLS, candidats) pour tenir dans un petit QR. */
export function packSignal(kind, sdp) {
  const m = (re) => (sdp.match(re) || [])[1];
  const cands = [...sdp.matchAll(/^a=candidate:\S+ \d+ (\w+) \d+ (\S+) (\d+) typ (\w+)/gim)]
    .filter((c) => c[1].toLowerCase() === 'udp')
    .map((c) => ({ addr: c[2], port: c[3], typ: c[4] }));
  const hosts = cands.filter((c) => c.typ === 'host');
  const use = (hosts.length ? hosts : cands).slice(0, 4).map((c) => `${c.addr} ${c.port}`);
  const arr = [kind, m(/a=ice-ufrag:(\S+)/), m(/a=ice-pwd:(\S+)/), hexToB64(m(/a=fingerprint:sha-256 (\S+)/)), ({ actpass: 'x', active: 'a', passive: 'p' }[m(/a=setup:(\S+)/)] || 'x'), use];
  return SIGNAL_PREFIX + b64u.enc(JSON.stringify(arr));
}

export function unpackSignal(code) {
  code = (code || '').trim();
  if (!code.startsWith(SIGNAL_PREFIX)) throw new Error('Code HEXACORE invalide');
  const [kind, u, p, f, s, c] = JSON.parse(b64u.dec(code.slice(SIGNAL_PREFIX.length)));
  const lines = [
    'v=0', 'o=- 4611731400430051336 2 IN IP4 127.0.0.1', 's=-', 't=0 0',
    'a=group:BUNDLE 0', 'a=msid-semantic: WMS',
    'm=application 9 UDP/DTLS/SCTP webrtc-datachannel', 'c=IN IP4 0.0.0.0',
    `a=ice-ufrag:${u}`, `a=ice-pwd:${p}`, `a=fingerprint:sha-256 ${b64ToHex(f)}`,
    `a=setup:${{ x: 'actpass', a: 'active', p: 'passive' }[s] || 'actpass'}`,
    'a=mid:0', 'a=sctp-port:5000', 'a=max-message-size:262144',
  ];
  c.forEach((x, i) => {
    const [addr, port] = x.split(' ');
    lines.push(`a=candidate:${1000 + i} 1 udp ${2113937151 - i * 256} ${addr} ${port} typ host generation 0`);
  });
  lines.push('a=end-of-candidates');
  return { kind, sdp: lines.join('\r\n') + '\r\n' };
}

export async function waitIce(pc, ms = 2500) {
  if (pc.iceGatheringState === 'complete') return;
  await new Promise((res) => {
    const t = setTimeout(res, ms);
    pc.addEventListener('icegatheringstatechange', () => { if (pc.iceGatheringState === 'complete') { clearTimeout(t); res(); } });
  });
}

// ---------- Médias ----------
export function pickMime() {
  const c = ['video/mp4;codecs=avc1.640028,mp4a.40.2', 'video/mp4;codecs=avc1,mp4a.40.2', 'video/mp4', 'video/webm;codecs=vp9,opus', 'video/webm;codecs=vp8,opus', 'video/webm'];
  if (!window.MediaRecorder) return '';
  return c.find((m) => MediaRecorder.isTypeSupported(m)) || '';
}
export const extFor = (mime) => (mime || '').includes('mp4') ? 'mp4' : 'webm';

export function download(blob, name) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = name;
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 4000);
}

// ---------- Sons d'alerte ----------
let actx;
export function beep(pattern = [[880, 0.18], [0, 0.08], [880, 0.18], [0, 0.08], [1175, 0.3]]) {
  try {
    actx = actx || new (window.AudioContext || window.webkitAudioContext)();
    let t = actx.currentTime;
    for (const [f, d] of pattern) {
      if (f) {
        const o = actx.createOscillator(), g = actx.createGain();
        o.type = 'square'; o.frequency.value = f; g.gain.value = 0.08;
        o.connect(g); g.connect(actx.destination); o.start(t); o.stop(t + d);
      }
      t += d;
    }
  } catch { /* audio indisponible */ }
}

// ---------- Toasts ----------
export function toast(msg, kind = 'info', ms = 3200) {
  let host = document.getElementById('toasts');
  if (!host) { host = document.createElement('div'); host.id = 'toasts'; host.setAttribute('role', 'status'); host.setAttribute('aria-live', 'polite'); document.body.appendChild(host); }
  const t = document.createElement('div');
  t.className = `toast ${kind}`; t.textContent = msg;
  host.appendChild(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 300); }, ms);
}

// ---------- QR ----------
export function drawQR(canvas, text, px = 320) {
  const qr = window.qrcode(0, 'M'); qr.addData(text); qr.make();
  const n = qr.getModuleCount(), quiet = 3, total = n + quiet * 2;
  const scale = Math.max(2, Math.floor(px / total));
  canvas.width = canvas.height = total * scale;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#000';
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) ctx.fillRect((c + quiet) * scale, (r + quiet) * scale, scale, scale);
}

/** Lit un QR depuis un élément <video> (BarcodeDetector si dispo, sinon jsQR). Retourne une fonction d'arrêt. */
export function scanQR(video, onCode, interval = 140) {
  let stop = false, busy = false;
  const detector = 'BarcodeDetector' in window ? new BarcodeDetector({ formats: ['qr_code'] }) : null;
  const cv = document.createElement('canvas'), cx = cv.getContext('2d', { willReadFrequently: true });
  const tick = async () => {
    if (stop) return;
    if (!busy && video.videoWidth) {
      busy = true;
      try {
        let code = null;
        if (detector) { const r = await detector.detect(video); if (r[0]) code = r[0].rawValue; }
        if (!code && window.jsQR) {
          const k = Math.min(1, 720 / video.videoWidth);
          cv.width = Math.round(video.videoWidth * k); cv.height = Math.round(video.videoHeight * k);
          cx.drawImage(video, 0, 0, cv.width, cv.height);
          const img = cx.getImageData(0, 0, cv.width, cv.height);
          const r = window.jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
          if (r) code = r.data;
        }
        if (code && code.startsWith(SIGNAL_PREFIX)) { stop = true; onCode(code); return; }
      } catch { /* frame ignorée */ }
      busy = false;
    }
    setTimeout(tick, interval);
  };
  tick();
  return () => { stop = true; };
}
