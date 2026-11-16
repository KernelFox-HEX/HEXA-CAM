// Côté tablette : réception des flux, commandes à distance, enregistrement des copies, journal
import * as db from './db.js';
import { Recorder, grabThumb } from './recorder.js';
import { packSignal, unpackSignal, waitIce, uid, kv, beep } from './util.js';
import { CameraNode } from './camera.js';

const DEFAULTS = { name: 'POSTE TAC', autoRec: false, emergencyRec: true, overlay: true, sound: true, quality: '1080p' };

export class CameraLink extends EventTarget {
  constructor(hub) {
    super();
    this.hub = hub; this.key = uid(); this.id = null; this.name = 'CAMÉRA'; this.model = '—';
    this.state = 'pairing'; this.tel = null; this.stream = new MediaStream();
    this.rtt = null; this.kbps = 0; this.lossPct = 0; this.fps = 0; this.w = 0; this.h = 0;
    this.rec = null; this.photos = new Map(); this.sosAt = null; this.lastTelAt = 0;
    this.video = document.createElement('video');
    Object.assign(this.video, { muted: true, autoplay: true, playsInline: true });
    this.video.style.cssText = 'position:fixed;width:2px;height:2px;opacity:0;pointer-events:none;left:0;top:0';
    document.body.appendChild(this.video);
  }
  emit(type, detail) { this.dispatchEvent(new CustomEvent(type, { detail })); }
  get connected() { return this.state === 'connected' || this.state === 'unstable'; }
  get recording() { return !!this.rec?.active; }

  async accept(code) {
    const { kind, sdp } = unpackSignal(code);
    if (kind !== 'o') throw new Error('Ce code n’est pas une offre de caméra');
    const pc = (this.pc = new RTCPeerConnection({ iceServers: [] }));
    const dc = (this.dc = pc.createDataChannel('ctrl', { negotiated: true, id: 0 }));
    dc.onmessage = (e) => this.onMessage(e.data);
    dc.onopen = () => this.setState('connected');
    dc.onclose = () => this.setState('lost');
    pc.ontrack = (e) => {
      if (!this.stream.getTracks().includes(e.track)) this.stream.addTrack(e.track);
      if (this.video.srcObject !== this.stream) this.video.srcObject = this.stream;
      this.video.play().catch(() => {});
      this.emit('stream');
    };
    pc.onconnectionstatechange = () => {
      const s = pc.connectionState;
      if (s === 'connected') this.setState('connected');
      else if (s === 'disconnected') this.setState('unstable');
      else if (s === 'failed' || s === 'closed') this.setState('lost');
    };
    await pc.setRemoteDescription({ type: 'offer', sdp });
    const ans = await pc.createAnswer();
    await pc.setLocalDescription(ans);
    await waitIce(pc);
    return packSignal('a', pc.localDescription.sdp);
  }

  setState(s) {
    if (this.state === s || this.closed) return;
    const prev = this.state; this.state = s;
    if (s === 'connected' && prev === 'pairing') { this.hub.log('link', `${this.name} : liaison établie`, this); }
    if (s === 'unstable') this.hub.log('warn', `${this.name} : liaison instable`, this);
    if (s === 'lost') {
      this.hub.log('error', `${this.name} : liaison perdue`, this);
      if (this.rec?.active) this.stopRec('liaison perdue');
      clearInterval(this.statTimer); clearInterval(this.pingTimer);
    }
    if (s === 'connected') this.startPolling();
    this.emit('state'); this.hub.changed();
  }

  send(o) { try { if (this.dc?.readyState === 'open') this.dc.send(JSON.stringify(o)); } catch { /* ok */ } }
  cmd(n, v) { this.send({ t: 'cmd', n, v }); }

  startPolling() {
    clearInterval(this.statTimer); clearInterval(this.pingTimer);
    this.pingTimer = setInterval(() => this.send({ t: 'ping', ts: performance.now() }), 1500);
    this.statTimer = setInterval(() => this.poll(), 1000);
  }
  async poll() {
    if (!this.pc) return;
    try {
      const st = await this.pc.getStats(); let bytes = 0, lost = 0, recv = 0, rtt = null;
      st.forEach((r) => {
        if (r.type === 'inbound-rtp' && r.kind === 'video') { bytes = r.bytesReceived; lost = r.packetsLost; recv = r.packetsReceived; this.fps = Math.round(r.framesPerSecond || 0); this.w = r.frameWidth || this.w; this.h = r.frameHeight || this.h; }
        if (r.type === 'candidate-pair' && r.nominated && r.state === 'succeeded' && r.currentRoundTripTime != null) rtt = r.currentRoundTripTime * 1000;
      });
      const now = performance.now();
      if (this.prev) {
        const dt = (now - this.prev.t) / 1000;
        this.kbps = Math.max(0, ((bytes - this.prev.bytes) * 8) / dt / 1000);
        const dl = lost - this.prev.lost, dr = recv - this.prev.recv;
        this.lossPct = dl + dr > 0 ? (dl / (dl + dr)) * 100 : 0;
      }
      this.prev = { t: now, bytes, lost, recv };
      if (this.rtt == null && rtt != null) this.rtt = rtt;
      this.emit('stats');
    } catch { /* ok */ }
  }
  get quality() {
    if (!this.connected) return { label: 'Hors liaison', cls: 'off' };
    if (this.state === 'unstable') return { label: 'Instable', cls: 'bad' };
    const r = this.rtt ?? 999;
    if (r < 120 && this.lossPct < 2) return { label: 'Excellente', cls: 'good' };
    if (r < 300 && this.lossPct < 6) return { label: 'Bonne', cls: 'ok' };
    return { label: 'Faible', cls: 'bad' };
  }

  async onMessage(raw) {
    let m; try { m = JSON.parse(raw); } catch { return; }
    switch (m.t) {
      case 'hello': {
        this.id = m.id; this.name = m.name; this.model = m.model;
        this.hub.dedupe(this);
        this.send({ t: 'hello', name: this.hub.s.name });
        this.send({ t: 'sync', now: Date.now() });
        if (this.hub.s.overlay === false) this.cmd('overlay', false);
        this.emit('hello'); this.hub.changed();
        break;
      }
      case 'sdp': {
        await this.pc.setRemoteDescription(m.d);
        if (m.d.type === 'offer') {
          const a = await this.pc.createAnswer(); await this.pc.setLocalDescription(a);
          this.send({ t: 'sdp', d: { type: a.type, sdp: a.sdp } });
        }
        break;
      }
      case 'pong': this.rtt = performance.now() - m.ts; break;
      case 'tel': {
        const first = !this.tel;
        this.tel = m; this.lastTelAt = performance.now(); this.name = m.name || this.name; this.model = m.model || this.model;
        if (m.rec && !this.rec?.active) this.startRec('caméra');
        if (!m.rec && this.rec?.active) this.stopRec('caméra');
        if (first && this.hub.s.autoRec && !m.rec) this.cmd('rec_start');
        this.emit('tel'); break;
      }
      case 'ev': this.onEvent(m); break;
      case 'photo': this.photos.set(m.id, { meta: m.meta, n: m.n, parts: [] }); break;
      case 'pc': {
        const p = this.photos.get(m.id); if (!p) break;
        p.parts[m.i] = Uint8Array.from(atob(m.d), (c) => c.charCodeAt(0));
        if (p.parts.filter(Boolean).length === p.n) {
          const blob = new Blob(p.parts, { type: 'image/jpeg' });
          const meta = { ...p.meta, origin: 'console', size: blob.size, camName: this.name };
          await db.put('photos', { ...meta, blob });
          this.photos.delete(m.id);
          this.hub.log('photo', `${this.name} : photo reçue`, this);
          this.hub.emit('photo', meta);
        }
        break;
      }
    }
  }

  onEvent(m) {
    switch (m.k) {
      case 'rec_start': if (!this.rec?.active) this.startRec(m.by === 'sos' ? 'urgence' : m.by === 'console' ? 'console' : m.by === 'alert' ? 'alerte' : 'caméra'); break;
      case 'rec_stop': if (this.rec?.active) this.stopRec(m.by); break;
      case 'marker': this.rec?.mark(m.label); this.hub.log('marker', `${this.name} : repère « ${m.label} »`, this); break;
      case 'sos':
        this.sosAt = Date.now(); this.hub.log('sos', `${this.name} : URGENCE déclenchée par le joueur`, this);
        this.hub.raiseAlert(this, m); break;
    }
  }

  async startRec(by = 'console') {
    if (this.rec?.active || this.starting) return;
    if (!this.stream.getVideoTracks().length) { setTimeout(() => this.startRec(by), 500); return; }
    this.starting = true;
    const rec = new Recorder(this.stream, {
      origin: 'console', camId: this.id, camName: this.name, bitrate: 3500000, now: () => Date.now(),
      thumbEl: this.video, w: this.w, h: this.h, gps: () => this.tel?.gps && { lat: this.tel.gps.lat, lon: this.tel.gps.lon },
    });
    this.rec = rec;
    await rec.start(); this.starting = false;
    this.hub.log('rec', `${this.name} : enregistrement démarré (${by})`, this);
    this.emit('rec'); this.hub.changed();
  }
  async stopRec(by = 'console') {
    if (!this.rec?.active) return;
    const meta = await this.rec.stop();
    this.hub.log('rec', `${this.name} : enregistrement terminé (${by})`, this);
    this.emit('rec'); this.hub.changed(); this.hub.emit('recsaved', meta);
  }
  toggleRec() { if (this.recording || this.tel?.rec) this.cmd('rec_stop'); else this.cmd('rec_start'); }

  mark(label = 'Repère') {
    this.cmd('marker', label); // la caméra confirme par un événement : le repère est alors posé et journalisé
  }

  close() {
    this.closed = true;
    clearInterval(this.statTimer); clearInterval(this.pingTimer);
    if (this.rec?.active) this.stopRec('fermeture');
    try { this.dc?.close(); this.pc?.close(); } catch { /* ok */ }
    this.video.srcObject = null; this.video.remove();
  }
}

export class ConsoleHub extends EventTarget {
  constructor() {
    super();
    this.s = { ...DEFAULTS, ...(kv.get('console') || {}) };
    this.links = []; this.selectedKey = null; this.alerts = []; this.logs = [];
    db.recentEvents(60).then((l) => { this.logs = l; this.emit('log'); });
  }
  emit(type, detail) { this.dispatchEvent(new CustomEvent(type, { detail })); }
  saveSettings() { kv.set('console', this.s); }
  changed() { this.emit('change'); }
  get selected() { return this.links.find((l) => l.key === this.selectedKey) || this.links.find((l) => l.id) || null; }
  get ready() { return this.links.filter((l) => l.id && l.state !== 'lost'); }
  get any() { return this.links.filter((l) => l.id); }

  newLink() { const l = new CameraLink(this); this.links.push(l); l.addEventListener('state', () => this.changed()); return l; }
  removeLink(l) { l.close(); this.links = this.links.filter((x) => x !== l); if (this.selectedKey === l.key) this.selectedKey = null; this.changed(); }
  /** Une caméra qui se ré-associe remplace son ancienne entrée. */
  dedupe(link) {
    for (const o of this.links.filter((x) => x !== link && x.id === link.id)) this.removeLink(o);
    if (!this.selectedKey) this.selectedKey = link.key;
    this.changed();
  }
  select(key) { this.selectedKey = key; this.changed(); }

  log(type, text, link) {
    const e = { t: Date.now(), type, text, cam: link?.name };
    this.logs.unshift(e); this.logs = this.logs.slice(0, 120);
    db.logEvent(e).catch(() => {});
    this.emit('log', e);
  }

  raiseAlert(link, m) {
    this.alerts.unshift({ key: link.key, name: link.name, at: Date.now(), gps: m.gps });
    if (this.s.sound) beep();
    if (navigator.vibrate) navigator.vibrate([300, 120, 300]);
    this.emit('alert');
  }
  ackAlert(key) {
    const l = this.links.find((x) => x.key === key);
    l?.send({ t: 'ack' });
    this.alerts = this.alerts.filter((a) => a.key !== key);
    this.emit('alert');
  }
  /** URGENCE console : alerte la caméra ciblée (ou toutes) et déclenche l’enregistrement. */
  emergency(target) {
    const list = target ? [target] : this.ready;
    for (const l of list) { l.cmd('alert', { rec: this.s.emergencyRec }); this.log('sos', `URGENCE envoyée à ${l.name}`, l); if (this.s.emergencyRec) setTimeout(() => l.mark('URGENCE'), 1200); }
    if (!list.length) this.log('warn', 'Urgence : aucune caméra liée');
  }

  /** Test avec cet appareil : une caméra virtuelle liée à la console dans le même onglet. */
  async startLoopback() {
    const host = document.createElement('div');
    host.style.cssText = 'position:fixed;left:-9999px;top:0;width:4px;height:4px;overflow:hidden';
    const video = document.createElement('video'), canvas = document.createElement('canvas');
    host.append(video, canvas); document.body.appendChild(host);
    const node = new CameraNode({ video, canvas, settings: { name: 'DÉMO-1', quality: '720p', facing: 'user' } });
    await node.start();
    const offer = await node.createOffer();
    const link = this.newLink();
    const answer = await link.accept(offer);
    await node.acceptAnswer(answer);
    this.demo = { node, host, link };
    return link;
  }
  async stopLoopback() {
    if (!this.demo) return;
    await this.demo.node.stop(); this.demo.host.remove(); this.removeLink(this.demo.link); this.demo = null;
  }
}
