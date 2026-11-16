// Côté téléphone : capture, incrustation horodatée, enregistrement local, liaison WebRTC directe
import * as db from './db.js';
import { Recorder, QUALITY, grabThumb } from './recorder.js';
import { packSignal, unpackSignal, waitIce, uid, pad, sleep, kv } from './util.js';

const DRAW_FONT = '600 {s}px Rajdhani, "Roboto Mono", monospace';

export class CameraNode extends EventTarget {
  constructor({ video, canvas, settings }) {
    super();
    this.video = video; this.canvas = canvas; this.ctx = canvas.getContext('2d', { alpha: false });
    this.s = { name: 'ALPHA-1', quality: '1080p', fps: 30, facing: 'environment', overlay: true, emergencyRec: true, mic: true, ...settings };
    this.id = kv.get('camId') || (() => { const i = uid(); kv.set('camId', i); return i; })();
    this.offset = 0;           // décalage d'horloge vers l'heure de la console
    this.linked = false; this.state = 'idle'; this.consoleName = null;
    this.gps = null; this.battery = { level: null, charging: false };
    this.storage = { usage: 0, quota: 0 };
    this.model = 'Smartphone';
    this.recorder = null; this.alerting = false;
    this.lastTel = 0;
  }
  emit(type, detail) { this.dispatchEvent(new CustomEvent(type, { detail })); }
  now() { return Date.now() + this.offset; }

  // ---------------- Démarrage caméra ----------------
  async start() {
    await this.acquire(true);
    try { document.fonts && (await document.fonts.load(DRAW_FONT.replace('{s}', '20'))); } catch { /* ok */ }
    this.out = this.canvas.captureStream(this.s.fps);
    const a = this.raw.getAudioTracks()[0];
    if (a) { a.enabled = this.s.mic; this.out.addTrack(a); }
    this.loop();
    this.startTelemetry();
    this.startGps();
    this.wake();
    try { const h = await navigator.userAgentData?.getHighEntropyValues?.(['model']); if (h?.model) this.model = h.model; else this.model = /Android/i.test(navigator.userAgent) ? 'Smartphone Android' : /iPhone/i.test(navigator.userAgent) ? 'iPhone' : 'Appareil'; } catch { /* ok */ }
    navigator.storage?.persist?.().catch(() => {});
  }

  async acquire(withAudio) {
    const q = QUALITY[this.s.quality];
    const v = { facingMode: { ideal: this.s.facing }, width: { ideal: q.w }, height: { ideal: q.h }, frameRate: { ideal: this.s.fps } };
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: v, audio: withAudio ? { echoCancellation: false, noiseSuppression: false, autoGainControl: true } : false });
    } catch (e) {
      if (!withAudio) throw e;
      stream = await navigator.mediaDevices.getUserMedia({ video: v, audio: false });
      this.emit('toast', { msg: 'Micro indisponible : vidéo seule', kind: 'warn' });
    }
    if (withAudio) this.raw = stream;
    else { this.raw.getVideoTracks().forEach((t) => { t.stop(); this.raw.removeTrack(t); }); stream.getVideoTracks().forEach((t) => this.raw.addTrack(t)); }
    this.video.srcObject = new MediaStream(this.raw.getVideoTracks());
    this.video.muted = true; this.video.playsInline = true;
    await this.video.play().catch(() => {});
  }

  async flip() {
    this.s.facing = this.s.facing === 'environment' ? 'user' : 'environment';
    await this.acquire(false);
    this.emit('settings', this.s);
  }

  async setQuality(q, fps) {
    if (QUALITY[q]) this.s.quality = q;
    if (fps) this.s.fps = fps;
    const t = this.raw.getVideoTracks()[0], Q = QUALITY[this.s.quality];
    try { await t.applyConstraints({ width: { ideal: Q.w }, height: { ideal: Q.h }, frameRate: { ideal: this.s.fps } }); } catch { await this.acquire(false); }
    this.applyBitrate();
    this.emit('settings', this.s);
    this.sendTel();
  }

  setMic(on) {
    this.s.mic = on;
    this.raw.getAudioTracks().forEach((t) => (t.enabled = on));
    this.emit('settings', this.s); this.sendTel();
  }

  // ---------------- Canvas + incrustation ----------------
  loop() {
    const v = this.video;
    const frame = () => {
      this.drawFrame();
      if (this.stopped) return;
      if (v.requestVideoFrameCallback) v.requestVideoFrameCallback(frame); else requestAnimationFrame(frame);
    };
    frame();
    // filet de sécurité : l'incrustation (horloge) continue même si la caméra n'envoie plus d'images
    this.safety = setInterval(() => { if (performance.now() - (this.lastDraw || 0) > 700) this.drawFrame(); }, 500);
  }

  drawFrame() {
    const v = this.video, c = this.canvas, x = this.ctx;
    if (!v.videoWidth) return;
    if (c.width !== v.videoWidth || c.height !== v.videoHeight) { c.width = v.videoWidth; c.height = v.videoHeight; }
    x.drawImage(v, 0, 0, c.width, c.height);
    if (this.s.overlay) this.drawOverlay(x, c.width, c.height);
    this.lastDraw = performance.now();
  }

  drawOverlay(x, W, H) {
    const s = Math.max(14, Math.round(Math.min(W, H) / 26)), m = Math.round(s * 0.8);
    const d = new Date(this.now());
    const date = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    x.save();
    x.font = DRAW_FONT.replace('{s}', s); x.textBaseline = 'top';
    x.shadowColor = 'rgba(0,0,0,.9)'; x.shadowBlur = s * 0.25; x.shadowOffsetY = 1;
    // haut gauche : nom + REC
    const rec = this.recorder?.active;
    let tx = m;
    if (rec) {
      if (Math.floor(performance.now() / 600) % 2 === 0) { x.fillStyle = '#ff2b2b'; x.beginPath(); x.arc(m + s * 0.4, m + s * 0.55, s * 0.32, 0, 7); x.fill(); }
      tx = m + s * 1.1;
    }
    x.fillStyle = '#fff'; x.textAlign = 'left';
    x.fillText(this.s.name, tx, m);
    if (rec) { x.fillStyle = '#ff6b6b'; x.fillText('REC', tx, m + s * 1.05); }
    // haut droite : date + heure
    x.textAlign = 'right'; x.fillStyle = '#fff';
    x.fillText(time, W - m, m);
    x.fillStyle = 'rgba(255,255,255,.8)'; x.fillText(date, W - m, m + s * 1.05);
    // bas gauche : GPS
    x.textAlign = 'left'; x.textBaseline = 'bottom';
    if (this.gps) { x.fillStyle = 'rgba(255,255,255,.85)'; x.fillText(`${this.gps.lat.toFixed(5)}  ${this.gps.lon.toFixed(5)}`, m, H - m); }
    // bas droite : marque
    x.textAlign = 'right'; x.fillStyle = 'rgba(255,60,60,.9)'; x.fillText('HEXACORE', W - m, H - m);
    x.restore();
  }

  // ---------------- Enregistrement local ----------------
  async startRecording(by = 'local') {
    if (this.recorder?.active) return;
    const Q = QUALITY[this.s.quality];
    this.recorder = new Recorder(this.out, {
      origin: 'camera', camId: this.id, camName: this.s.name, bitrate: Q.rec, now: () => this.now(),
      thumbEl: this.canvas, gps: () => this.gps && { lat: this.gps.lat, lon: this.gps.lon }, w: this.canvas.width, h: this.canvas.height,
    });
    await this.recorder.start();
    this.recStartedBy = by;
    this.emit('rec', { on: true, by });
    this.send({ t: 'ev', k: 'rec_start', by, rid: this.recorder.meta.id, at: this.now() });
    this.sendTel();
  }
  async stopRecording(by = 'local') {
    if (!this.recorder?.active) return;
    const meta = await this.recorder.stop();
    this.emit('rec', { on: false, by, meta });
    this.send({ t: 'ev', k: 'rec_stop', by, rid: meta.id, at: this.now(), dur: meta.dur });
    this.sendTel();
  }
  addMarker(label = 'Repère') {
    const m = this.recorder?.mark(label);
    this.send({ t: 'ev', k: 'marker', label, at: this.now() });
    this.emit('toast', { msg: `Repère : ${label}`, kind: 'info' });
    return m;
  }

  async takePhoto() {
    this.drawFrame();
    const blob = await new Promise((r) => this.canvas.toBlob(r, 'image/jpeg', 0.92));
    const meta = { id: uid(), camId: this.id, camName: this.s.name, t: this.now(), size: blob.size, origin: 'camera', gps: this.gps && { lat: this.gps.lat, lon: this.gps.lon } };
    await db.put('photos', { ...meta, blob });
    this.emit('photo', meta);
    if (this.linked) this.sendPhoto(blob, meta);
    return meta;
  }
  async sendPhoto(blob, meta) {
    const buf = new Uint8Array(await blob.arrayBuffer()), CH = 12000, n = Math.ceil(buf.length / CH);
    this.send({ t: 'photo', id: meta.id, n, meta });
    for (let i = 0; i < n; i++) {
      const part = buf.subarray(i * CH, (i + 1) * CH);
      let bin = ''; for (let j = 0; j < part.length; j += 8192) bin += String.fromCharCode.apply(null, part.subarray(j, j + 8192));
      while (this.dc && this.dc.bufferedAmount > 1e6) await sleep(30);
      this.send({ t: 'pc', id: meta.id, i, d: btoa(bin) });
    }
  }

  sos() {
    this.send({ t: 'ev', k: 'sos', at: this.now(), gps: this.gps && { lat: this.gps.lat, lon: this.gps.lon } });
    if (this.s.emergencyRec) this.startRecording('sos').then(() => this.addMarker('URGENCE'));
    else this.addMarker('URGENCE');
    this.emit('sos');
  }

  // ---------------- Liaison directe WebRTC (sans serveur) ----------------
  closePeer() {
    try { this.dc?.close(); } catch { /* ok */ }
    try { this.pc?.close(); } catch { /* ok */ }
    this.pc = this.dc = null; this.linked = false;
  }

  async createOffer() {
    this.closePeer();
    const pc = (this.pc = new RTCPeerConnection({ iceServers: [] }));
    const dc = (this.dc = pc.createDataChannel('ctrl', { negotiated: true, id: 0 }));
    dc.onopen = () => this.onOpen();
    dc.onmessage = (e) => this.onMessage(e.data);
    dc.onclose = () => this.setState('lost');
    pc.onconnectionstatechange = () => {
      const s = pc.connectionState;
      if (s === 'connected') this.setState('connected');
      else if (s === 'disconnected') this.setState('unstable');
      else if (s === 'failed' || s === 'closed') this.setState('lost');
    };
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await waitIce(pc);
    return packSignal('o', pc.localDescription.sdp);
  }

  async acceptAnswer(code) {
    const { kind, sdp } = unpackSignal(code);
    if (kind !== 'a') throw new Error('Ce code n’est pas une réponse de la console');
    await this.pc.setRemoteDescription({ type: 'answer', sdp });
  }

  setState(s) {
    if (this.state === s) return;
    this.state = s;
    this.linked = s === 'connected' && this.dc?.readyState === 'open';
    this.emit('conn', { state: s });
  }

  async onOpen() {
    this.linked = true;
    this.send({ t: 'hello', id: this.id, name: this.s.name, model: this.model, v: 1 });
    // On ajoute la vidéo/audio une fois le canal ouvert (SDP initiale minuscule => QR léger)
    for (const t of this.out.getTracks()) {
      const sender = this.pc.addTrack(t, this.out);
      if (t.kind === 'video') this.sender = sender;
    }
    try {
      const tr = this.pc.getTransceivers().find((x) => x.sender === this.sender);
      const caps = RTCRtpSender.getCapabilities?.('video')?.codecs || [];
      const h264 = caps.filter((c) => /h264/i.test(c.mimeType));
      if (tr?.setCodecPreferences && h264.length) tr.setCodecPreferences([...h264, ...caps.filter((c) => !/h264/i.test(c.mimeType))]);
    } catch { /* codec par défaut */ }
    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    this.send({ t: 'sdp', d: { type: offer.type, sdp: offer.sdp } });
    this.applyBitrate();
    this.setState('connected');
    this.sendTel();
  }

  applyBitrate() {
    const sender = this.sender; if (!sender) return;
    try {
      const p = sender.getParameters(); if (!p.encodings?.length) p.encodings = [{}];
      p.encodings[0].maxBitrate = QUALITY[this.s.quality].live; p.encodings[0].maxFramerate = this.s.fps;
      sender.setParameters(p);
    } catch { /* ok */ }
  }

  send(o) { try { if (this.dc?.readyState === 'open') this.dc.send(JSON.stringify(o)); } catch { /* ok */ } }

  async onMessage(raw) {
    let m; try { m = JSON.parse(raw); } catch { return; }
    switch (m.t) {
      case 'hello': this.consoleName = m.name; this.emit('link', { name: m.name }); break;
      case 'sdp': await this.pc.setRemoteDescription(m.d); break;
      case 'sync': this.offset = m.now - Date.now(); this.emit('sync', { offset: this.offset }); break;
      case 'ping': this.send({ t: 'pong', ts: m.ts }); break;
      case 'cmd': this.command(m.n, m.v); break;
      case 'ack': this.alerting = false; this.emit('ack'); break;
    }
  }

  async command(n, v) {
    switch (n) {
      case 'rec_start': await this.startRecording('console'); break;
      case 'rec_stop': await this.stopRecording('console'); break;
      case 'photo': await this.takePhoto(); break;
      case 'mic': this.setMic(v); break;
      case 'flip': await this.flip(); break;
      case 'quality': await this.setQuality(v.q, v.fps); break;
      case 'overlay': this.s.overlay = !!v; this.emit('settings', this.s); break;
      case 'marker': this.addMarker(v || 'Repère'); break;
      case 'alert':
        this.alerting = true;
        if (v?.rec && !this.recorder?.active) await this.startRecording('alert');
        this.emit('alert', { from: 'console' }); break;
      case 'rename': this.s.name = v; this.emit('settings', this.s); break;
    }
    this.sendTel();
  }

  // ---------------- Télémétrie ----------------
  telemetry() {
    const t = this.raw?.getVideoTracks()[0]?.getSettings?.() || {};
    const w = this.canvas.width, h = this.canvas.height;
    return {
      t: 'tel', name: this.s.name, model: this.model, bat: this.battery.level, chg: this.battery.charging,
      st: this.storage, gps: this.gps && { lat: this.gps.lat, lon: this.gps.lon, acc: this.gps.acc },
      rec: !!this.recorder?.active, recMs: this.recorder?.active ? Math.round(this.recorder.elapsed) : 0,
      w, h, fps: Math.round(t.frameRate || this.s.fps), q: this.s.quality, mic: this.s.mic, facing: this.s.facing, ovl: this.s.overlay, at: this.now(),
    };
  }
  sendTel() { if (this.linked) this.send(this.telemetry()); }

  async startTelemetry() {
    try {
      const b = await navigator.getBattery?.();
      if (b) { const up = () => (this.battery = { level: Math.round(b.level * 100), charging: b.charging }); up(); b.addEventListener('levelchange', up); b.addEventListener('chargingchange', up); }
    } catch { /* ok */ }
    const tick = async () => {
      try { const e = await navigator.storage?.estimate?.(); if (e) this.storage = { usage: e.usage, quota: e.quota }; } catch { /* ok */ }
    };
    tick();
    this.tel = setInterval(() => { this.sendTel(); }, 1000);
    this.tel2 = setInterval(tick, 15000);
    this.emit('ready');
  }

  startGps() {
    if (!navigator.geolocation) return;
    try {
      this.geoId = navigator.geolocation.watchPosition(
        (p) => { this.gps = { lat: p.coords.latitude, lon: p.coords.longitude, acc: p.coords.accuracy }; },
        () => { this.gps = null; }, { enableHighAccuracy: true, maximumAge: 3000, timeout: 20000 });
    } catch { /* ok */ }
  }

  async wake() {
    try {
      this.wl = await navigator.wakeLock?.request('screen');
      document.addEventListener('visibilitychange', async () => { if (document.visibilityState === 'visible' && !this.stopped) { try { this.wl = await navigator.wakeLock.request('screen'); } catch { /* ok */ } } });
    } catch { /* ok */ }
  }

  async stop() {
    this.stopped = true;
    await this.stopRecording('local');
    clearInterval(this.tel); clearInterval(this.tel2); clearInterval(this.safety);
    if (this.geoId != null) navigator.geolocation.clearWatch(this.geoId);
    this.closePeer();
    this.raw?.getTracks().forEach((t) => t.stop());
    try { await this.wl?.release(); } catch { /* ok */ }
  }
}
