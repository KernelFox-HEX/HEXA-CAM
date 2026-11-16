// Enregistreur robuste : écrit les morceaux au fil de l'eau (résiste à une coupure de batterie)
import * as db from './db.js';
import { pickMime, uid } from './util.js';

export const QUALITY = {
  '480p': { w: 854, h: 480, live: 1200000, rec: 1500000 },
  '720p': { w: 1280, h: 720, live: 2500000, rec: 3000000 },
  '1080p': { w: 1920, h: 1080, live: 5000000, rec: 6000000 },
};

export function grabThumb(el, w = 320) {
  try {
    const vw = el.videoWidth || el.width, vh = el.videoHeight || el.height;
    if (!vw) return null;
    const c = document.createElement('canvas'); c.width = w; c.height = Math.round((w * vh) / vw);
    c.getContext('2d').drawImage(el, 0, 0, c.width, c.height);
    return c.toDataURL('image/jpeg', 0.6);
  } catch { return null; }
}

export class Recorder {
  /**
   * @param {MediaStream} stream
   * @param {object} o { origin, camId, camName, bitrate, now(), thumbEl, gps(), w, h }
   */
  constructor(stream, o) {
    this.stream = stream; this.o = o; this.queue = Promise.resolve(); this.active = false;
  }
  get elapsed() { return this.active ? performance.now() - this.p0 : (this.meta?.dur || 0); }

  async start() {
    const mime = pickMime();
    const id = uid();
    this.p0 = performance.now();
    this.mr = new MediaRecorder(this.stream, { mimeType: mime || undefined, videoBitsPerSecond: this.o.bitrate, audioBitsPerSecond: 128000 });
    this.meta = {
      id, camId: this.o.camId, camName: this.o.camName, origin: this.o.origin,
      t0: this.o.now(), t1: null, dur: 0, mime: this.mr.mimeType || mime, size: 0, chunks: 0,
      markers: [], archived: false, thumb: null, w: this.o.w || 0, h: this.o.h || 0,
      gps: this.o.gps ? this.o.gps() : null,
    };
    this.mr.ondataavailable = (e) => {
      if (!e.data || !e.data.size) return;
      this.queue = this.queue.then(async () => {
        this.meta.chunks++; this.meta.size += e.data.size; this.meta.dur = Math.round(performance.now() - this.p0);
        await db.put('chunks', { rid: id, seq: this.meta.chunks, data: e.data });
        await db.put('recordings', this.meta);
      }).catch(() => {});
    };
    await db.put('recordings', this.meta);
    this.mr.start(2000);
    this.active = true;
    setTimeout(() => { if (this.active && this.o.thumbEl) { this.meta.thumb = grabThumb(this.o.thumbEl); db.put('recordings', this.meta); } }, 1200);
    return this.meta;
  }

  mark(label) {
    if (!this.active) return null;
    const m = { at: Math.round(performance.now() - this.p0), label, wall: this.o.now() };
    this.meta.markers.push(m);
    return m;
  }

  stop() {
    if (!this.active) return Promise.resolve(this.meta);
    this.active = false;
    return new Promise((res) => {
      this.mr.onstop = () => this.queue.then(async () => {
        this.meta.t1 = this.o.now(); this.meta.dur = Math.round(performance.now() - this.p0);
        await db.put('recordings', this.meta); res(this.meta);
      });
      try { this.mr.stop(); } catch { res(this.meta); }
    });
  }
}

/** Finalise les enregistrements interrompus (batterie, fermeture brutale). */
export async function recoverOrphans() {
  const all = await db.getAll('recordings');
  let n = 0;
  for (const r of all) {
    if (r.t1 == null) { r.t1 = r.t0 + (r.dur || 0); r.recovered = true; await db.put('recordings', r); n++; }
  }
  return n;
}
