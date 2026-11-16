import { safeGlobal } from './util.js';
// Stockage local : IndexedDB (avec repli mémoire si indisponible)
const NAME = 'hexacore', VER = 1;
const STORES = {
  recordings: { keyPath: 'id' },
  chunks: { keyPath: ['rid', 'seq'] },
  photos: { keyPath: 'id' },
  events: { autoIncrement: true },
};
let dbp = null, mem = null;

function open() {
  if (dbp) return dbp;
  dbp = new Promise((resolve) => {
    try {
      const idb = safeGlobal('indexed' + 'DB');
      if (!idb) { resolve(null); return; }
      const req = idb.open(NAME, VER);
      req.onupgradeneeded = () => {
        const d = req.result;
        for (const [n, o] of Object.entries(STORES)) if (!d.objectStoreNames.contains(n)) d.createObjectStore(n, o);
        req.transaction.objectStore('chunks').createIndex('rid', 'rid');
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
      req.onblocked = () => resolve(null);
    } catch { resolve(null); }
  }).then((d) => { if (!d) { mem = { recordings: new Map(), chunks: new Map(), photos: new Map(), events: [] }; } return d; });
  return dbp;
}

const wrap = (req) => new Promise((res, rej) => { req.onsuccess = () => res(req.result); req.onerror = () => rej(req.error); });
export const isPersistent = async () => !!(await open());

export async function put(store, val) {
  const d = await open();
  if (!d) {
    if (store === 'chunks') mem.chunks.set(`${val.rid}:${val.seq}`, val);
    else if (store === 'events') mem.events.push(val);
    else mem[store].set(val.id, val);
    return;
  }
  return wrap(d.transaction(store, 'readwrite').objectStore(store).put(val));
}
export async function get(store, key) {
  const d = await open();
  if (!d) return mem[store].get(key);
  return wrap(d.transaction(store).objectStore(store).get(key));
}
export async function getAll(store) {
  const d = await open();
  if (!d) return store === 'events' ? [...mem.events] : [...mem[store].values()];
  return wrap(d.transaction(store).objectStore(store).getAll());
}
export async function del(store, key) {
  const d = await open();
  if (!d) { mem[store].delete(key); return; }
  return wrap(d.transaction(store, 'readwrite').objectStore(store).delete(key));
}
export async function chunksOf(rid) {
  const d = await open();
  if (!d) return [...mem.chunks.values()].filter((c) => c.rid === rid).sort((a, b) => a.seq - b.seq);
  const all = await wrap(d.transaction('chunks').objectStore('chunks').index('rid').getAll(rid));
  return all.sort((a, b) => a.seq - b.seq);
}
export async function delChunks(rid) {
  const d = await open();
  if (!d) { for (const k of [...mem.chunks.keys()]) if (k.startsWith(rid + ':')) mem.chunks.delete(k); return; }
  const tx = d.transaction('chunks', 'readwrite');
  const idx = tx.objectStore('chunks').index('rid');
  return new Promise((res) => {
    const cur = idx.openKeyCursor(safeGlobal('IDBKeyRange').only(rid));
    cur.onsuccess = () => { const c = cur.result; if (c) { tx.objectStore('chunks').delete(c.primaryKey); c.continue(); } };
    tx.oncomplete = res; tx.onerror = res;
  });
}
export async function clearAll() {
  const d = await open();
  if (!d) { mem = { recordings: new Map(), chunks: new Map(), photos: new Map(), events: [] }; return; }
  for (const s of Object.keys(STORES)) await wrap(d.transaction(s, 'readwrite').objectStore(s).clear());
}

/** Assemble les morceaux d'un enregistrement en Blob lisible. */
export async function recordingBlob(rec) {
  const ch = await chunksOf(rec.id);
  return new Blob(ch.map((c) => c.data), { type: (rec.mime || 'video/webm').split(';')[0] });
}

export async function logEvent(ev) { await put('events', { t: Date.now(), ...ev }); }
export async function recentEvents(n = 80) {
  const all = await getAll('events');
  return all.slice(-n).reverse();
}
