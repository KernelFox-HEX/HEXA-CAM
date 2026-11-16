(() => {
  // src/util.js
  var VERSION = "1.0.0";
  var pad = (n, l = 2) => String(n).padStart(l, "0");
  function fmtDur(ms) {
    const s = Math.max(0, Math.floor(ms / 1e3));
    const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), r = s % 60;
    return `${pad(h)}:${pad(m)}:${pad(r)}`;
  }
  function fmtClock(d = /* @__PURE__ */ new Date()) {
    return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }
  function fmtDate(d = /* @__PURE__ */ new Date()) {
    return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`;
  }
  function fmtStamp(d = /* @__PURE__ */ new Date()) {
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }
  function fmtFileStamp(d = /* @__PURE__ */ new Date()) {
    return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
  }
  function fmtSize(b) {
    if (b == null || isNaN(b)) return "\u2014";
    if (b < 1024) return `${b} o`;
    const u = ["Ko", "Mo", "Go", "To"];
    let i = -1;
    do {
      b /= 1024;
      i++;
    } while (b >= 1024 && i < 3);
    return `${b.toFixed(b >= 100 ? 0 : 1).replace(".", ",")} ${u[i]}`;
  }
  function fmtGo(b) {
    return `${(b / 1073741824).toFixed(1).replace(".", ",")} Go`;
  }
  var uid = () => crypto.randomUUID ? crypto.randomUUID().replace(/-/g, "").slice(0, 12) : Math.random().toString(16).slice(2, 14);
  var esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  var $ = (sel, root2 = document) => root2.querySelector(sel);
  var $$ = (sel, root2 = document) => [...root2.querySelectorAll(sel)];
  var sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  var memKV = /* @__PURE__ */ new Map();
  var safeGlobal = (name) => {
    try {
      return globalThis[name] || null;
    } catch {
      return null;
    }
  };
  var persist = () => safeGlobal("localStorage");
  var kv = {
    get(k, d = null) {
      try {
        const v = persist().getItem("hxc." + k);
        return v == null ? d : JSON.parse(v);
      } catch {
        return memKV.has(k) ? memKV.get(k) : d;
      }
    },
    set(k, v) {
      try {
        persist().setItem("hxc." + k, JSON.stringify(v));
      } catch {
        memKV.set(k, v);
      }
    }
  };
  var b64u = {
    enc: (s) => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
    dec: (s) => decodeURIComponent(escape(atob(s.replace(/-/g, "+").replace(/_/g, "/"))))
  };
  var hexToB64 = (hex) => {
    const bytes = hex.split(":").map((h) => parseInt(h, 16));
    return btoa(String.fromCharCode(...bytes)).replace(/=+$/, "");
  };
  var b64ToHex = (b) => [...atob(b)].map((c) => pad(c.charCodeAt(0).toString(16).toUpperCase())).join(":");
  var SIGNAL_PREFIX = "HXC1.";
  function packSignal(kind, sdp) {
    const m = (re) => (sdp.match(re) || [])[1];
    const cands = [...sdp.matchAll(/^a=candidate:\S+ \d+ (\w+) \d+ (\S+) (\d+) typ (\w+)/gim)].filter((c) => c[1].toLowerCase() === "udp").map((c) => ({ addr: c[2], port: c[3], typ: c[4] }));
    const hosts = cands.filter((c) => c.typ === "host");
    const use = (hosts.length ? hosts : cands).slice(0, 4).map((c) => `${c.addr} ${c.port}`);
    const arr = [kind, m(/a=ice-ufrag:(\S+)/), m(/a=ice-pwd:(\S+)/), hexToB64(m(/a=fingerprint:sha-256 (\S+)/)), { actpass: "x", active: "a", passive: "p" }[m(/a=setup:(\S+)/)] || "x", use];
    return SIGNAL_PREFIX + b64u.enc(JSON.stringify(arr));
  }
  function unpackSignal(code) {
    code = (code || "").trim();
    if (!code.startsWith(SIGNAL_PREFIX)) throw new Error("Code HEXACORE invalide");
    const [kind, u, p, f, s, c] = JSON.parse(b64u.dec(code.slice(SIGNAL_PREFIX.length)));
    const lines = [
      "v=0",
      "o=- 4611731400430051336 2 IN IP4 127.0.0.1",
      "s=-",
      "t=0 0",
      "a=group:BUNDLE 0",
      "a=msid-semantic: WMS",
      "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
      "c=IN IP4 0.0.0.0",
      `a=ice-ufrag:${u}`,
      `a=ice-pwd:${p}`,
      `a=fingerprint:sha-256 ${b64ToHex(f)}`,
      `a=setup:${{ x: "actpass", a: "active", p: "passive" }[s] || "actpass"}`,
      "a=mid:0",
      "a=sctp-port:5000",
      "a=max-message-size:262144"
    ];
    c.forEach((x, i) => {
      const [addr, port] = x.split(" ");
      lines.push(`a=candidate:${1e3 + i} 1 udp ${2113937151 - i * 256} ${addr} ${port} typ host generation 0`);
    });
    lines.push("a=end-of-candidates");
    return { kind, sdp: lines.join("\r\n") + "\r\n" };
  }
  async function waitIce(pc, ms = 2500) {
    if (pc.iceGatheringState === "complete") return;
    await new Promise((res) => {
      const t = setTimeout(res, ms);
      pc.addEventListener("icegatheringstatechange", () => {
        if (pc.iceGatheringState === "complete") {
          clearTimeout(t);
          res();
        }
      });
    });
  }
  function pickMime() {
    const c = ["video/mp4;codecs=avc1.640028,mp4a.40.2", "video/mp4;codecs=avc1,mp4a.40.2", "video/mp4", "video/webm;codecs=vp9,opus", "video/webm;codecs=vp8,opus", "video/webm"];
    if (!window.MediaRecorder) return "";
    return c.find((m) => MediaRecorder.isTypeSupported(m)) || "";
  }
  var extFor = (mime) => (mime || "").includes("mp4") ? "mp4" : "webm";
  function download(blob, name) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(a.href);
      a.remove();
    }, 4e3);
  }
  var actx;
  function beep(pattern = [[880, 0.18], [0, 0.08], [880, 0.18], [0, 0.08], [1175, 0.3]]) {
    try {
      actx = actx || new (window.AudioContext || window.webkitAudioContext)();
      let t = actx.currentTime;
      for (const [f, d] of pattern) {
        if (f) {
          const o = actx.createOscillator(), g = actx.createGain();
          o.type = "square";
          o.frequency.value = f;
          g.gain.value = 0.08;
          o.connect(g);
          g.connect(actx.destination);
          o.start(t);
          o.stop(t + d);
        }
        t += d;
      }
    } catch {
    }
  }
  function toast(msg, kind = "info", ms = 3200) {
    let host = document.getElementById("toasts");
    if (!host) {
      host = document.createElement("div");
      host.id = "toasts";
      host.setAttribute("role", "status");
      host.setAttribute("aria-live", "polite");
      document.body.appendChild(host);
    }
    const t = document.createElement("div");
    t.className = `toast ${kind}`;
    t.textContent = msg;
    host.appendChild(t);
    setTimeout(() => {
      t.classList.add("out");
      setTimeout(() => t.remove(), 300);
    }, ms);
  }
  function drawQR(canvas, text, px = 320) {
    const qr = window.qrcode(0, "M");
    qr.addData(text);
    qr.make();
    const n = qr.getModuleCount(), quiet = 3, total = n + quiet * 2;
    const scale = Math.max(2, Math.floor(px / total));
    canvas.width = canvas.height = total * scale;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#fff";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#000";
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) ctx.fillRect((c + quiet) * scale, (r + quiet) * scale, scale, scale);
  }
  function scanQR(video, onCode, interval = 140) {
    let stop = false, busy = false;
    const detector = "BarcodeDetector" in window ? new BarcodeDetector({ formats: ["qr_code"] }) : null;
    const cv = document.createElement("canvas"), cx = cv.getContext("2d", { willReadFrequently: true });
    const tick = async () => {
      if (stop) return;
      if (!busy && video.videoWidth) {
        busy = true;
        try {
          let code = null;
          if (detector) {
            const r = await detector.detect(video);
            if (r[0]) code = r[0].rawValue;
          }
          if (!code && window.jsQR) {
            const k = Math.min(1, 720 / video.videoWidth);
            cv.width = Math.round(video.videoWidth * k);
            cv.height = Math.round(video.videoHeight * k);
            cx.drawImage(video, 0, 0, cv.width, cv.height);
            const img = cx.getImageData(0, 0, cv.width, cv.height);
            const r = window.jsQR(img.data, img.width, img.height, { inversionAttempts: "dontInvert" });
            if (r) code = r.data;
          }
          if (code && code.startsWith(SIGNAL_PREFIX)) {
            stop = true;
            onCode(code);
            return;
          }
        } catch {
        }
        busy = false;
      }
      setTimeout(tick, interval);
    };
    tick();
    return () => {
      stop = true;
    };
  }

  // src/icons.js
  var P = {
    video: '<path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h8A2.5 2.5 0 0 1 16 7.5v9a2.5 2.5 0 0 1-2.5 2.5h-8A2.5 2.5 0 0 1 3 16.5z"/><path d="m16 10 5-3v10l-5-3"/>',
    videoFill: '<path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h8A2.5 2.5 0 0 1 16 7.5v9a2.5 2.5 0 0 1-2.5 2.5h-8A2.5 2.5 0 0 1 3 16.5z"/><path d="m16 10 5-3v10l-5-3z"/>',
    play: '<path d="M7 4.5v15l13-7.5z"/>',
    folder: '<path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h3.8l2 2.2h7.2A2.5 2.5 0 0 1 21 9.7v7.8a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5z"/>',
    bars: '<path d="M5 20V13M12 20V5M19 20v-9"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
    camera: '<path d="M4 8.5A2.5 2.5 0 0 1 6.5 6h1.2l1.3-2h6l1.3 2h1.2A2.5 2.5 0 0 1 20 8.5v8a2.5 2.5 0 0 1-2.5 2.5h-11A2.5 2.5 0 0 1 4 16.5z"/><circle cx="12" cy="12.5" r="3.5"/>',
    mic: '<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0 0 14 0M12 18v3"/>',
    micOff: '<path d="M9 9v2a3 3 0 0 0 5.1 2.1M15 9.3V6a3 3 0 0 0-5.9-.8"/><path d="M5 11a7 7 0 0 0 11.3 5.5M19 11a7 7 0 0 1-.7 3M12 18v3M3 3l18 18"/>',
    warn: '<path d="M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4.5M12 17.5v.01"/>',
    shield: '<path d="M12 3 4.5 6v5.5c0 4.7 3.2 8.2 7.5 9.5 4.3-1.3 7.5-4.8 7.5-9.5V6z"/><path d="m8.7 12 2.4 2.4 4.3-4.6"/>',
    wifi: '<path d="M2.5 9a15 15 0 0 1 19 0M5.5 12.5a10.5 10.5 0 0 1 13 0M8.7 16a6 6 0 0 1 6.6 0"/><path d="M12 19.5v.01"/>',
    pin: '<path d="M12 21s-6.5-5.7-6.5-11a6.5 6.5 0 0 1 13 0c0 5.3-6.5 11-6.5 11z"/><circle cx="12" cy="10" r="2.3"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 7.8v.01"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    x: '<path d="M6 6l12 12M18 6 6 18"/>',
    qr: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14v.01M14 20h3M20 17v4"/>',
    flip: '<path d="M4 8V5h3M20 16v3h-3"/><path d="M5.2 9A8 8 0 0 1 19 8M18.8 15A8 8 0 0 1 5 16"/>',
    download: '<path d="M12 4v11M7.5 11 12 15.5 16.5 11M5 20h14"/>',
    trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 12.5A1.5 1.5 0 0 0 8.5 21h7a1.5 1.5 0 0 0 1.5-1.5L18 7M9 7V4.5h6V7"/>',
    archive: '<rect x="3" y="4" width="18" height="4.5" rx="1"/><path d="M5 8.5V19a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8.5M10 13h4"/>',
    unarchive: '<rect x="3" y="4" width="18" height="4.5" rx="1"/><path d="M5 8.5V19a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8.5M12 17v-5M9.5 14 12 11.5 14.5 14"/>',
    flag: '<path d="M5 21V4M5 4h11l-2 4 2 4H5"/>',
    eyeOff: '<path d="M3 3l18 18M10.6 6.1A9.5 9.5 0 0 1 12 6c5 0 8.5 4 9.5 6a14 14 0 0 1-2.8 3.5M6.6 6.7A14.5 14.5 0 0 0 2.5 12c1 2 4.5 6 9.5 6 1.6 0 3-.4 4.2-1M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
    speaker: '<path d="M4 9.5v5h3.5L12 18.5v-13L7.5 9.5zM16 9a4.5 4.5 0 0 1 0 6M18.5 6.5a8 8 0 0 1 0 11"/>',
    speakerOff: '<path d="M4 9.5v5h3.5L12 18.5v-13L7.5 9.5zM22 9.5l-5 5M17 9.5l5 5"/>',
    grid: '<rect x="3.5" y="3.5" width="7" height="7" rx="1"/><rect x="13.5" y="3.5" width="7" height="7" rx="1"/><rect x="3.5" y="13.5" width="7" height="7" rx="1"/><rect x="13.5" y="13.5" width="7" height="7" rx="1"/>',
    photo: '<rect x="3" y="4" width="18" height="16" rx="2.5"/><circle cx="9" cy="10" r="1.8"/><path d="m21 16-5-5-9 9"/>',
    tablet: '<rect x="4" y="3" width="16" height="18" rx="2.5"/><path d="M11 18h2"/>',
    phone: '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/>',
    link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>',
    bolt: '<path d="M13 3 5 13.5h6L10 21l8-10.5h-6z"/>'
  };
  var icon = (n, cls = "") => `<svg class="i ${cls}" viewBox="0 0 24 24" aria-hidden="true">${P[n] || ""}</svg>`;

  // src/db.js
  var NAME = "hexacore";
  var VER = 1;
  var STORES = {
    recordings: { keyPath: "id" },
    chunks: { keyPath: ["rid", "seq"] },
    photos: { keyPath: "id" },
    events: { autoIncrement: true }
  };
  var dbp = null;
  var mem = null;
  function open() {
    if (dbp) return dbp;
    dbp = new Promise((resolve) => {
      try {
        const idb = safeGlobal("indexedDB");
        if (!idb) {
          resolve(null);
          return;
        }
        const req = idb.open(NAME, VER);
        req.onupgradeneeded = () => {
          const d = req.result;
          for (const [n, o] of Object.entries(STORES)) if (!d.objectStoreNames.contains(n)) d.createObjectStore(n, o);
          req.transaction.objectStore("chunks").createIndex("rid", "rid");
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => resolve(null);
        req.onblocked = () => resolve(null);
      } catch {
        resolve(null);
      }
    }).then((d) => {
      if (!d) {
        mem = { recordings: /* @__PURE__ */ new Map(), chunks: /* @__PURE__ */ new Map(), photos: /* @__PURE__ */ new Map(), events: [] };
      }
      return d;
    });
    return dbp;
  }
  var wrap = (req) => new Promise((res, rej) => {
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
  var isPersistent = async () => !!await open();
  async function put(store, val) {
    const d = await open();
    if (!d) {
      if (store === "chunks") mem.chunks.set(`${val.rid}:${val.seq}`, val);
      else if (store === "events") mem.events.push(val);
      else mem[store].set(val.id, val);
      return;
    }
    return wrap(d.transaction(store, "readwrite").objectStore(store).put(val));
  }
  async function get(store, key) {
    const d = await open();
    if (!d) return mem[store].get(key);
    return wrap(d.transaction(store).objectStore(store).get(key));
  }
  async function getAll(store) {
    const d = await open();
    if (!d) return store === "events" ? [...mem.events] : [...mem[store].values()];
    return wrap(d.transaction(store).objectStore(store).getAll());
  }
  async function del(store, key) {
    const d = await open();
    if (!d) {
      mem[store].delete(key);
      return;
    }
    return wrap(d.transaction(store, "readwrite").objectStore(store).delete(key));
  }
  async function chunksOf(rid) {
    const d = await open();
    if (!d) return [...mem.chunks.values()].filter((c) => c.rid === rid).sort((a, b) => a.seq - b.seq);
    const all = await wrap(d.transaction("chunks").objectStore("chunks").index("rid").getAll(rid));
    return all.sort((a, b) => a.seq - b.seq);
  }
  async function delChunks(rid) {
    const d = await open();
    if (!d) {
      for (const k of [...mem.chunks.keys()]) if (k.startsWith(rid + ":")) mem.chunks.delete(k);
      return;
    }
    const tx = d.transaction("chunks", "readwrite");
    const idx = tx.objectStore("chunks").index("rid");
    return new Promise((res) => {
      const cur = idx.openKeyCursor(safeGlobal("IDBKeyRange").only(rid));
      cur.onsuccess = () => {
        const c = cur.result;
        if (c) {
          tx.objectStore("chunks").delete(c.primaryKey);
          c.continue();
        }
      };
      tx.oncomplete = res;
      tx.onerror = res;
    });
  }
  async function clearAll() {
    const d = await open();
    if (!d) {
      mem = { recordings: /* @__PURE__ */ new Map(), chunks: /* @__PURE__ */ new Map(), photos: /* @__PURE__ */ new Map(), events: [] };
      return;
    }
    for (const s of Object.keys(STORES)) await wrap(d.transaction(s, "readwrite").objectStore(s).clear());
  }
  async function recordingBlob(rec) {
    const ch = await chunksOf(rec.id);
    return new Blob(ch.map((c) => c.data), { type: (rec.mime || "video/webm").split(";")[0] });
  }
  async function logEvent(ev) {
    await put("events", { t: Date.now(), ...ev });
  }
  async function recentEvents(n = 80) {
    const all = await getAll("events");
    return all.slice(-n).reverse();
  }

  // src/recorder.js
  var QUALITY = {
    "480p": { w: 854, h: 480, live: 12e5, rec: 15e5 },
    "720p": { w: 1280, h: 720, live: 25e5, rec: 3e6 },
    "1080p": { w: 1920, h: 1080, live: 5e6, rec: 6e6 }
  };
  function grabThumb(el, w = 320) {
    try {
      const vw = el.videoWidth || el.width, vh = el.videoHeight || el.height;
      if (!vw) return null;
      const c = document.createElement("canvas");
      c.width = w;
      c.height = Math.round(w * vh / vw);
      c.getContext("2d").drawImage(el, 0, 0, c.width, c.height);
      return c.toDataURL("image/jpeg", 0.6);
    } catch {
      return null;
    }
  }
  var Recorder = class {
    /**
     * @param {MediaStream} stream
     * @param {object} o { origin, camId, camName, bitrate, now(), thumbEl, gps(), w, h }
     */
    constructor(stream, o) {
      this.stream = stream;
      this.o = o;
      this.queue = Promise.resolve();
      this.active = false;
    }
    get elapsed() {
      return this.active ? performance.now() - this.p0 : this.meta?.dur || 0;
    }
    async start() {
      const mime = pickMime();
      const id = uid();
      this.p0 = performance.now();
      this.mr = new MediaRecorder(this.stream, { mimeType: mime || void 0, videoBitsPerSecond: this.o.bitrate, audioBitsPerSecond: 128e3 });
      this.meta = {
        id,
        camId: this.o.camId,
        camName: this.o.camName,
        origin: this.o.origin,
        t0: this.o.now(),
        t1: null,
        dur: 0,
        mime: this.mr.mimeType || mime,
        size: 0,
        chunks: 0,
        markers: [],
        archived: false,
        thumb: null,
        w: this.o.w || 0,
        h: this.o.h || 0,
        gps: this.o.gps ? this.o.gps() : null
      };
      this.mr.ondataavailable = (e) => {
        if (!e.data || !e.data.size) return;
        this.queue = this.queue.then(async () => {
          this.meta.chunks++;
          this.meta.size += e.data.size;
          this.meta.dur = Math.round(performance.now() - this.p0);
          await put("chunks", { rid: id, seq: this.meta.chunks, data: e.data });
          await put("recordings", this.meta);
        }).catch(() => {
        });
      };
      await put("recordings", this.meta);
      this.mr.start(2e3);
      this.active = true;
      setTimeout(() => {
        if (this.active && this.o.thumbEl) {
          this.meta.thumb = grabThumb(this.o.thumbEl);
          put("recordings", this.meta);
        }
      }, 1200);
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
          this.meta.t1 = this.o.now();
          this.meta.dur = Math.round(performance.now() - this.p0);
          await put("recordings", this.meta);
          res(this.meta);
        });
        try {
          this.mr.stop();
        } catch {
          res(this.meta);
        }
      });
    }
  };
  async function recoverOrphans() {
    const all = await getAll("recordings");
    let n = 0;
    for (const r of all) {
      if (r.t1 == null) {
        r.t1 = r.t0 + (r.dur || 0);
        r.recovered = true;
        await put("recordings", r);
        n++;
      }
    }
    return n;
  }

  // src/camera.js
  var DRAW_FONT = '600 {s}px Rajdhani, "Roboto Mono", monospace';
  var CameraNode = class extends EventTarget {
    constructor({ video, canvas, settings }) {
      super();
      this.video = video;
      this.canvas = canvas;
      this.ctx = canvas.getContext("2d", { alpha: false });
      this.s = { name: "ALPHA-1", quality: "1080p", fps: 30, facing: "environment", overlay: true, emergencyRec: true, mic: true, ...settings };
      this.id = kv.get("camId") || (() => {
        const i = uid();
        kv.set("camId", i);
        return i;
      })();
      this.offset = 0;
      this.linked = false;
      this.state = "idle";
      this.consoleName = null;
      this.gps = null;
      this.battery = { level: null, charging: false };
      this.storage = { usage: 0, quota: 0 };
      this.model = "Smartphone";
      this.recorder = null;
      this.alerting = false;
      this.lastTel = 0;
    }
    emit(type, detail) {
      this.dispatchEvent(new CustomEvent(type, { detail }));
    }
    now() {
      return Date.now() + this.offset;
    }
    // ---------------- Démarrage caméra ----------------
    async start() {
      await this.acquire(true);
      try {
        document.fonts && await document.fonts.load(DRAW_FONT.replace("{s}", "20"));
      } catch {
      }
      this.out = this.canvas.captureStream(this.s.fps);
      const a = this.raw.getAudioTracks()[0];
      if (a) {
        a.enabled = this.s.mic;
        this.out.addTrack(a);
      }
      this.loop();
      this.startTelemetry();
      this.startGps();
      this.wake();
      try {
        const h = await navigator.userAgentData?.getHighEntropyValues?.(["model"]);
        if (h?.model) this.model = h.model;
        else this.model = /Android/i.test(navigator.userAgent) ? "Smartphone Android" : /iPhone/i.test(navigator.userAgent) ? "iPhone" : "Appareil";
      } catch {
      }
      navigator.storage?.persist?.().catch(() => {
      });
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
        this.emit("toast", { msg: "Micro indisponible : vid\xE9o seule", kind: "warn" });
      }
      if (withAudio) this.raw = stream;
      else {
        this.raw.getVideoTracks().forEach((t) => {
          t.stop();
          this.raw.removeTrack(t);
        });
        stream.getVideoTracks().forEach((t) => this.raw.addTrack(t));
      }
      this.video.srcObject = new MediaStream(this.raw.getVideoTracks());
      this.video.muted = true;
      this.video.playsInline = true;
      await this.video.play().catch(() => {
      });
    }
    async flip() {
      this.s.facing = this.s.facing === "environment" ? "user" : "environment";
      await this.acquire(false);
      this.emit("settings", this.s);
    }
    async setQuality(q, fps) {
      if (QUALITY[q]) this.s.quality = q;
      if (fps) this.s.fps = fps;
      const t = this.raw.getVideoTracks()[0], Q = QUALITY[this.s.quality];
      try {
        await t.applyConstraints({ width: { ideal: Q.w }, height: { ideal: Q.h }, frameRate: { ideal: this.s.fps } });
      } catch {
        await this.acquire(false);
      }
      this.applyBitrate();
      this.emit("settings", this.s);
      this.sendTel();
    }
    setMic(on) {
      this.s.mic = on;
      this.raw.getAudioTracks().forEach((t) => t.enabled = on);
      this.emit("settings", this.s);
      this.sendTel();
    }
    // ---------------- Canvas + incrustation ----------------
    loop() {
      const v = this.video;
      const frame = () => {
        this.drawFrame();
        if (this.stopped) return;
        if (v.requestVideoFrameCallback) v.requestVideoFrameCallback(frame);
        else requestAnimationFrame(frame);
      };
      frame();
      this.safety = setInterval(() => {
        if (performance.now() - (this.lastDraw || 0) > 700) this.drawFrame();
      }, 500);
    }
    drawFrame() {
      const v = this.video, c = this.canvas, x = this.ctx;
      if (!v.videoWidth) return;
      if (c.width !== v.videoWidth || c.height !== v.videoHeight) {
        c.width = v.videoWidth;
        c.height = v.videoHeight;
      }
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
      x.font = DRAW_FONT.replace("{s}", s);
      x.textBaseline = "top";
      x.shadowColor = "rgba(0,0,0,.9)";
      x.shadowBlur = s * 0.25;
      x.shadowOffsetY = 1;
      const rec = this.recorder?.active;
      let tx = m;
      if (rec) {
        if (Math.floor(performance.now() / 600) % 2 === 0) {
          x.fillStyle = "#ff2b2b";
          x.beginPath();
          x.arc(m + s * 0.4, m + s * 0.55, s * 0.32, 0, 7);
          x.fill();
        }
        tx = m + s * 1.1;
      }
      x.fillStyle = "#fff";
      x.textAlign = "left";
      x.fillText(this.s.name, tx, m);
      if (rec) {
        x.fillStyle = "#ff6b6b";
        x.fillText("REC", tx, m + s * 1.05);
      }
      x.textAlign = "right";
      x.fillStyle = "#fff";
      x.fillText(time, W - m, m);
      x.fillStyle = "rgba(255,255,255,.8)";
      x.fillText(date, W - m, m + s * 1.05);
      x.textAlign = "left";
      x.textBaseline = "bottom";
      if (this.gps) {
        x.fillStyle = "rgba(255,255,255,.85)";
        x.fillText(`${this.gps.lat.toFixed(5)}  ${this.gps.lon.toFixed(5)}`, m, H - m);
      }
      x.textAlign = "right";
      x.fillStyle = "rgba(255,60,60,.9)";
      x.fillText("HEXACORE", W - m, H - m);
      x.restore();
    }
    // ---------------- Enregistrement local ----------------
    async startRecording(by = "local") {
      if (this.recorder?.active) return;
      const Q = QUALITY[this.s.quality];
      this.recorder = new Recorder(this.out, {
        origin: "camera",
        camId: this.id,
        camName: this.s.name,
        bitrate: Q.rec,
        now: () => this.now(),
        thumbEl: this.canvas,
        gps: () => this.gps && { lat: this.gps.lat, lon: this.gps.lon },
        w: this.canvas.width,
        h: this.canvas.height
      });
      await this.recorder.start();
      this.recStartedBy = by;
      this.emit("rec", { on: true, by });
      this.send({ t: "ev", k: "rec_start", by, rid: this.recorder.meta.id, at: this.now() });
      this.sendTel();
    }
    async stopRecording(by = "local") {
      if (!this.recorder?.active) return;
      const meta = await this.recorder.stop();
      this.emit("rec", { on: false, by, meta });
      this.send({ t: "ev", k: "rec_stop", by, rid: meta.id, at: this.now(), dur: meta.dur });
      this.sendTel();
    }
    addMarker(label = "Rep\xE8re") {
      const m = this.recorder?.mark(label);
      this.send({ t: "ev", k: "marker", label, at: this.now() });
      this.emit("toast", { msg: `Rep\xE8re : ${label}`, kind: "info" });
      return m;
    }
    async takePhoto() {
      this.drawFrame();
      const blob = await new Promise((r) => this.canvas.toBlob(r, "image/jpeg", 0.92));
      const meta = { id: uid(), camId: this.id, camName: this.s.name, t: this.now(), size: blob.size, origin: "camera", gps: this.gps && { lat: this.gps.lat, lon: this.gps.lon } };
      await put("photos", { ...meta, blob });
      this.emit("photo", meta);
      if (this.linked) this.sendPhoto(blob, meta);
      return meta;
    }
    async sendPhoto(blob, meta) {
      const buf = new Uint8Array(await blob.arrayBuffer()), CH = 12e3, n = Math.ceil(buf.length / CH);
      this.send({ t: "photo", id: meta.id, n, meta });
      for (let i = 0; i < n; i++) {
        const part = buf.subarray(i * CH, (i + 1) * CH);
        let bin = "";
        for (let j = 0; j < part.length; j += 8192) bin += String.fromCharCode.apply(null, part.subarray(j, j + 8192));
        while (this.dc && this.dc.bufferedAmount > 1e6) await sleep(30);
        this.send({ t: "pc", id: meta.id, i, d: btoa(bin) });
      }
    }
    sos() {
      this.send({ t: "ev", k: "sos", at: this.now(), gps: this.gps && { lat: this.gps.lat, lon: this.gps.lon } });
      if (this.s.emergencyRec) this.startRecording("sos").then(() => this.addMarker("URGENCE"));
      else this.addMarker("URGENCE");
      this.emit("sos");
    }
    // ---------------- Liaison directe WebRTC (sans serveur) ----------------
    closePeer() {
      try {
        this.dc?.close();
      } catch {
      }
      try {
        this.pc?.close();
      } catch {
      }
      this.pc = this.dc = null;
      this.linked = false;
    }
    async createOffer() {
      this.closePeer();
      const pc = this.pc = new RTCPeerConnection({ iceServers: [] });
      const dc = this.dc = pc.createDataChannel("ctrl", { negotiated: true, id: 0 });
      dc.onopen = () => this.onOpen();
      dc.onmessage = (e) => this.onMessage(e.data);
      dc.onclose = () => this.setState("lost");
      pc.onconnectionstatechange = () => {
        const s = pc.connectionState;
        if (s === "connected") this.setState("connected");
        else if (s === "disconnected") this.setState("unstable");
        else if (s === "failed" || s === "closed") this.setState("lost");
      };
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await waitIce(pc);
      return packSignal("o", pc.localDescription.sdp);
    }
    async acceptAnswer(code) {
      const { kind, sdp } = unpackSignal(code);
      if (kind !== "a") throw new Error("Ce code n\u2019est pas une r\xE9ponse de la console");
      await this.pc.setRemoteDescription({ type: "answer", sdp });
    }
    setState(s) {
      if (this.state === s) return;
      this.state = s;
      this.linked = s === "connected" && this.dc?.readyState === "open";
      this.emit("conn", { state: s });
    }
    async onOpen() {
      this.linked = true;
      this.send({ t: "hello", id: this.id, name: this.s.name, model: this.model, v: 1 });
      for (const t of this.out.getTracks()) {
        const sender = this.pc.addTrack(t, this.out);
        if (t.kind === "video") this.sender = sender;
      }
      try {
        const tr = this.pc.getTransceivers().find((x) => x.sender === this.sender);
        const caps = RTCRtpSender.getCapabilities?.("video")?.codecs || [];
        const h264 = caps.filter((c) => /h264/i.test(c.mimeType));
        if (tr?.setCodecPreferences && h264.length) tr.setCodecPreferences([...h264, ...caps.filter((c) => !/h264/i.test(c.mimeType))]);
      } catch {
      }
      const offer = await this.pc.createOffer();
      await this.pc.setLocalDescription(offer);
      this.send({ t: "sdp", d: { type: offer.type, sdp: offer.sdp } });
      this.applyBitrate();
      this.setState("connected");
      this.sendTel();
    }
    applyBitrate() {
      const sender = this.sender;
      if (!sender) return;
      try {
        const p = sender.getParameters();
        if (!p.encodings?.length) p.encodings = [{}];
        p.encodings[0].maxBitrate = QUALITY[this.s.quality].live;
        p.encodings[0].maxFramerate = this.s.fps;
        sender.setParameters(p);
      } catch {
      }
    }
    send(o) {
      try {
        if (this.dc?.readyState === "open") this.dc.send(JSON.stringify(o));
      } catch {
      }
    }
    async onMessage(raw) {
      let m;
      try {
        m = JSON.parse(raw);
      } catch {
        return;
      }
      switch (m.t) {
        case "hello":
          this.consoleName = m.name;
          this.emit("link", { name: m.name });
          break;
        case "sdp":
          await this.pc.setRemoteDescription(m.d);
          break;
        case "sync":
          this.offset = m.now - Date.now();
          this.emit("sync", { offset: this.offset });
          break;
        case "ping":
          this.send({ t: "pong", ts: m.ts });
          break;
        case "cmd":
          this.command(m.n, m.v);
          break;
        case "ack":
          this.alerting = false;
          this.emit("ack");
          break;
      }
    }
    async command(n, v) {
      switch (n) {
        case "rec_start":
          await this.startRecording("console");
          break;
        case "rec_stop":
          await this.stopRecording("console");
          break;
        case "photo":
          await this.takePhoto();
          break;
        case "mic":
          this.setMic(v);
          break;
        case "flip":
          await this.flip();
          break;
        case "quality":
          await this.setQuality(v.q, v.fps);
          break;
        case "overlay":
          this.s.overlay = !!v;
          this.emit("settings", this.s);
          break;
        case "marker":
          this.addMarker(v || "Rep\xE8re");
          break;
        case "alert":
          this.alerting = true;
          if (v?.rec && !this.recorder?.active) await this.startRecording("alert");
          this.emit("alert", { from: "console" });
          break;
        case "rename":
          this.s.name = v;
          this.emit("settings", this.s);
          break;
      }
      this.sendTel();
    }
    // ---------------- Télémétrie ----------------
    telemetry() {
      const t = this.raw?.getVideoTracks()[0]?.getSettings?.() || {};
      const w = this.canvas.width, h = this.canvas.height;
      return {
        t: "tel",
        name: this.s.name,
        model: this.model,
        bat: this.battery.level,
        chg: this.battery.charging,
        st: this.storage,
        gps: this.gps && { lat: this.gps.lat, lon: this.gps.lon, acc: this.gps.acc },
        rec: !!this.recorder?.active,
        recMs: this.recorder?.active ? Math.round(this.recorder.elapsed) : 0,
        w,
        h,
        fps: Math.round(t.frameRate || this.s.fps),
        q: this.s.quality,
        mic: this.s.mic,
        facing: this.s.facing,
        ovl: this.s.overlay,
        at: this.now()
      };
    }
    sendTel() {
      if (this.linked) this.send(this.telemetry());
    }
    async startTelemetry() {
      try {
        const b = await navigator.getBattery?.();
        if (b) {
          const up = () => this.battery = { level: Math.round(b.level * 100), charging: b.charging };
          up();
          b.addEventListener("levelchange", up);
          b.addEventListener("chargingchange", up);
        }
      } catch {
      }
      const tick = async () => {
        try {
          const e = await navigator.storage?.estimate?.();
          if (e) this.storage = { usage: e.usage, quota: e.quota };
        } catch {
        }
      };
      tick();
      this.tel = setInterval(() => {
        this.sendTel();
      }, 1e3);
      this.tel2 = setInterval(tick, 15e3);
      this.emit("ready");
    }
    startGps() {
      if (!navigator.geolocation) return;
      try {
        this.geoId = navigator.geolocation.watchPosition(
          (p) => {
            this.gps = { lat: p.coords.latitude, lon: p.coords.longitude, acc: p.coords.accuracy };
          },
          () => {
            this.gps = null;
          },
          { enableHighAccuracy: true, maximumAge: 3e3, timeout: 2e4 }
        );
      } catch {
      }
    }
    async wake() {
      try {
        this.wl = await navigator.wakeLock?.request("screen");
        document.addEventListener("visibilitychange", async () => {
          if (document.visibilityState === "visible" && !this.stopped) {
            try {
              this.wl = await navigator.wakeLock.request("screen");
            } catch {
            }
          }
        });
      } catch {
      }
    }
    async stop() {
      this.stopped = true;
      await this.stopRecording("local");
      clearInterval(this.tel);
      clearInterval(this.tel2);
      clearInterval(this.safety);
      if (this.geoId != null) navigator.geolocation.clearWatch(this.geoId);
      this.closePeer();
      this.raw?.getTracks().forEach((t) => t.stop());
      try {
        await this.wl?.release();
      } catch {
      }
    }
  };

  // src/console.js
  var DEFAULTS = { name: "POSTE TAC", autoRec: false, emergencyRec: true, overlay: true, sound: true, quality: "1080p" };
  var CameraLink = class extends EventTarget {
    constructor(hub) {
      super();
      this.hub = hub;
      this.key = uid();
      this.id = null;
      this.name = "CAM\xC9RA";
      this.model = "\u2014";
      this.state = "pairing";
      this.tel = null;
      this.stream = new MediaStream();
      this.rtt = null;
      this.kbps = 0;
      this.lossPct = 0;
      this.fps = 0;
      this.w = 0;
      this.h = 0;
      this.rec = null;
      this.photos = /* @__PURE__ */ new Map();
      this.sosAt = null;
      this.lastTelAt = 0;
      this.video = document.createElement("video");
      Object.assign(this.video, { muted: true, autoplay: true, playsInline: true });
      this.video.style.cssText = "position:fixed;width:2px;height:2px;opacity:0;pointer-events:none;left:0;top:0";
      document.body.appendChild(this.video);
    }
    emit(type, detail) {
      this.dispatchEvent(new CustomEvent(type, { detail }));
    }
    get connected() {
      return this.state === "connected" || this.state === "unstable";
    }
    get recording() {
      return !!this.rec?.active;
    }
    async accept(code) {
      const { kind, sdp } = unpackSignal(code);
      if (kind !== "o") throw new Error("Ce code n\u2019est pas une offre de cam\xE9ra");
      const pc = this.pc = new RTCPeerConnection({ iceServers: [] });
      const dc = this.dc = pc.createDataChannel("ctrl", { negotiated: true, id: 0 });
      dc.onmessage = (e) => this.onMessage(e.data);
      dc.onopen = () => this.setState("connected");
      dc.onclose = () => this.setState("lost");
      pc.ontrack = (e) => {
        if (!this.stream.getTracks().includes(e.track)) this.stream.addTrack(e.track);
        if (this.video.srcObject !== this.stream) this.video.srcObject = this.stream;
        this.video.play().catch(() => {
        });
        this.emit("stream");
      };
      pc.onconnectionstatechange = () => {
        const s = pc.connectionState;
        if (s === "connected") this.setState("connected");
        else if (s === "disconnected") this.setState("unstable");
        else if (s === "failed" || s === "closed") this.setState("lost");
      };
      await pc.setRemoteDescription({ type: "offer", sdp });
      const ans = await pc.createAnswer();
      await pc.setLocalDescription(ans);
      await waitIce(pc);
      return packSignal("a", pc.localDescription.sdp);
    }
    setState(s) {
      if (this.state === s || this.closed) return;
      const prev = this.state;
      this.state = s;
      if (s === "connected" && prev === "pairing") {
        this.hub.log("link", `${this.name} : liaison \xE9tablie`, this);
      }
      if (s === "unstable") this.hub.log("warn", `${this.name} : liaison instable`, this);
      if (s === "lost") {
        this.hub.log("error", `${this.name} : liaison perdue`, this);
        if (this.rec?.active) this.stopRec("liaison perdue");
        clearInterval(this.statTimer);
        clearInterval(this.pingTimer);
      }
      if (s === "connected") this.startPolling();
      this.emit("state");
      this.hub.changed();
    }
    send(o) {
      try {
        if (this.dc?.readyState === "open") this.dc.send(JSON.stringify(o));
      } catch {
      }
    }
    cmd(n, v) {
      this.send({ t: "cmd", n, v });
    }
    startPolling() {
      clearInterval(this.statTimer);
      clearInterval(this.pingTimer);
      this.pingTimer = setInterval(() => this.send({ t: "ping", ts: performance.now() }), 1500);
      this.statTimer = setInterval(() => this.poll(), 1e3);
    }
    async poll() {
      if (!this.pc) return;
      try {
        const st = await this.pc.getStats();
        let bytes = 0, lost = 0, recv = 0, rtt = null;
        st.forEach((r) => {
          if (r.type === "inbound-rtp" && r.kind === "video") {
            bytes = r.bytesReceived;
            lost = r.packetsLost;
            recv = r.packetsReceived;
            this.fps = Math.round(r.framesPerSecond || 0);
            this.w = r.frameWidth || this.w;
            this.h = r.frameHeight || this.h;
          }
          if (r.type === "candidate-pair" && r.nominated && r.state === "succeeded" && r.currentRoundTripTime != null) rtt = r.currentRoundTripTime * 1e3;
        });
        const now = performance.now();
        if (this.prev) {
          const dt = (now - this.prev.t) / 1e3;
          this.kbps = Math.max(0, (bytes - this.prev.bytes) * 8 / dt / 1e3);
          const dl = lost - this.prev.lost, dr = recv - this.prev.recv;
          this.lossPct = dl + dr > 0 ? dl / (dl + dr) * 100 : 0;
        }
        this.prev = { t: now, bytes, lost, recv };
        if (this.rtt == null && rtt != null) this.rtt = rtt;
        this.emit("stats");
      } catch {
      }
    }
    get quality() {
      if (!this.connected) return { label: "Hors liaison", cls: "off" };
      if (this.state === "unstable") return { label: "Instable", cls: "bad" };
      const r = this.rtt ?? 999;
      if (r < 120 && this.lossPct < 2) return { label: "Excellente", cls: "good" };
      if (r < 300 && this.lossPct < 6) return { label: "Bonne", cls: "ok" };
      return { label: "Faible", cls: "bad" };
    }
    async onMessage(raw) {
      let m;
      try {
        m = JSON.parse(raw);
      } catch {
        return;
      }
      switch (m.t) {
        case "hello": {
          this.id = m.id;
          this.name = m.name;
          this.model = m.model;
          this.hub.dedupe(this);
          this.send({ t: "hello", name: this.hub.s.name });
          this.send({ t: "sync", now: Date.now() });
          if (this.hub.s.overlay === false) this.cmd("overlay", false);
          this.emit("hello");
          this.hub.changed();
          break;
        }
        case "sdp": {
          await this.pc.setRemoteDescription(m.d);
          if (m.d.type === "offer") {
            const a = await this.pc.createAnswer();
            await this.pc.setLocalDescription(a);
            this.send({ t: "sdp", d: { type: a.type, sdp: a.sdp } });
          }
          break;
        }
        case "pong":
          this.rtt = performance.now() - m.ts;
          break;
        case "tel": {
          const first = !this.tel;
          this.tel = m;
          this.lastTelAt = performance.now();
          this.name = m.name || this.name;
          this.model = m.model || this.model;
          if (m.rec && !this.rec?.active) this.startRec("cam\xE9ra");
          if (!m.rec && this.rec?.active) this.stopRec("cam\xE9ra");
          if (first && this.hub.s.autoRec && !m.rec) this.cmd("rec_start");
          this.emit("tel");
          break;
        }
        case "ev":
          this.onEvent(m);
          break;
        case "photo":
          this.photos.set(m.id, { meta: m.meta, n: m.n, parts: [] });
          break;
        case "pc": {
          const p = this.photos.get(m.id);
          if (!p) break;
          p.parts[m.i] = Uint8Array.from(atob(m.d), (c) => c.charCodeAt(0));
          if (p.parts.filter(Boolean).length === p.n) {
            const blob = new Blob(p.parts, { type: "image/jpeg" });
            const meta = { ...p.meta, origin: "console", size: blob.size, camName: this.name };
            await put("photos", { ...meta, blob });
            this.photos.delete(m.id);
            this.hub.log("photo", `${this.name} : photo re\xE7ue`, this);
            this.hub.emit("photo", meta);
          }
          break;
        }
      }
    }
    onEvent(m) {
      switch (m.k) {
        case "rec_start":
          if (!this.rec?.active) this.startRec(m.by === "sos" ? "urgence" : m.by === "console" ? "console" : m.by === "alert" ? "alerte" : "cam\xE9ra");
          break;
        case "rec_stop":
          if (this.rec?.active) this.stopRec(m.by);
          break;
        case "marker":
          this.rec?.mark(m.label);
          this.hub.log("marker", `${this.name} : rep\xE8re \xAB ${m.label} \xBB`, this);
          break;
        case "sos":
          this.sosAt = Date.now();
          this.hub.log("sos", `${this.name} : URGENCE d\xE9clench\xE9e par le joueur`, this);
          this.hub.raiseAlert(this, m);
          break;
      }
    }
    async startRec(by = "console") {
      if (this.rec?.active || this.starting) return;
      if (!this.stream.getVideoTracks().length) {
        setTimeout(() => this.startRec(by), 500);
        return;
      }
      this.starting = true;
      const rec = new Recorder(this.stream, {
        origin: "console",
        camId: this.id,
        camName: this.name,
        bitrate: 35e5,
        now: () => Date.now(),
        thumbEl: this.video,
        w: this.w,
        h: this.h,
        gps: () => this.tel?.gps && { lat: this.tel.gps.lat, lon: this.tel.gps.lon }
      });
      this.rec = rec;
      await rec.start();
      this.starting = false;
      this.hub.log("rec", `${this.name} : enregistrement d\xE9marr\xE9 (${by})`, this);
      this.emit("rec");
      this.hub.changed();
    }
    async stopRec(by = "console") {
      if (!this.rec?.active) return;
      const meta = await this.rec.stop();
      this.hub.log("rec", `${this.name} : enregistrement termin\xE9 (${by})`, this);
      this.emit("rec");
      this.hub.changed();
      this.hub.emit("recsaved", meta);
    }
    toggleRec() {
      if (this.recording || this.tel?.rec) this.cmd("rec_stop");
      else this.cmd("rec_start");
    }
    mark(label = "Rep\xE8re") {
      this.cmd("marker", label);
    }
    close() {
      this.closed = true;
      clearInterval(this.statTimer);
      clearInterval(this.pingTimer);
      if (this.rec?.active) this.stopRec("fermeture");
      try {
        this.dc?.close();
        this.pc?.close();
      } catch {
      }
      this.video.srcObject = null;
      this.video.remove();
    }
  };
  var ConsoleHub = class extends EventTarget {
    constructor() {
      super();
      this.s = { ...DEFAULTS, ...kv.get("console") || {} };
      this.links = [];
      this.selectedKey = null;
      this.alerts = [];
      this.logs = [];
      recentEvents(60).then((l) => {
        this.logs = l;
        this.emit("log");
      });
    }
    emit(type, detail) {
      this.dispatchEvent(new CustomEvent(type, { detail }));
    }
    saveSettings() {
      kv.set("console", this.s);
    }
    changed() {
      this.emit("change");
    }
    get selected() {
      return this.links.find((l) => l.key === this.selectedKey) || this.links.find((l) => l.id) || null;
    }
    get ready() {
      return this.links.filter((l) => l.id && l.state !== "lost");
    }
    get any() {
      return this.links.filter((l) => l.id);
    }
    newLink() {
      const l = new CameraLink(this);
      this.links.push(l);
      l.addEventListener("state", () => this.changed());
      return l;
    }
    removeLink(l) {
      l.close();
      this.links = this.links.filter((x) => x !== l);
      if (this.selectedKey === l.key) this.selectedKey = null;
      this.changed();
    }
    /** Une caméra qui se ré-associe remplace son ancienne entrée. */
    dedupe(link) {
      for (const o of this.links.filter((x) => x !== link && x.id === link.id)) this.removeLink(o);
      if (!this.selectedKey) this.selectedKey = link.key;
      this.changed();
    }
    select(key) {
      this.selectedKey = key;
      this.changed();
    }
    log(type, text, link) {
      const e = { t: Date.now(), type, text, cam: link?.name };
      this.logs.unshift(e);
      this.logs = this.logs.slice(0, 120);
      logEvent(e).catch(() => {
      });
      this.emit("log", e);
    }
    raiseAlert(link, m) {
      this.alerts.unshift({ key: link.key, name: link.name, at: Date.now(), gps: m.gps });
      if (this.s.sound) beep();
      if (navigator.vibrate) navigator.vibrate([300, 120, 300]);
      this.emit("alert");
    }
    ackAlert(key) {
      const l = this.links.find((x) => x.key === key);
      l?.send({ t: "ack" });
      this.alerts = this.alerts.filter((a) => a.key !== key);
      this.emit("alert");
    }
    /** URGENCE console : alerte la caméra ciblée (ou toutes) et déclenche l’enregistrement. */
    emergency(target) {
      const list = target ? [target] : this.ready;
      for (const l of list) {
        l.cmd("alert", { rec: this.s.emergencyRec });
        this.log("sos", `URGENCE envoy\xE9e \xE0 ${l.name}`, l);
        if (this.s.emergencyRec) setTimeout(() => l.mark("URGENCE"), 1200);
      }
      if (!list.length) this.log("warn", "Urgence : aucune cam\xE9ra li\xE9e");
    }
    /** Test avec cet appareil : une caméra virtuelle liée à la console dans le même onglet. */
    async startLoopback() {
      const host = document.createElement("div");
      host.style.cssText = "position:fixed;left:-9999px;top:0;width:4px;height:4px;overflow:hidden";
      const video = document.createElement("video"), canvas = document.createElement("canvas");
      host.append(video, canvas);
      document.body.appendChild(host);
      const node = new CameraNode({ video, canvas, settings: { name: "D\xC9MO-1", quality: "720p", facing: "user" } });
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
      await this.demo.node.stop();
      this.demo.host.remove();
      this.removeLink(this.demo.link);
      this.demo = null;
    }
  };

  // src/ui-console.js
  var resLabel = (w, h) => {
    const m = Math.min(w || 0, h || 0);
    if (!m) return "\u2014";
    if (m >= 1e3) return `${m}p (FHD)`;
    if (m >= 700) return `${m}p (HD)`;
    return `${m}p`;
  };
  var mbps = (k) => k >= 1e3 ? `${(k / 1e3).toFixed(1).replace(".", ",")} Mb/s` : `${Math.round(k)} kb/s`;
  var slug = (s) => String(s || "CAM").normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^\w-]+/g, "_");
  var vname = (r) => `HXC_${slug(r.camName)}_${fmtFileStamp(new Date(r.t0))}`;
  function mountConsole(root2, hub, app2) {
    let view = "live", lib = "videos", mosaic = false, speaker = true, urgArm = 0, urls = [], pairCtl = null;
    root2.innerHTML = `
  <div class="console" id="console">
    <header class="top">
      <div class="brand"><img src="img/logo-mark.png" alt="" width="56" height="52"><div class="wordmark"><span class="b1">HEXACORE</span><span class="b2">BODYCAM</span></div></div>
      <div class="stat rec" id="st-rec"><i class="dot"></i><div><div class="lbl" id="rec-l">Pr\xEAt \xE0 enregistrer</div><div class="val tnum" id="rec-t">00:00:00</div></div></div>
      <div class="stat" id="st-cam"><i class="dot" id="cam-d"></i><div><div class="lbl" id="cam-l">Aucune cam\xE9ra</div><div class="sub" id="cam-s">Associez un t\xE9l\xE9phone</div></div></div>
      <div class="stat bat"><div><div class="lbl">Batterie cam\xE9ra</div><div class="batrow"><span class="bar" id="bat-bar"><i style="width:0"></i></span><span class="val tnum" id="bat-v">\u2014</span></div></div></div>
      <div class="clock"><div class="time tnum" id="clk-t">--:--</div><div class="date" id="clk-d"></div></div>
    </header>
    <nav class="side" aria-label="Navigation principale">
      <div class="nav">
        <button data-a="nav" data-v="live">${icon("videoFill")}<span>Live view</span></button>
        <button data-a="nav" data-v="rec">${icon("play")}<span>Enregistrements</span></button>
        <button data-a="nav" data-v="arch">${icon("folder")}<span>Archives</span></button>
        <button data-a="nav" data-v="status">${icon("bars")}<span>Statut syst\xE8me</span></button>
        <button data-a="nav" data-v="settings">${icon("gear")}<span>Param\xE8tres</span></button>
      </div>
      <div class="sig"><div class="n">HEXACORE</div><div class="f">FIELD SOLUTIONS</div></div>
    </nav>
    <main class="view" id="view"></main>
    <footer class="foot"><div class="ok" id="foot-s">${icon("shield")}<span>Syst\xE8me op\xE9rationnel</span></div><div>HEXACORE BODYCAM v${VERSION}</div></footer>
  </div>
  <div id="overlays"></div>`;
    const view$ = $("#view");
    const revoke = () => {
      urls.forEach(URL.revokeObjectURL);
      urls = [];
    };
    const objUrl = (b) => {
      const u = URL.createObjectURL(b);
      urls.push(u);
      return u;
    };
    function go(v) {
      view = v;
      revoke();
      $$(".nav button").forEach((b) => b.setAttribute("aria-current", b.dataset.v === v ? "page" : "false"));
      ({ live: renderLive, rec: () => renderLib(false), arch: () => renderLib(true), status: renderStatus, settings: renderSettings })[v]();
      tick();
    }
    function renderLive() {
      view$.innerHTML = `
    <section class="live">
      <div class="stagewrap">
        <div class="camstrip" id="strip"></div>
        <div class="stage" id="stage"></div>
      </div>
      <aside class="info" aria-label="Informations cam\xE9ra">
        <h3>${icon("info")}Informations cam\xE9ra</h3>
        <dl class="kv"><dt>Mod\xE8le :</dt><dd id="i-model">\u2014</dd><dt>R\xE9solution :</dt><dd id="i-res">\u2014</dd><dt>FPS :</dt><dd id="i-fps">\u2014</dd><dt>Orientation :</dt><dd id="i-ori">\u2014</dd><dt>Stockage libre :</dt><dd id="i-sto">\u2014</dd></dl>
        <dl class="kv sep"><dt>${icon("wifi")}Connexion :</dt><dd id="i-con" class="off">\u2014</dd><dt>&nbsp;&nbsp;&nbsp;&nbsp;Latence :</dt><dd id="i-lat">\u2014</dd><dt>&nbsp;&nbsp;&nbsp;&nbsp;D\xE9bit :</dt><dd id="i-br">\u2014</dd></dl>
        <div class="gpsh">${icon("pin")}<span>GPS (si disponible)</span></div>
        <dl class="kv"><dt>Latitude :</dt><dd id="i-lat1">\u2014</dd><dt>Longitude :</dt><dd id="i-lon">\u2014</dd></dl>
      </aside>
      <div class="actions">
        <button class="act rec" data-a="rec" id="b-rec"></button><span class="sep"></span>
        <button class="act photo" data-a="photo" id="b-photo">${icon("camera")}<span>Capture<br>photo</span></button><span class="sep"></span>
        <button class="act mic" data-a="mic" id="b-mic" aria-pressed="true"><span class="on">${icon("mic")}</span><span class="off">${icon("micOff")}</span><span id="b-mic-t">Micro<br>(on)</span></button><span class="sep"></span>
        <button class="act mark" data-a="mark" id="b-mark">${icon("flag")}<span>Rep\xE8re</span></button><span class="sep"></span>
        <button class="act urg" data-a="urg" id="b-urg">${icon("warn")}<span id="b-urg-t">Urgence</span></button>
      </div>
    </section>`;
      renderStrip();
      renderStage();
    }
    function renderStrip() {
      const el = $("#strip");
      if (!el) return;
      const sel = hub.selected;
      const html = hub.any.map((l) => `<button class="chip" data-a="cam" data-k="${l.key}" aria-pressed="${sel === l}"><i class="dot ${l.state === "connected" ? "green" : l.state === "unstable" ? "amber" : "red"}"></i>${esc(l.name)}${l.recording ? '<span class="rc">\u25CF REC</span>' : ""}</button>`).join("") + `<button class="chip add" data-a="add">${icon("plus")}Cam\xE9ra</button>` + (hub.ready.length > 1 ? `<button class="chip" data-a="mosaic" aria-pressed="${mosaic}" style="margin-left:auto">${icon("grid")}Mosa\xEFque</button>` : "");
      if (el.dataset.h !== html) {
        el.dataset.h = html;
        el.innerHTML = html;
      }
    }
    let stageKey = "";
    function renderStage() {
      const st = $("#stage");
      if (!st) return;
      const sel = hub.selected, ready = hub.ready;
      const key = [sel?.key, mosaic && ready.length > 1, ready.map((l) => l.key).join()].join("|");
      if (key === stageKey && st.children.length) return;
      stageKey = key;
      if (!hub.any.length) {
        st.innerHTML = `<div class="empty"><div class="ring">${icon("videoFill")}</div><h3>Aucune cam\xE9ra li\xE9e</h3>
        <p>Lancez HEXACORE sur le t\xE9l\xE9phone du joueur (r\xF4le Cam\xE9ra), touchez \xAB Associer \xBB, puis scannez son QR code ici. Aucun Internet n\u2019est n\xE9cessaire.</p>
        <div class="btnrow" style="display:flex;gap:.8rem;flex-wrap:wrap;justify-content:center"><button class="btn pri" data-a="add">${icon("qr")}Ajouter une cam\xE9ra</button><button class="btn" data-a="demo">${icon("phone")}Tester avec cet appareil</button></div></div>`;
        return;
      }
      if (mosaic && ready.length > 1) {
        const n = ready.length, cols = n <= 2 ? n : n <= 4 ? 2 : 3;
        st.innerHTML = `<div class="mosaic" style="grid-template-columns:repeat(${cols},1fr)">${ready.map((l) => `<div class="tile ${l.recording ? "rec" : ""}" data-a="tile" data-k="${l.key}" aria-current="${l === sel}"><video autoplay playsinline muted data-k="${l.key}"></video><span class="cap">${esc(l.name)}</span></div>`).join("")}</div>`;
        $$("video", st).forEach((v2) => {
          const l = hub.links.find((x) => x.key === v2.dataset.k);
          v2.srcObject = l.stream;
          v2.play().catch(() => {
          });
        });
        return;
      }
      st.innerHTML = `<video id="sv" autoplay playsinline></video>
      <div class="hud tl"><span class="tag" id="h-res">\u2014</span><span class="tag" id="h-fps">\u2014</span></div>
      <div class="hud tr"><span class="live-tag off" id="h-live"><i></i><span>LIVE</span></span></div>
      <div class="hud bl"><span class="camname" id="h-name"></span></div>
      <div class="hud" style="right:.8rem;bottom:.8rem;gap:.5rem"><button class="ib" data-a="speaker" id="b-spk" aria-label="Son du flux" aria-pressed="${speaker}">${icon(speaker ? "speaker" : "speakerOff")}</button></div>
      <div class="empty" id="wait" style="display:none"><div class="ring">${icon("videoFill")}</div><h3 id="wait-t">R\xE9ception du flux\u2026</h3><p id="wait-p"></p></div>`;
      const v = $("#sv");
      v.muted = !speaker;
      if (sel) {
        v.srcObject = sel.stream;
        v.play().catch(() => {
          v.muted = true;
          v.play().catch(() => {
          });
        });
      }
    }
    function tick() {
      const now = /* @__PURE__ */ new Date();
      $("#clk-t").textContent = fmtClock(now);
      $("#clk-d").textContent = fmtDate(now);
      const l = hub.selected, tel = l?.tel;
      const recOn = !!(l && (l.recording || tel?.rec));
      const sr = $("#st-rec");
      sr.classList.toggle("on", recOn);
      $("#rec-l").textContent = recOn ? "Enregistrement en cours" : "Pr\xEAt \xE0 enregistrer";
      $("#rec-t").textContent = fmtDur(recOn ? l.rec?.active ? l.rec.elapsed : tel?.recMs || 0 : 0);
      $(".dot", sr).className = "dot " + (recOn ? "red" : "");
      const cd = $("#cam-d"), cl = $("#cam-l"), cs = $("#cam-s");
      if (!hub.any.length) {
        cd.className = "dot";
        cl.textContent = "Aucune cam\xE9ra";
        cs.textContent = "Associez un t\xE9l\xE9phone";
      } else if (l) {
        const extra = hub.ready.length > 1 ? ` \xB7 ${hub.ready.length} cam\xE9ras` : "";
        if (l.state === "lost") {
          cd.className = "dot red";
          cl.textContent = "Liaison perdue";
          cs.textContent = `${l.name} \xB7 r\xE9-associez la cam\xE9ra`;
        } else if (l.state === "unstable") {
          cd.className = "dot amber";
          cl.textContent = "Liaison instable";
          cs.textContent = l.name;
        } else {
          cd.className = "dot green";
          cl.textContent = "Cam\xE9ra connect\xE9e";
          cs.textContent = `${l.name}${extra}${l.rtt != null ? ` \xB7 ${Math.round(l.rtt)} ms` : ""}`;
        }
      }
      const bat = tel?.bat, bb = $("#bat-bar");
      $("#bat-v").textContent = bat != null ? `${bat} %` : "\u2014";
      bb.className = "bar " + (bat != null && bat < 20 ? "low" : bat != null && bat < 40 ? "mid" : "");
      $("i", bb).style.width = (bat ?? 0) + "%";
      const fs = $("#foot-s"), alerting = hub.alerts.length;
      fs.className = "ok " + (alerting ? "alert" : !hub.any.length || l && l.state !== "connected" ? "warn" : "");
      $("span", fs).textContent = alerting ? "Alerte urgence active" : !hub.any.length ? "En attente de cam\xE9ra" : l?.state === "lost" ? "Liaison perdue" : l?.state === "unstable" ? "Liaison instable" : "Syst\xE8me op\xE9rationnel";
      if (view === "live") tickLive(l, tel, recOn);
      else if (view === "status") renderStatus();
    }
    function tickLive(l, tel, recOn) {
      renderStrip();
      renderStage();
      const set = (id, t, cls) => {
        const e = $("#" + id);
        if (e) {
          e.textContent = t;
          if (cls != null) e.className = cls;
        }
      };
      const w = tel?.w || l?.w, h = tel?.h || l?.h;
      set("i-model", l?.model || "\u2014");
      set("i-res", l ? resLabel(w, h) : "\u2014");
      set("i-fps", tel ? `${tel.fps} ips` : "\u2014");
      set("i-ori", w && h ? h > w ? "Portrait" : "Paysage" : "\u2014");
      set("i-sto", tel?.st?.quota ? `${fmtGo(Math.max(0, tel.st.quota - tel.st.usage))} / ${fmtGo(tel.st.quota)}` : "\u2014");
      const q = l?.quality || { label: "\u2014", cls: "off" };
      set("i-con", q.label, q.cls);
      set("i-lat", l?.rtt != null ? `${Math.round(l.rtt)} ms` : "\u2014");
      set("i-br", l?.connected ? mbps(l.kbps) : "\u2014");
      set("i-lat1", tel?.gps ? tel.gps.lat.toFixed(4) : "Indisponible");
      set("i-lon", tel?.gps ? tel.gps.lon.toFixed(4) : "Indisponible");
      set("h-res", l ? `${Math.min(w || 0, h || 0) || "\u2014"}p` : "\u2014");
      set("h-fps", l?.fps || tel?.fps ? `${l?.fps || tel?.fps} FPS` : "\u2014");
      const live = $("#h-live");
      if (live) {
        live.className = "live-tag" + (l?.connected && l.kbps > 20 ? "" : " off");
      }
      set("h-name", l?.name || "");
      const wait = $("#wait");
      if (wait && l) {
        const noVideo = !l.stream.getVideoTracks().length || l.connected && l.kbps < 5 && !l.fps;
        wait.style.display = l.state === "lost" || noVideo ? "" : "none";
        if (l.state === "lost") {
          set("wait-t", "Liaison perdue");
          set("wait-p", "La cam\xE9ra continue d\u2019enregistrer en local. Rapprochez-vous puis r\xE9-associez-la (Cam\xE9ra \u2192 Associer).");
        } else if (noVideo) {
          set("wait-t", "R\xE9ception du flux\u2026");
          set("wait-p", "");
        }
      }
      const br = $("#b-rec"), connected = !!l?.connected;
      br.disabled = !connected;
      br.className = "act rec" + (recOn ? " on" : "");
      br.innerHTML = `<span class="rcirc ${recOn ? "sq" : ""}"></span><span>${recOn ? "Arr\xEAter<br>l\u2019enregistrement" : "D\xE9marrer<br>l\u2019enregistrement"}</span>`;
      for (const id of ["b-photo", "b-mic", "b-mark", "b-urg"]) $("#" + id).disabled = !connected;
      const mic = tel?.mic ?? true;
      const bm = $("#b-mic");
      bm.setAttribute("aria-pressed", mic);
      $("#b-mic-t").innerHTML = `Micro<br>(${mic ? "on" : "off"})`;
      if (urgArm && Date.now() > urgArm) {
        urgArm = 0;
      }
      const bu = $("#b-urg");
      bu.classList.toggle("armed", !!urgArm);
      $("#b-urg-t").textContent = urgArm ? "Confirmer ?" : "Urgence";
    }
    async function renderLib(archived) {
      revoke();
      view$.innerHTML = `<div class="page"><div class="page-h"><div><h2>${archived ? "Archives" : "Enregistrements"}</h2><div class="sub">${archived ? "\xC9l\xE9ments conserv\xE9s hors de la liste courante." : "Copies enregistr\xE9es sur la tablette. Chaque fichier est horodat\xE9 et r\xE9f\xE9rence ses rep\xE8res."}</div></div>
      <div class="seg"><button data-a="lib" data-t="videos" aria-pressed="${lib === "videos"}">Vid\xE9os</button><button data-a="lib" data-t="photos" aria-pressed="${lib === "photos"}">Photos</button></div></div><div id="lib"></div></div>`;
      const host = $("#lib");
      if (lib === "videos") {
        const all = (await getAll("recordings")).filter((r) => r.origin === "console" && !!r.archived === archived && r.t1 != null).sort((a, b) => b.t0 - a.t0);
        if (view !== (archived ? "arch" : "rec")) return;
        if (!all.length) {
          host.innerHTML = emptyList(archived ? "Aucune archive" : "Aucun enregistrement", archived ? "Archivez un enregistrement pour le retrouver ici." : "D\xE9marrez un enregistrement depuis le Live view : une copie sera conserv\xE9e sur cette tablette.", "play");
          return;
        }
        host.innerHTML = `<div class="grid">${all.map((r) => `<article class="card"><button class="th" data-a="play" data-id="${r.id}" aria-label="Lire ${esc(vname(r))}" style="${r.thumb ? `background-image:url(${r.thumb})` : ""}">${r.thumb ? "" : icon("videoFill")}<span class="pl">${icon("play", "fill")}</span><span class="du tnum">${fmtDur(r.dur)}</span></button>
        <div class="bd"><div class="nm">${esc(r.camName)}${r.recovered ? " \xB7 r\xE9cup\xE9r\xE9" : ""}</div><div class="mt"><span>${fmtStamp(new Date(r.t0))}</span><span>${fmtSize(r.size)}</span>${r.markers?.length ? `<span>${r.markers.length} rep\xE8re${r.markers.length > 1 ? "s" : ""}</span>` : ""}</div></div>
        <div class="ac"><button class="btn sm" data-a="play" data-id="${r.id}">${icon("play")}Lire</button><button class="btn sm" data-a="export" data-id="${r.id}">${icon("download")}Exporter</button><button class="btn sm" data-a="arc" data-id="${r.id}">${icon(archived ? "unarchive" : "archive")}${archived ? "Restaurer" : "Archiver"}</button><button class="btn sm danger" data-a="del" data-id="${r.id}">${icon("trash")}</button></div></article>`).join("")}</div>`;
      } else {
        const all = (await getAll("photos")).filter((p) => p.origin === "console" && !!p.archived === archived).sort((a, b) => b.t - a.t);
        if (view !== (archived ? "arch" : "rec")) return;
        if (!all.length) {
          host.innerHTML = emptyList("Aucune photo", "Utilisez \xAB Capture photo \xBB : la photo horodat\xE9e est envoy\xE9e \xE0 la tablette.", "photo");
          return;
        }
        host.innerHTML = `<div class="grid">${all.map((p) => {
          const u = objUrl(p.blob);
          return `<article class="card"><button class="th" data-a="viewphoto" data-id="${p.id}" style="background-image:url(${u})" aria-label="Agrandir la photo"><span class="pl">${icon("photo")}</span></button><div class="bd"><div class="nm">${esc(p.camName)}</div><div class="mt"><span>${fmtStamp(new Date(p.t))}</span><span>${fmtSize(p.size)}</span></div></div>
        <div class="ac"><button class="btn sm" data-a="expphoto" data-id="${p.id}">${icon("download")}Exporter</button><button class="btn sm" data-a="arcphoto" data-id="${p.id}">${icon(archived ? "unarchive" : "archive")}${archived ? "Restaurer" : "Archiver"}</button><button class="btn sm danger" data-a="delphoto" data-id="${p.id}">${icon("trash")}</button></div></article>`;
        }).join("")}</div>`;
      }
    }
    const emptyList = (t, d, ic) => `<div class="empty-list">${icon(ic)}<b>${t}</b>${d}</div>`;
    async function openPlayer(id) {
      const r = await get("recordings", id);
      if (!r) return;
      const blob = await recordingBlob(r);
      const u = objUrl(blob);
      const m = modal(`<div class="dlg wide"><h3><span>${esc(vname(r))}</span><button class="x" data-a="close" aria-label="Fermer">${icon("x")}</button></h3>
      <div class="player"><video id="pv" controls playsinline src="${u}"></video>
      <aside><dl class="kv" style="margin:0"><dt>Cam\xE9ra</dt><dd>${esc(r.camName)}</dd><dt>D\xE9but</dt><dd>${fmtStamp(new Date(r.t0))}</dd><dt>Dur\xE9e</dt><dd class="tnum">${fmtDur(r.dur)}</dd><dt>Taille</dt><dd>${fmtSize(r.size)}</dd><dt>Format</dt><dd>${esc((r.mime || "").split(";")[0])}</dd>${r.gps ? `<dt>Position</dt><dd>${r.gps.lat.toFixed(4)}, ${r.gps.lon.toFixed(4)}</dd>` : ""}</dl>
      <div><div class="lbl" style="margin-bottom:.5rem">Rep\xE8res (${r.markers?.length || 0})</div><div class="mk">${(r.markers || []).map((k) => `<button data-a="seek" data-s="${k.at / 1e3}"><b class="tnum">${fmtDur(k.at)}</b><span>${esc(k.label)}</span></button>`).join("") || '<span class="sub">Aucun rep\xE8re</span>'}</div></div>
      <button class="btn sm" data-a="hash" id="hashb">${icon("shield")}Empreinte SHA-256</button><code id="hashv" style="font-size:.7rem;word-break:break-all;color:var(--mut)"></code>
      <button class="btn" data-a="export" data-id="${r.id}">${icon("download")}Exporter le fichier</button></aside></div></div>`);
      const v = $("#pv", m);
      v.addEventListener("loadedmetadata", () => {
        if (v.duration === Infinity) {
          v.currentTime = 1e101;
          v.addEventListener("timeupdate", function f() {
            v.removeEventListener("timeupdate", f);
            v.currentTime = 0;
          });
        }
      });
      m.addEventListener("click", async (e) => {
        const b = e.target.closest("[data-a]");
        if (!b) return;
        if (b.dataset.a === "seek") {
          v.currentTime = +b.dataset.s;
          v.play();
        }
        if (b.dataset.a === "hash") {
          $("#hashv", m).textContent = "Calcul\u2026";
          const buf = await blob.arrayBuffer();
          const d = await crypto.subtle.digest("SHA-256", buf);
          $("#hashv", m).textContent = [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join("");
        }
      });
    }
    async function renderStatus() {
      const est = await navigator.storage?.estimate?.().catch(() => null);
      let batt = null;
      try {
        const b = await navigator.getBattery?.();
        if (b) batt = `${Math.round(b.level * 100)} %${b.charging ? " (en charge)" : ""}`;
      } catch {
      }
      const persistent = await isPersistent();
      if (view !== "status") return;
      const cam = (l) => `<div class="panel"><h3><i class="dot ${l.state === "connected" ? "green" : l.state === "unstable" ? "amber" : "red"}"></i>${esc(l.name)}</h3><div class="sub">${esc(l.model)}</div>
      <dl class="kv"><dt>Liaison</dt><dd class="${l.quality.cls}">${l.quality.label}</dd><dt>Latence</dt><dd>${l.rtt != null ? Math.round(l.rtt) + " ms" : "\u2014"}</dd><dt>D\xE9bit vid\xE9o</dt><dd>${l.connected ? mbps(l.kbps) : "\u2014"}</dd><dt>Perte de paquets</dt><dd>${l.lossPct.toFixed(1).replace(".", ",")} %</dd><dt>Flux</dt><dd>${resLabel(l.w, l.h)} \xB7 ${l.fps || "\u2014"} ips</dd><dt>Batterie</dt><dd>${l.tel?.bat != null ? l.tel.bat + " %" + (l.tel.chg ? " \u26A1" : "") : "\u2014"}</dd><dt>Enregistrement</dt><dd>${l.recording || l.tel?.rec ? "En cours" : "Arr\xEAt\xE9"}</dd><dt>Stockage cam\xE9ra</dt><dd>${l.tel?.st?.quota ? fmtGo(l.tel.st.quota - l.tel.st.usage) + " libres" : "\u2014"}</dd></dl></div>`;
      view$.innerHTML = `<div class="page"><div class="page-h"><div><h2>Statut syst\xE8me</h2><div class="sub">\xC9tat de la tablette, des liaisons et journal horodat\xE9.</div></div></div>
      <div class="cards3"><div class="panel"><h3>${icon("tablet")}Poste \xB7 ${esc(hub.s.name)}</h3><dl class="kv"><dt>Batterie tablette</dt><dd>${batt || "\u2014"}</dd><dt>Stockage utilis\xE9</dt><dd>${est ? fmtSize(est.usage) + " / " + fmtGo(est.quota) : "\u2014"}</dd><dt>Base locale</dt><dd class="${persistent ? "good" : "bad"}">${persistent ? "Persistante" : "M\xE9moire (non persistante)"}</dd><dt>Internet</dt><dd>${navigator.onLine ? "Disponible (non requis)" : "Hors ligne (mode normal)"}</dd><dt>Application hors ligne</dt><dd class="${app2.offlineReady ? "good" : "off"}">${app2.offlineReady ? "Install\xE9e" : "Non install\xE9e"}</dd><dt>Version</dt><dd>${VERSION}</dd></dl></div>
      ${hub.any.map(cam).join("")}</div>
      <div class="panel log"><h3>${icon("bars")}Journal d\u2019\xE9v\xE9nements</h3><ol>${hub.logs.slice(0, 40).map((e) => `<li class="${e.type}"><time class="tnum">${fmtStamp(new Date(e.t)).slice(11)}</time><span>${esc(e.text)}</span></li>`).join("") || '<li><span class="sub">Aucun \xE9v\xE9nement</span></li>'}</ol></div></div>`;
    }
    function renderSettings() {
      const s = hub.s;
      const tg = (k, t, d) => `<div class="row"><div><div class="t">${t}</div><div class="d">${d}</div></div><button class="tgl" role="switch" aria-checked="${!!s[k]}" data-a="tgl" data-k="${k}" aria-label="${t}"></button></div>`;
      view$.innerHTML = `<div class="page"><div class="page-h"><div><h2>Param\xE8tres</h2><div class="sub">R\xE9glages du poste de commandement.</div></div></div>
      <div class="set">
      <div class="panel"><h3>Poste</h3><div class="row"><div><div class="t">Nom du poste</div><div class="d">Affich\xE9 sur les cam\xE9ras li\xE9es.</div></div><input class="inp" id="s-name" value="${esc(s.name)}" maxlength="24" aria-label="Nom du poste"></div></div>
      <div class="panel"><h3>Enregistrement</h3>
        ${tg("autoRec", "Enregistrer d\xE8s la liaison", "D\xE9marre automatiquement l\u2019enregistrement quand une cam\xE9ra se connecte.")}
        ${tg("emergencyRec", "Urgence : enregistrer automatiquement", "Le bouton Urgence lance l\u2019enregistrement et pose un rep\xE8re sur la cam\xE9ra cibl\xE9e.")}
        ${tg("overlay", "Incrustation horodat\xE9e", "Nom de la cam\xE9ra, date, heure (synchronis\xE9e sur la tablette) et GPS grav\xE9s dans la vid\xE9o.")}
      </div>
      <div class="panel"><h3>Alertes</h3>${tg("sound", "Son d\u2019alerte", "Bip et vibration \xE0 la r\xE9ception d\u2019une urgence joueur.")}</div>
      <div class="panel"><h3>Qualit\xE9 de liaison</h3><div class="row"><div><div class="t">Qualit\xE9 demand\xE9e aux cam\xE9ras</div><div class="d">720p est plus fiable \xE0 distance ; 1080p demande une liaison forte. L\u2019enregistrement local de la cam\xE9ra suit le m\xEAme r\xE9glage.</div></div><select class="sel" id="s-q" aria-label="Qualit\xE9">${["480p", "720p", "1080p"].map((q) => `<option ${s.quality === q ? "selected" : ""}>${q}</option>`).join("")}</select></div><div style="padding-top:.8rem"><button class="btn" data-a="applyq">Appliquer aux cam\xE9ras li\xE9es</button></div></div>
      <div class="panel"><h3>Donn\xE9es</h3><div class="row"><div><div class="t">Tout effacer</div><div class="d">Supprime enregistrements, photos et journal de cette tablette. Irr\xE9versible.</div></div><button class="btn danger" data-a="wipe" id="wipeb">${icon("trash")}Effacer</button></div>
        <div class="row"><div><div class="t">Changer de r\xF4le</div><div class="d">Revenir \xE0 l\u2019\xE9cran de choix Console / Cam\xE9ra.</div></div><button class="btn" data-a="role">Changer</button></div></div>
      <div class="panel"><h3>${icon("shield")}\xC0 savoir</h3><p class="sub" style="line-height:1.55;font-size:.88rem">Le bouton Urgence est une alerte de jeu entre joueurs, pas un appel aux secours : en cas de blessure r\xE9elle, appelez le 112. Enregistrez uniquement avec l\u2019accord des participants et de l\u2019organisateur.</p></div>
      </div></div>`;
      $("#s-name").addEventListener("input", (e) => {
        hub.s.name = e.target.value.trim() || "POSTE TAC";
        hub.saveSettings();
      });
      $("#s-q").addEventListener("change", (e) => {
        hub.s.quality = e.target.value;
        hub.saveSettings();
      });
    }
    function modal(html) {
      const m = document.createElement("div");
      m.className = "modal";
      m.innerHTML = html;
      m.addEventListener("click", (e) => {
        if (e.target === m || e.target.closest("[data-a=close]")) {
          m.remove();
          pairCleanup();
        }
      });
      $("#overlays").appendChild(m);
      return m;
    }
    const pairCleanup = () => {
      if (pairCtl) {
        pairCtl.stop();
        pairCtl = null;
      }
    };
    function openPair() {
      const m = modal(`<div class="dlg"><h3><span>Ajouter une cam\xE9ra</span><button class="x" data-a="close" aria-label="Fermer">${icon("x")}</button></h3>
      <div class="steps"><span class="on" id="ps1"></span><span id="ps2"></span><span id="ps3"></span></div><div id="pair-body"></div></div>`);
      const body = $("#pair-body", m);
      let stream = null, stopScan = null, pending = null;
      const killCam = () => {
        stopScan?.();
        stopScan = null;
        stream?.getTracks().forEach((t) => t.stop());
        stream = null;
      };
      pairCtl = { stop: () => {
        killCam();
        if (pending && !pending.id) hub.removeLink(pending);
      } };
      async function accept(code) {
        killCam();
        body.innerHTML = `<div class="wait"><div class="spin"></div>Cr\xE9ation de la liaison\u2026</div>`;
        pending = hub.newLink();
        try {
          const answer = await pending.accept(code);
          $("#ps2", m).classList.add("on");
          body.innerHTML = `<p class="lead">Pr\xE9sentez ce QR code \xE0 la cam\xE9ra du t\xE9l\xE9phone (touchez \xAB Scanner la r\xE9ponse \xBB). La liaison d\xE9marre automatiquement.</p>
          <div class="qrbox"><canvas id="aq" aria-label="QR code de r\xE9ponse"></canvas></div>
          <div class="wait"><div class="spin"></div>En attente du t\xE9l\xE9phone\u2026</div>
          <details class="guide" style="margin-top:1rem"><summary>Pas de scan possible ? Copier le code</summary><textarea class="inp" readonly id="acode" style="margin-bottom:12px">${answer}</textarea><button class="btn sm" data-a="copyc">${icon("copy")}Copier</button></details>`;
          drawQR($("#aq", m), answer, 360);
          const link = pending;
          const done = () => {
            if (!link.id) return;
            link.removeEventListener("hello", done);
            $("#ps3", m).classList.add("on");
            toast(`${link.name} li\xE9e`, "ok");
            hub.select(link.key);
            pairCtl = null;
            m.remove();
            go("live");
          };
          link.addEventListener("hello", done);
          setTimeout(() => {
            if (!link.id && document.body.contains(m)) {
              const w = $(".wait", m);
              if (w) w.innerHTML = '<span style="color:var(--amber)">Toujours en attente. V\xE9rifiez que les deux appareils sont sur le m\xEAme r\xE9seau local (point d\u2019acc\xE8s de la tablette) puis recommencez.</span>';
            }
          }, 25e3);
        } catch (e) {
          hub.removeLink(pending);
          pending = null;
          toast(e.message || "Code invalide", "error");
          startScan();
        }
      }
      async function startScan() {
        body.innerHTML = `<p class="lead">Sur le t\xE9l\xE9phone : r\xF4le Cam\xE9ra, d\xE9marrer, puis \xAB Associer \xBB. Cadrez son QR code avec la tablette.</p>
        <div class="scanbox"><video id="sv2" playsinline muted autoplay></video><div class="ms" id="scanms" style="display:none"></div></div>
        <div style="display:flex;gap:.6rem;margin-top:1rem;flex-wrap:wrap"><button class="btn" data-a="manual">${icon("link")}Saisir un code</button></div>`;
        try {
          stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" }, width: { ideal: 1280 } }, audio: false });
          const v = $("#sv2", m);
          v.srcObject = stream;
          await v.play();
          stopScan = scanQR(v, accept);
        } catch {
          const ms = $("#scanms", m);
          ms.style.display = "grid";
          ms.textContent = "Cam\xE9ra de la tablette indisponible. Utilisez \xAB Saisir un code \xBB.";
        }
      }
      m.addEventListener("click", (e) => {
        const b = e.target.closest("[data-a]");
        if (!b) return;
        if (b.dataset.a === "manual") {
          killCam();
          body.innerHTML = `<p class="lead">Collez le code affich\xE9 par le t\xE9l\xE9phone (\xAB Copier mon code \xBB).</p><textarea class="inp" id="mcode" placeholder="HXC1.\u2026"></textarea><div style="display:flex;gap:.6rem;margin-top:1rem"><button class="btn pri" data-a="mgo">Valider</button><button class="btn" data-a="mback">${icon("qr")}Scanner</button></div>`;
        }
        if (b.dataset.a === "mgo") accept($("#mcode", m).value);
        if (b.dataset.a === "mback") startScan();
        if (b.dataset.a === "copyc") {
          navigator.clipboard?.writeText($("#acode", m).value).then(() => toast("Code copi\xE9", "ok")).catch(() => {
            $("#acode", m).select();
          });
        }
      });
      startScan();
      window.__pair = { accept };
    }
    function renderAlerts() {
      const host = $("#overlays");
      host.querySelector(".alertov")?.remove();
      const a = hub.alerts[0];
      if (!a) return;
      const el = document.createElement("div");
      el.className = "alertov";
      el.setAttribute("role", "alertdialog");
      el.setAttribute("aria-label", "Urgence");
      el.innerHTML = `<div class="box">${icon("warn")}<div class="big">URGENCE</div><div class="who">${esc(a.name)}</div><div class="sub">${fmtStamp(new Date(a.at)).slice(11)}${a.gps ? ` \xB7 ${a.gps.lat.toFixed(4)}, ${a.gps.lon.toFixed(4)}` : ""}</div>
      <div class="btns"><button class="btn" data-a="alertview" data-k="${a.key}">${icon("videoFill")}Voir le flux</button><button class="btn pri" data-a="ack" data-k="${a.key}">Acquitter</button></div></div>`;
      $("svg", el).style.cssText = "width:4rem;height:4rem;color:#fff;margin:auto";
      host.appendChild(el);
    }
    const confirmTap = (btn, fn) => {
      if (btn.dataset.armed) {
        fn();
        return;
      }
      btn.dataset.armed = "1";
      const o = btn.innerHTML;
      btn.innerHTML = "Confirmer ?";
      setTimeout(() => {
        delete btn.dataset.armed;
        if (btn.isConnected) btn.innerHTML = o;
      }, 3e3);
    };
    const A = {
      nav: (b) => go(b.dataset.v),
      add: () => openPair(),
      demo: async (b) => {
        b.disabled = true;
        try {
          const l = await hub.startLoopback();
          hub.select(l.key);
          toast("Cam\xE9ra de test li\xE9e (cet appareil)", "ok");
        } catch (e) {
          toast("Test impossible : " + (e.message || e), "error");
          b.disabled = false;
        }
      },
      cam: (b) => {
        hub.select(b.dataset.k);
        stageKey = "";
        renderLive();
      },
      tile: (b) => {
        hub.select(b.dataset.k);
        mosaic = false;
        stageKey = "";
        renderLive();
      },
      mosaic: () => {
        mosaic = !mosaic;
        stageKey = "";
        renderStage();
        renderStrip();
      },
      speaker: (b) => {
        speaker = !speaker;
        const v = $("#sv");
        if (v) {
          v.muted = !speaker;
          v.play().catch(() => {
          });
        }
        b.setAttribute("aria-pressed", speaker);
        b.innerHTML = icon(speaker ? "speaker" : "speakerOff");
      },
      rec: () => hub.selected?.toggleRec(),
      photo: () => {
        hub.selected?.cmd("photo");
        toast("Photo demand\xE9e", "info", 1500);
      },
      mic: () => {
        const l = hub.selected;
        l?.cmd("mic", !(l.tel?.mic ?? true));
      },
      mark: () => {
        const l = hub.selected;
        if (!l) return;
        const n = (l.rec?.meta.markers.length || 0) + 1;
        l.mark(`Rep\xE8re ${n}`);
        toast(`Rep\xE8re ${n} pos\xE9`, "ok", 1500);
      },
      urg: () => {
        if (!urgArm) {
          urgArm = Date.now() + 3e3;
          tickLive(hub.selected, hub.selected?.tel, false);
          return;
        }
        urgArm = 0;
        hub.emergency(hub.selected);
        toast("Urgence envoy\xE9e \xE0 la cam\xE9ra", "warn");
      },
      lib: (b) => {
        lib = b.dataset.t;
        renderLib(view === "arch");
      },
      play: (b) => openPlayer(b.dataset.id),
      export: async (b) => {
        const r = await get("recordings", b.dataset.id);
        download(await recordingBlob(r), `${vname(r)}.${extFor(r.mime)}`);
      },
      arc: async (b) => {
        const r = await get("recordings", b.dataset.id);
        r.archived = !r.archived;
        await put("recordings", r);
        renderLib(view === "arch");
        toast(r.archived ? "Archiv\xE9" : "Restaur\xE9", "ok", 1500);
      },
      del: (b) => confirmTap(b, async () => {
        await del("recordings", b.dataset.id);
        await delChunks(b.dataset.id);
        renderLib(view === "arch");
      }),
      viewphoto: async (b) => {
        const p = await get("photos", b.dataset.id);
        modal(`<div class="dlg wide photo-view"><h3><span>${esc(p.camName)} \xB7 ${fmtStamp(new Date(p.t))}</span><button class="x" data-a="close">${icon("x")}</button></h3><img src="${objUrl(p.blob)}" alt="Photo horodat\xE9e"></div>`);
      },
      expphoto: async (b) => {
        const p = await get("photos", b.dataset.id);
        download(p.blob, `HXC_${slug(p.camName)}_${fmtFileStamp(new Date(p.t))}.jpg`);
      },
      arcphoto: async (b) => {
        const p = await get("photos", b.dataset.id);
        p.archived = !p.archived;
        await put("photos", p);
        renderLib(view === "arch");
      },
      delphoto: (b) => confirmTap(b, async () => {
        await del("photos", b.dataset.id);
        renderLib(view === "arch");
      }),
      tgl: (b) => {
        const k = b.dataset.k;
        hub.s[k] = !hub.s[k];
        hub.saveSettings();
        b.setAttribute("aria-checked", hub.s[k]);
        if (k === "overlay") hub.ready.forEach((l) => l.cmd("overlay", hub.s.overlay));
      },
      applyq: () => {
        hub.ready.forEach((l) => l.cmd("quality", { q: hub.s.quality, fps: 30 }));
        toast(hub.ready.length ? "Qualit\xE9 envoy\xE9e" : "Aucune cam\xE9ra li\xE9e", "ok");
      },
      wipe: (b) => confirmTap(b, async () => {
        await clearAll();
        hub.logs = [];
        toast("Donn\xE9es effac\xE9es", "ok");
      }),
      role: () => app2.chooseRole(),
      ack: (b) => hub.ackAlert(b.dataset.k),
      alertview: (b) => {
        hub.select(b.dataset.k);
        go("live");
      }
    };
    root2.addEventListener("click", (e) => {
      const b = e.target.closest("[data-a]");
      if (b && A[b.dataset.a] && !b.closest(".modal[data-own]")) A[b.dataset.a](b, e);
    });
    hub.addEventListener("change", () => {
      if (view === "live") {
        stageKey = "";
        renderStrip();
        renderStage();
      }
    });
    hub.addEventListener("alert", renderAlerts);
    hub.addEventListener("recsaved", () => {
      toast("Enregistrement sauvegard\xE9 sur la tablette", "ok");
      if (view === "rec") renderLib(false);
    });
    hub.addEventListener("photo", () => {
      toast("Photo re\xE7ue", "ok", 1800);
      if (view === "rec" && lib === "photos") renderLib(false);
    });
    const timer = setInterval(tick, 500);
    go("live");
    return () => {
      clearInterval(timer);
      revoke();
    };
  }

  // src/ui-camera.js
  function mountCamera(root2, app2) {
    const saved = { name: "ALPHA-1", quality: "1080p", fps: 30, facing: "environment", overlay: true, emergencyRec: true, mic: true, ...kv.get("camSettings") || {} };
    let node = null, sheet = null, scanStop = null, dimmed = false, lastTap = 0, alarm = null, timer = null;
    root2.innerHTML = `
  <div class="cam" id="cam">
    <video class="rawv" id="raw" playsinline muted></video>
    <canvas id="prev" aria-label="Aper\xE7u cam\xE9ra"></canvas>
    <div class="cam-top"><span class="chipx" id="c-link"><i class="dot"></i><span>Non li\xE9e</span></span><span class="chipx rec" id="c-rec" style="display:none"><i class="dot red"></i><span class="tnum">00:00:00</span></span><span class="chipx" id="c-bat"><span class="tnum">\u2014</span></span></div>
    <div class="cam-bot" id="bot" style="visibility:hidden">
      <button class="cb" data-a="pair"><span class="c">${icon("qr")}</span>Associer</button>
      <button class="cb" data-a="photo"><span class="c">${icon("camera")}</span>Photo</button>
      <button class="cb main" data-a="rec" id="b-rec"><span class="c"></span><span id="b-rec-t">REC</span></button>
      <button class="cb" data-a="dim"><span class="c">${icon("eyeOff")}</span>\xC9cran noir</button>
      <button class="cb" data-a="set"><span class="c">${icon("gear")}</span>R\xE9glages</button>
    </div>
    <button class="cb sos" id="sos" style="position:absolute;right:10px;top:calc(env(safe-area-inset-top) + 64px);z-index:6;flex:none;visibility:hidden" aria-label="Urgence : maintenir appuy\xE9"><span class="c"><i id="sos-f"></i>${icon("warn")}</span>SOS</button>
    <div class="start" id="start">
      <div class="logo"><img src="img/logo-mark.png" alt=""><div class="wordmark"><span class="b1">HEXACORE</span><span class="b2">BODYCAM</span></div></div>
      <h2 style="font-family:var(--f-tech);font-size:1.6rem;letter-spacing:.08em">CAM\xC9RA DE TERRAIN</h2>
      <label for="f-name">Indicatif</label><input class="inp" id="f-name" maxlength="16" value="${esc(saved.name)}" autocapitalize="characters" autocomplete="off">
      <label for="f-q">Qualit\xE9</label><select class="sel" id="f-q">${["480p", "720p", "1080p"].map((q) => `<option ${saved.quality === q ? "selected" : ""}>${q}</option>`).join("")}</select>
      <label for="f-f">Cam\xE9ra</label><select class="sel" id="f-f"><option value="environment" ${saved.facing === "environment" ? "selected" : ""}>Arri\xE8re</option><option value="user" ${saved.facing === "user" ? "selected" : ""}>Avant</option></select>
      <button class="btn pri" id="go">${icon("videoFill")}D\xE9marrer la cam\xE9ra</button>
      <p class="note">Autorisez cam\xE9ra, micro et position quand le t\xE9l\xE9phone le demande. Laissez l\u2019\xE9cran allum\xE9 : utilisez \xAB \xC9cran noir \xBB pour \xE9conomiser la batterie sans interrompre l\u2019enregistrement.</p>
      <button class="link-btn" style="margin-top:1rem;align-self:flex-start;color:var(--mut)" data-a="role">Changer de r\xF4le</button>
    </div>
    <div class="flash" id="flash" role="alertdialog"><div class="big" id="fl-t">ALERTE</div><div id="fl-s" style="font-size:1.1rem"></div><button class="btn" data-a="flashoff" style="background:#fff;color:#900">Compris</button></div>
    <div class="dim" id="dim" style="display:none"><div class="r" id="dim-r">\u25CF STANDBY</div><small>Double appui pour r\xE9veiller</small></div>
  </div>`;
    const camEl = $("#cam");
    const persist2 = () => kv.set("camSettings", node ? node.s : saved);
    $("#go").addEventListener("click", async () => {
      const btn = $("#go");
      btn.disabled = true;
      btn.textContent = "D\xE9marrage\u2026";
      saved.name = ($("#f-name").value.trim() || "ALPHA-1").toUpperCase();
      saved.quality = $("#f-q").value;
      saved.facing = $("#f-f").value;
      node = new CameraNode({ video: $("#raw"), canvas: $("#prev"), settings: saved });
      try {
        await node.start();
      } catch (e) {
        btn.disabled = false;
        btn.innerHTML = `${icon("videoFill")}R\xE9essayer`;
        toast(e.name === "NotAllowedError" ? "Acc\xE8s cam\xE9ra refus\xE9 : autorisez-le dans le navigateur" : "Cam\xE9ra indisponible : " + (e.message || e.name), "error", 6e3);
        return;
      }
      persist2();
      node.addEventListener("conn", onConn);
      node.addEventListener("link", () => {
        toast(`Li\xE9e \xE0 ${node.consoleName}`, "ok");
        closeSheet();
      });
      node.addEventListener("rec", () => hud());
      node.addEventListener("toast", (e) => toast(e.detail.msg, e.detail.kind));
      node.addEventListener("photo", () => toast("Photo enregistr\xE9e", "ok", 1500));
      node.addEventListener("alert", () => showFlash("ALERTE", "Demande de la console", true));
      node.addEventListener("sos", () => showFlash("SOS ENVOY\xC9", "En attente d\u2019acquittement de la console", false));
      node.addEventListener("ack", () => {
        hideFlash();
        toast("Urgence acquitt\xE9e par la console", "ok");
      });
      node.addEventListener("settings", persist2);
      $("#start").remove();
      $("#bot").style.visibility = $("#sos").style.visibility = "visible";
      timer = setInterval(hud, 500);
      hud();
      window.__node = node;
    });
    function onConn(e) {
      hud();
      if (e.detail.state === "connected") {
        toast("Liaison \xE9tablie", "ok");
        closeSheet();
      }
      if (e.detail.state === "lost") toast("Liaison perdue : l\u2019enregistrement local continue", "warn", 4500);
    }
    function hud() {
      if (!node) return;
      const link = $("#c-link"), st = node.state;
      const txt = st === "connected" ? `Li\xE9e \xB7 ${node.consoleName || "console"}` : st === "unstable" ? "Liaison instable" : st === "lost" ? "Liaison perdue" : "Non li\xE9e";
      $(".dot", link).className = "dot " + (st === "connected" ? "green" : st === "unstable" ? "amber" : st === "lost" ? "red" : "");
      $("span", link).textContent = txt;
      const rec = node.recorder?.active, cr = $("#c-rec");
      cr.style.display = rec ? "" : "none";
      if (rec) $(".tnum", cr).textContent = fmtDur(node.recorder.elapsed);
      const b = node.battery.level;
      $("#c-bat .tnum").textContent = b != null ? `${b} %${node.battery.charging ? " \u26A1" : ""}` : "\u2014";
      $("#b-rec").classList.toggle("on", !!rec);
      $("#b-rec-t").textContent = rec ? "STOP" : "REC";
      const dr = $("#dim-r");
      if (dr) {
        dr.className = "r" + (rec ? " on" : "");
        dr.textContent = rec ? `\u25CF REC ${fmtDur(node.recorder.elapsed)}` : "\u25CF STANDBY";
      }
    }
    function openSheet(html) {
      closeSheet(true);
      sheet = document.createElement("div");
      sheet.className = "sheet";
      sheet.innerHTML = html;
      camEl.appendChild(sheet);
      return sheet;
    }
    function closeSheet(keepScan) {
      sheet?.remove();
      sheet = null;
      if (!keepScan) {
        scanStop?.();
        scanStop = null;
        $(".reticle")?.remove();
      }
    }
    async function openPair() {
      if (node.linked && node.state === "connected") {
        const s2 = openSheet(`<h3>Liaison active<button class="x" data-a="closesheet">${icon("x")}</button></h3><p>Li\xE9e \xE0 ${esc(node.consoleName || "la console")}. Les commandes de la tablette (REC, photo, micro, urgence) sont actives.</p><div class="stack"><button class="btn" data-a="repair">Nouvelle association</button></div>`);
        return s2;
      }
      const s = openSheet(`<h3>Associer \xE0 la tablette<button class="x" data-a="closesheet">${icon("x")}</button></h3><p>Sur la tablette : <b>Ajouter une cam\xE9ra</b>, puis scannez ce QR code.</p><div class="qrbox"><canvas id="oq" aria-label="QR code d\u2019association"></canvas></div><div class="wait"><div class="spin"></div>Pr\xE9paration\u2026</div>`);
      let offer;
      try {
        offer = await node.createOffer();
      } catch (e) {
        toast("Impossible de pr\xE9parer la liaison", "error");
        return;
      }
      if (!sheet) return;
      drawQR($("#oq", s), offer, 420);
      $(".wait", s).remove();
      s.insertAdjacentHTML("beforeend", `<div class="stack"><button class="btn pri" data-a="scan">${icon("qr")}2. Scanner la r\xE9ponse de la tablette</button><button class="btn" data-a="manualpair">${icon("link")}Code manuel</button></div>`);
      s.dataset.offer = offer;
    }
    function startScan() {
      closeSheet(true);
      const hint = openSheet(`<div class="scanhint">Visez le QR code de la tablette</div><div class="stack"><button class="btn" data-a="closesheet">Annuler</button></div>`);
      hint.style.cssText = "padding-top:.8rem";
      camEl.insertAdjacentHTML("beforeend", '<div class="reticle"></div>');
      scanStop = scanQR(node.video, async (code) => {
        $(".reticle")?.remove();
        scanStop = null;
        try {
          await node.acceptAnswer(code);
          toast("R\xE9ponse re\xE7ue, liaison en cours\u2026", "info");
          openSheet(`<div class="wait"><div class="spin"></div>Connexion \xE0 la tablette\u2026</div>`);
          setTimeout(() => {
            if (node.state !== "connected" && sheet) {
              sheet.innerHTML = `<h3>Liaison impossible<button class="x" data-a="closesheet">${icon("x")}</button></h3><p>V\xE9rifiez que t\xE9l\xE9phone et tablette sont sur le m\xEAme r\xE9seau local (point d\u2019acc\xE8s de la tablette), puis recommencez.</p><div class="stack"><button class="btn pri" data-a="repair">Recommencer</button></div>`;
            }
          }, 15e3);
        } catch (e) {
          toast(e.message || "QR invalide", "error");
          closeSheet();
        }
      });
    }
    function manualPair() {
      const offer = sheet?.dataset.offer || "";
      openSheet(`<h3>Code manuel<button class="x" data-a="closesheet">${icon("x")}</button></h3><p>Copiez ce code vers la tablette (Ajouter une cam\xE9ra \u2192 Saisir un code), puis collez ici le code de r\xE9ponse.</p>
      <textarea class="inp" readonly id="mo">${offer}</textarea><div class="stack"><button class="btn" data-a="copyo">${icon("copy")}Copier mon code</button></div>
      <p style="margin-top:1rem">Code de r\xE9ponse :</p><textarea class="inp" id="ma" placeholder="HXC1.\u2026"></textarea><div class="stack"><button class="btn pri" data-a="sendans">Valider</button></div>`);
    }
    async function openSettings() {
      const s = node.s;
      const recs = (await getAll("recordings")).filter((r) => r.origin === "camera" && r.t1 != null).sort((a, b) => b.t0 - a.t0);
      const tg = (k, t) => `<div class="row"><div class="t">${t}</div><button class="tgl" role="switch" aria-checked="${!!s[k]}" data-a="tgl" data-k="${k}" aria-label="${t}"></button></div>`;
      openSheet(`<h3>R\xE9glages<button class="x" data-a="closesheet">${icon("x")}</button></h3>
      <div class="row"><div class="t">Indicatif</div><input class="inp" id="s-n" value="${esc(s.name)}" maxlength="16" style="min-width:0;width:9rem"></div>
      <div class="row"><div class="t">Qualit\xE9</div><select class="sel" id="s-q" style="min-width:0">${["480p", "720p", "1080p"].map((q) => `<option ${s.quality === q ? "selected" : ""}>${q}</option>`).join("")}</select></div>
      ${tg("mic", "Micro")}${tg("overlay", "Incrustation date / heure / GPS")}${tg("emergencyRec", "SOS : enregistrer automatiquement")}
      <div class="stack"><button class="btn" data-a="flip">${icon("flip")}Changer de cam\xE9ra</button></div>
      <h3 style="margin-top:1.3rem;font-size:1.1rem">Enregistrements sur ce t\xE9l\xE9phone</h3>
      <div class="rl">${recs.map((r) => `<div class="it"><div><b>${esc(r.camName)}</b> <span>${fmtStamp(new Date(r.t0)).slice(5, 16)} \xB7 ${fmtDur(r.dur)} \xB7 ${fmtSize(r.size)}</span></div><div style="display:flex;gap:.4rem"><button class="btn sm" data-a="exp" data-id="${r.id}" aria-label="Exporter">${icon("download")}</button><button class="btn sm danger" data-a="rm" data-id="${r.id}" aria-label="Supprimer">${icon("trash")}</button></div></div>`).join("") || '<span class="sub" style="color:var(--mut)">Aucun enregistrement.</span>'}</div>
      <div class="stack"><button class="btn" data-a="role">Changer de r\xF4le / quitter</button></div>`);
      $("#s-n", sheet).addEventListener("change", (e) => {
        node.s.name = e.target.value.trim().toUpperCase() || "ALPHA-1";
        persist2();
        node.sendTel();
      });
      $("#s-q", sheet).addEventListener("change", (e) => node.setQuality(e.target.value));
    }
    function showFlash(t, s, siren) {
      $("#fl-t").textContent = t;
      $("#fl-s").textContent = s;
      $("#flash").classList.add("on");
      clearInterval(alarm);
      const go = () => {
        beep();
        navigator.vibrate?.([400, 150, 400]);
      };
      go();
      if (siren) alarm = setInterval(go, 2500);
      if (dimmed) wake();
    }
    function hideFlash() {
      clearInterval(alarm);
      alarm = null;
      $("#flash").classList.remove("on");
    }
    const wake = () => {
      dimmed = false;
      $("#dim").style.display = "none";
    };
    const A = {
      pair: openPair,
      repair: openPair,
      scan: startScan,
      manualpair: manualPair,
      closesheet: () => closeSheet(),
      set: openSettings,
      flip: () => node.flip().catch(() => toast("Changement de cam\xE9ra impossible", "error")),
      photo: () => node.takePhoto(),
      rec: () => node.recorder?.active ? node.stopRecording("local") : node.startRecording("local"),
      dim: () => {
        dimmed = true;
        $("#dim").style.display = "flex";
        hud();
      },
      flashoff: () => {
        hideFlash();
      },
      role: async () => {
        if (node) {
          clearInterval(timer);
          await node.stop();
        }
        app2.chooseRole();
      },
      copyo: () => {
        navigator.clipboard?.writeText($("#mo").value).then(() => toast("Code copi\xE9", "ok")).catch(() => $("#mo").select());
      },
      sendans: async () => {
        try {
          await node.acceptAnswer($("#ma").value.trim());
          closeSheet();
          toast("Connexion\u2026", "info");
        } catch (e) {
          toast(e.message || "Code invalide", "error");
        }
      },
      tgl: (b) => {
        const k = b.dataset.k;
        if (k === "mic") node.setMic(!node.s.mic);
        else node.s[k] = !node.s[k];
        persist2();
        b.setAttribute("aria-checked", node.s[k]);
      },
      exp: async (b) => {
        const r = await get("recordings", b.dataset.id);
        download(await recordingBlob(r), `HXC_${r.camName}_${fmtFileStamp(new Date(r.t0))}.${extFor(r.mime)}`);
      },
      rm: async (b) => {
        if (!b.dataset.s) {
          b.dataset.s = 1;
          b.textContent = "?";
          return;
        }
        await del("recordings", b.dataset.id);
        await delChunks(b.dataset.id);
        openSettings();
      }
    };
    camEl.addEventListener("click", (e) => {
      const b = e.target.closest("[data-a]");
      if (b && A[b.dataset.a]) A[b.dataset.a](b);
    });
    $("#dim").addEventListener("pointerup", () => {
      const n = Date.now();
      if (n - lastTap < 450) wake();
      lastTap = n;
    });
    const sos = $("#sos"), fill = $("#sos-f");
    let sosT = null;
    const sosStart = (e) => {
      e.preventDefault();
      fill.style.transition = "height .8s linear";
      fill.style.height = "100%";
      sosT = setTimeout(() => {
        sosT = null;
        fill.style.transition = "none";
        fill.style.height = "0";
        node.sos();
      }, 800);
    };
    const sosCancel = () => {
      if (sosT) {
        clearTimeout(sosT);
        sosT = null;
      }
      fill.style.transition = "height .2s";
      fill.style.height = "0";
    };
    sos.addEventListener("pointerdown", sosStart);
    ["pointerup", "pointerleave", "pointercancel"].forEach((ev) => sos.addEventListener(ev, sosCancel));
    sos.addEventListener("contextmenu", (e) => e.preventDefault());
    return async () => {
      clearInterval(timer);
      clearInterval(alarm);
      scanStop?.();
      await node?.stop();
    };
  }

  // src/app.js
  var root = document.getElementById("root");
  var setHash = (h) => {
    try {
      history.replaceState(null, "", h ? "#" + h : location.pathname + location.search);
    } catch {
    }
  };
  var app = { offlineReady: false, unmount: null, hub: null, chooseRole, install: null };
  window.__hxc = app;
  async function unmount() {
    try {
      await app.unmount?.();
    } catch {
    }
    app.unmount = null;
    root.innerHTML = "";
  }
  async function chooseRole() {
    await unmount();
    if (app.hub) {
      await app.hub.stopLoopback?.();
      app.hub.links.forEach((l) => l.close());
      app.hub = null;
    }
    setHash("");
    root.innerHTML = `<div class="landing"><div class="inner">
    <div class="logo"><img src="img/logo-mark.png" alt="" width="64" height="60"><div class="wordmark"><span class="b1">HEXACORE</span><span class="b2">BODYCAM</span></div></div>
    <h1>Bodycam et poste de commandement pour milsim, polsim et RP airsoft. Liaison directe t\xE9l\xE9phone vers tablette, sans Wi-Fi public ni 4G/5G.</h1>
    <div class="roles">
      <button class="role" data-r="console"><div class="ic">${icon("tablet")}</div><div class="tag">Tablette \xB7 poste TAC</div><h2>CONSOLE</h2><p>Live view, commande \xE0 distance, enregistrements horodat\xE9s, archives, statut des liaisons et alertes urgence.</p></button>
      <button class="role" data-r="camera"><div class="ic">${icon("phone")}</div><div class="tag">T\xE9l\xE9phone \xB7 joueur</div><h2>CAM\xC9RA</h2><p>Transforme le t\xE9l\xE9phone en bodycam : flux en direct vers la tablette et enregistrement local de secours.</p></button>
    </div>
    <div class="meta"><span class="pill"><i class="d" id="off-d"></i><span id="off-t">Pr\xE9paration du mode hors ligne\u2026</span></span><span id="inst-w"></span><span>v${VERSION}</span></div>
    <details class="guide"><summary>Guide de terrain en 4 \xE9tapes</summary><ol>
      <li><b>Avant la partie, avec Internet :</b> ouvrez cette page une fois sur chaque appareil, puis \xAB Ajouter \xE0 l\u2019\xE9cran d\u2019accueil \xBB. L\u2019application est alors disponible hors ligne.</li>
      <li><b>Sur le terrain :</b> activez le point d\u2019acc\xE8s Wi-Fi de la tablette (sans Internet) ou allumez un petit routeur local, et connectez-y les t\xE9l\xE9phones.</li>
      <li><b>Association :</b> t\xE9l\xE9phone en r\xF4le Cam\xE9ra, \xAB Associer \xBB affiche un QR ; la tablette (Ajouter une cam\xE9ra) le scanne et affiche une r\xE9ponse que le t\xE9l\xE9phone scanne \xE0 son tour.</li>
      <li><b>Pilotage :</b> la tablette d\xE9marre et arr\xEAte l\u2019enregistrement, prend des photos, coupe le micro et pose des rep\xE8res. Chaque vid\xE9o est horodat\xE9e et copi\xE9e sur la tablette ; le t\xE9l\xE9phone garde l\u2019original.</li>
    </ol></details></div></div>`;
    root.querySelectorAll(".role").forEach((b) => b.addEventListener("click", () => setRole(b.dataset.r)));
    updateOffline();
    renderInstall();
  }
  async function setRole(r) {
    kv.set("role", r);
    setHash(r);
    await unmount();
    if (r === "console") {
      app.hub = app.hub || new ConsoleHub();
      app.unmount = mountConsole(root, app.hub, app);
    } else app.unmount = mountCamera(root, app);
  }
  function updateOffline() {
    const d = $("#off-d"), t = $("#off-t");
    if (!d) return;
    d.classList.toggle("on", app.offlineReady);
    t.textContent = app.offlineReady ? "Pr\xEAt hors ligne" : location.protocol === "file:" ? "Fichier local : hors ligne par nature (installation PWA indisponible)" : "serviceWorker" in navigator ? "Mode hors ligne en cours d\u2019installation\u2026" : "Mode hors ligne non pris en charge";
  }
  function renderInstall() {
    const w = $("#inst-w");
    if (!w) return;
    w.innerHTML = app.install ? `<button class="link-btn" id="inst">Installer l\u2019application</button>` : "";
    $("#inst")?.addEventListener("click", async () => {
      app.install.prompt();
      await app.install.userChoice;
      app.install = null;
      renderInstall();
    });
  }
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    app.install = e;
    renderInstall();
  });
  if ("serviceWorker" in navigator) {
    Promise.resolve().then(() => navigator.serviceWorker.register("sw.js")).then(() => navigator.serviceWorker.ready).then(() => {
      app.offlineReady = true;
      updateOffline();
    }).catch(() => {
    });
  }
  recoverOrphans().then((n) => {
    if (n) toast(`${n} enregistrement(s) interrompu(s) r\xE9cup\xE9r\xE9(s)`, "warn", 5e3);
  }).catch(() => {
  });
  isPersistent();
  var hash = location.hash.slice(1);
  if (hash === "console" || hash === "camera") setRole(hash);
  else chooseRole();
})();
