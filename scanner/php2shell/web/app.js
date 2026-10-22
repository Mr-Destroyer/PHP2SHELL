/* ==========================================================================
   php2shell — one punch
   The page is a thin renderer over the scanner's event stream. Nothing here
   guesses at progress: every pose change is triggered by a real event.

   Rig geometry must match index.html: the punch fist lands at (274, 116) in
   a 300x340 viewBox once the front arm is rotated -92 degrees.
   ========================================================================== */

(() => {
  'use strict';

  const TOKEN = new URLSearchParams(location.search).get('token') || '';
  const $ = (id) => document.getElementById(id);

  const app = $('app');
  const stage = $('stage');
  const hero = $('hero');
  const card = $('card');
  const cardUrl = $('cardUrl');
  const cardMeta = $('cardMeta');
  const cardStatus = $('cardStatus');
  const cardProbes = $('cardProbes');
  const cardStamp = $('cardStamp');
  const fragments = $('fragments');
  const fx = $('fx');
  const speedlines = $('speedlines');
  const bubble = $('bubble');
  const bubbleText = $('bubbleText');
  const afterimages = $('afterimages');
  const dust = $('dust');
  const logEl = $('log');
  const conn = $('conn');
  const connText = conn.querySelector('span');
  const form = $('scanForm');
  const input = $('urlInput');
  const scanBtn = $('scanBtn');
  const verdictPanel = $('verdictPanel');
  const vLabel = $('vLabel');
  const vConf = $('vConf');
  const vVersion = $('vVersion');
  const vSignal = $('vSignal');
  const vElapsed = $('vElapsed');
  const vSent = $('vSent');
  const vReason = $('vReason');
  const vCaveat = $('vCaveat');

  const VB_W = 300;
  const FIST_X = 274;
  const FIST_Y = 116;

  const REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const wait = (ms) => new Promise((r) => setTimeout(r, REDUCED ? Math.min(ms, 24) : ms));
  const rand = (a, b) => a + Math.random() * (b - a);
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

  /* ── sound: synthesized, no assets ─────────────────────────────────── */

  const Sfx = {
    ctx: null,
    enabled: true,
    _noise: null,

    ensure() {
      if (!this.enabled) return null;
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) { this.enabled = false; return null; }
      if (!this.ctx) this.ctx = new AC();
      if (this.ctx.state === 'suspended') this.ctx.resume();
      return this.ctx;
    },

    buffer(ctx) {
      if (this._noise && this._noise.sampleRate === ctx.sampleRate) return this._noise;
      const len = Math.floor(ctx.sampleRate * 1.2);
      const buf = ctx.createBuffer(1, len, ctx.sampleRate);
      const data = buf.getChannelData(0);
      for (let i = 0; i < len; i++) data[i] = Math.random() * 2 - 1;
      this._noise = buf;
      return buf;
    },

    whoosh() {
      const ctx = this.ensure(); if (!ctx) return;
      const t = ctx.currentTime;
      const src = ctx.createBufferSource();
      src.buffer = this.buffer(ctx);
      const bp = ctx.createBiquadFilter();
      bp.type = 'bandpass'; bp.Q.value = 1.1;
      bp.frequency.setValueAtTime(280, t);
      bp.frequency.exponentialRampToValueAtTime(3400, t + 0.26);
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.0001, t);
      g.gain.linearRampToValueAtTime(0.28, t + 0.045);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 0.34);
      src.connect(bp).connect(g).connect(ctx.destination);
      src.start(t); src.stop(t + 0.38);
    },

    boom() {
      const ctx = this.ensure(); if (!ctx) return;
      const t = ctx.currentTime;
      const o = ctx.createOscillator();
      o.type = 'sine';
      o.frequency.setValueAtTime(170, t);
      o.frequency.exponentialRampToValueAtTime(32, t + 0.42);
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.0001, t);
      g.gain.linearRampToValueAtTime(0.85, t + 0.012);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 0.66);
      o.connect(g).connect(ctx.destination);
      o.start(t); o.stop(t + 0.7);

      const src = ctx.createBufferSource();
      src.buffer = this.buffer(ctx);
      const lp = ctx.createBiquadFilter();
      lp.type = 'lowpass'; lp.frequency.value = 1500;
      const ng = ctx.createGain();
      ng.gain.setValueAtTime(0.5, t);
      ng.gain.exponentialRampToValueAtTime(0.0001, t + 0.16);
      src.connect(lp).connect(ng).connect(ctx.destination);
      src.start(t); src.stop(t + 0.2);
    },

    tink() {
      const ctx = this.ensure(); if (!ctx) return;
      const t = ctx.currentTime;
      [1568, 2349].forEach((f, i) => {
        const o = ctx.createOscillator();
        o.type = 'triangle';
        o.frequency.value = f;
        const g = ctx.createGain();
        g.gain.setValueAtTime(0.0001, t);
        g.gain.linearRampToValueAtTime(0.16 / (i + 1), t + 0.004);
        g.gain.exponentialRampToValueAtTime(0.0001, t + 0.16);
        o.connect(g).connect(ctx.destination);
        o.start(t); o.stop(t + 0.18);
      });
    },

    stamp() {
      const ctx = this.ensure(); if (!ctx) return;
      const t = ctx.currentTime;
      const src = ctx.createBufferSource();
      src.buffer = this.buffer(ctx);
      const bp = ctx.createBiquadFilter();
      bp.type = 'bandpass'; bp.frequency.value = 420; bp.Q.value = 0.8;
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.35, t);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 0.12);
      src.connect(bp).connect(g).connect(ctx.destination);
      src.start(t); src.stop(t + 0.14);
    },
  };

  /* ── stage control ─────────────────────────────────────────────────── */

  function setPhase(phase) {
    app.dataset.phase = phase;
  }

  function setConn(state, text) {
    conn.dataset.state = state;
    connText.textContent = text || state;
  }

  function say(text, tone) {
    if (!text) { bubble.classList.remove('show'); return; }
    bubbleText.textContent = text;
    bubble.dataset.tone = tone || 'paper';
    bubble.classList.add('show');
  }

  function logLine(html, cls) {
    const el = document.createElement('div');
    el.className = 'line' + (cls ? ' ' + cls : '');
    el.innerHTML = html;
    logEl.appendChild(el);
    while (logEl.children.length > 40) logEl.removeChild(logEl.firstChild);
    logEl.scrollTop = logEl.scrollHeight;
  }

  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));

  function fmtBytes(n) {
    if (!n) return '0 B';
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / 1048576).toFixed(1)} MiB`;
  }

  /* ── geometry ──────────────────────────────────────────────────────── */

  function measure(overlap) {
    const s = stage.getBoundingClientRect();
    const c = card.getBoundingClientRect();
    const h = hero.getBoundingClientRect();
    const scale = h.width / VB_W;
    const fistX = h.left + FIST_X * scale;
    const fistY = h.top + FIST_Y * scale;
    return {
      dash: Math.max(0, c.left + overlap - fistX),
      x: c.left + overlap - s.left,
      y: fistY - s.top,
    };
  }

  function applyGeometry(geo) {
    stage.style.setProperty('--dash-x', `${geo.dash}px`);
    stage.style.setProperty('--fx-x', `${geo.x}px`);
    stage.style.setProperty('--fx-y', `${geo.y}px`);
  }

  /* ── impact effects ────────────────────────────────────────────────── */

  function fireFx(soft) {
    fx.classList.remove('on', 'soft');
    void fx.offsetWidth; // restart the animations
    if (soft) fx.classList.add('soft');
    fx.classList.add('on');
    speedlines.classList.remove('on');
    void speedlines.offsetWidth;
    if (!soft) speedlines.classList.add('on');

    stage.classList.remove('on-shake');
    void stage.offsetWidth;
    if (!soft) stage.classList.add('on-shake');

    setTimeout(() => {
      fx.classList.remove('on', 'soft');
      speedlines.classList.remove('on');
      stage.classList.remove('on-shake');
    }, 1000);
  }

  function makeGhosts() {
    afterimages.innerHTML = '';
    for (let i = 0; i < 3; i++) {
      const clone = hero.cloneNode(true);
      clone.removeAttribute('id');
      clone.setAttribute('aria-hidden', 'true');
      clone.style.transform = `translateX(${-(i + 1) * 26}px)`;
      afterimages.appendChild(clone);
    }
    afterimages.classList.add('on');
    setTimeout(() => {
      afterimages.classList.remove('on');
      afterimages.innerHTML = '';
    }, 620);
  }

  /* ── shatter ───────────────────────────────────────────────────────── */

  function shatter() {
    const rect = card.getBoundingClientRect();
    const COLS = 4;
    const ROWS = 3;
    const xs = [0];
    const ys = [0];
    for (let i = 1; i < COLS; i++) xs.push(clamp((i * 100) / COLS + rand(-7, 7), 3, 97));
    for (let j = 1; j < ROWS; j++) ys.push(clamp((j * 100) / ROWS + rand(-6, 6), 3, 97));
    xs.push(100);
    ys.push(100);

    fragments.innerHTML = '';
    let n = 0;
    for (let r = 0; r < ROWS; r++) {
      for (let c = 0; c < COLS; c++) {
        const x0 = xs[c], x1 = xs[c + 1], y0 = ys[r], y1 = ys[r + 1];
        const piece = card.cloneNode(true);
        piece.removeAttribute('id');
        piece.querySelectorAll('[id]').forEach((el) => el.removeAttribute('id'));
        piece.classList.remove('wobble');
        piece.classList.add('frag');
        piece.style.clipPath =
          `polygon(${x0}% ${y0}%, ${x1}% ${y0}%, ${x1}% ${y1}%, ${x0}% ${y1}%)`;
        fragments.appendChild(piece);

        const cx = (x0 + x1) / 2;
        const cy = (y0 + y1) / 2;
