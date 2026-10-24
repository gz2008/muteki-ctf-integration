(() => {
  "use strict";

  const TOKEN = window.__STUDIO_TOKEN__ || "";
  const VERSION = window.__STUDIO_VERSION__ || "";
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  const state = {
    view: "compose",
    files: [],
    status: null,
    run: null,
    runStartedAt: 0,
    lastSeq: 0,
    events: [],
    pollTimer: null,
    tickTimer: null,
    solvedToastShown: false,
    mutekiPoll: null,
    busy: false,
    recipe: [],
    transformOutput: "",
    transformFlags: [],
  };

  const STATUS_LABEL = {
    created: "待派发",
    queued: "排队中",
    running: "运行中",
    done: "已完成",
    failed: "失败",
    cancelled: "已停止",
    interrupted: "已中断",
    timeout: "超时",
    skipped: "跳过",
  };

  function esc(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  async function api(path, options = {}) {
    const opts = {
      method: options.method || "GET",
      headers: { "X-Studio-Token": TOKEN, ...(options.headers || {}) },
      cache: "no-store",
    };
    if (options.body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(options.body);
    }
    const resp = await fetch(path, opts);
    let data = {};
    try {
      data = await resp.json();
    } catch {
      data = {};
    }
    if (!resp.ok) {
      throw new Error(data.error || data.detail || `${resp.status} ${resp.statusText}`);
    }
    return data;
  }

  const recentToasts = new Map();

  function toast(message, kind = "") {
    const key = `${kind}:${message}`;
    const now = Date.now();
    if (now - (recentToasts.get(key) || 0) < 8000) return;
    recentToasts.set(key, now);
    const stack = $("#toasts");
    while (stack.children.length >= 3) stack.firstElementChild.remove();
    const node = document.createElement("div");
    node.className = `toast ${kind}`;
    node.textContent = message;
    stack.appendChild(node);
    setTimeout(() => {
      node.style.opacity = "0";
      node.style.transform = "translateY(6px)";
      setTimeout(() => node.remove(), 220);
    }, 4600);
  }

  const MODE_HINTS = {
    local: "本地快解：附件分诊、字符串扫描、离线语料和状态分析，不发 LLM 请求，最快。",
    codex: "Codex 蜂群：多个 codex exec Worker 在隔离目录竞速；需要已登录的 Codex CLI。",
    muteki: "Muteki 蜂群：派发给本机 Muteki 服务；需要先在设置里启动服务。",
  };

  function renderModeHint() {
    const hint = $("#modeHint");
    if (hint) hint.textContent = MODE_HINTS[$("#mode").value] || "";
  }

  function openGuide() {
    $("#guideBackdrop").classList.remove("hidden");
    document.body.classList.add("modal-open");
    $("#guideClose").focus();
  }

  function closeGuide() {
    $("#guideBackdrop").classList.add("hidden");
    document.body.classList.remove("modal-open");
    localStorage.setItem("ctf-studio-guide-seen", "1");
    $("#firstRunCard").classList.add("hidden");
  }

  function fmtTime(seconds) {
    seconds = Math.max(0, Math.floor(seconds || 0));
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return h ? `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`
             : `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }

  function fmtBytes(n) {
    n = Number(n || 0);
    if (n < 1024) return `${n} B`;
    if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
    return `${(n / 1024 ** 3).toFixed(2)} GB`;
  }

  function setView(name) {
    state.view = name;
    $$(".view").forEach((node) => node.classList.add("hidden"));
    const view = $(`#view-${name}`);
    if (view) view.classList.remove("hidden");
    $$(".rail-btn[data-view]").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.view === name);
    });
    const titles = {
      compose: "新建解题",
      run: "运行",
      history: "运行记录",
      corpus: "语料检索",
      tools: "变换台",
      settings: "设置与诊断",
    };
    $("#crumbCurrent").textContent = titles[name] || name;
    if (name === "history") loadHistory();
    if (name === "settings") renderSettings();
    if (name === "tools") {
      renderTransformOps();
      renderTransform();
    }
  }

  // ---- status -------------------------------------------------------------

  async function loadStatus(force = false) {
    try {
      const data = await api(`/api/status${force ? "?force=1" : ""}`);
      state.status = data;
      renderStatus();
    } catch (err) {
      toast(`状态检测失败：${err.message}`, "error");
    }
  }

  function chip(label, ok, detail = "") {
    const cls = ok === true ? "ok" : ok === false ? "bad" : "warn";
    return `<span class="chip ${cls}" title="${esc(detail)}"><span class="dot"></span>${esc(label)}</span>`;
  }

  function renderStatus() {
    const s = state.status;
    if (!s) return;
    $("#statusChips").innerHTML = [
      chip("语料", s.corpus_ready, s.corpus_ready ? "九套语料已就绪" : "语料目录为空，先运行 fetch-knowledge"),
      chip("Kali", s.wsl?.ok, s.wsl?.ok ? `${s.wsl.distro} 可执行` : "WSL 不可用"),
      chip("Codex", s.codex?.ok, s.codex?.path || "未找到 codex CLI"),
    ].join("");
    $("#mutekiDot").className = `dot ${s.muteki?.online ? "ok" : "bad"}`;
    renderCapabilities();
    if (state.view === "settings") renderSettings();
  }

  function renderCapabilities() {
    const s = state.status;
    if (!s) return;
    const corpusCount = Object.values(s.corpus || {}).filter(Boolean).length;
    const toolCount = Object.values(s.tools || {}).filter(Boolean).length;
    const cards = [
      {
        title: "离线语料",
        ok: s.corpus_ready,
        detail: `${corpusCount}/4 目录 · BM25 + ripgrep`,
        icon: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2Z"/>',
      },
      {
        title: "工具链",
        ok: toolCount === Object.keys(s.tools || {}).length,
        detail: `${toolCount}/${Object.keys(s.tools || {}).length} 入口 · stdlib 分析器`,
        icon: '<path d="m14.7 6.3 3-3a3 3 0 0 1 4.2 4.2l-3 3"/><path d="m9.3 17.7-3 3a3 3 0 0 1-4.2-4.2l3-3"/><path d="m6 18 12-12"/>',
      },
      {
        title: "ctf-kali",
        ok: s.wsl?.ok,
        detail: s.wsl?.ok ? `${s.wsl.distro} · pwntools/gdb/z3` : "WSL / ctf-kali 不可用",
        icon: '<rect x="2" y="4" width="20" height="14" rx="2"/><path d="M8 21h8M12 18v3"/>',
      },
      {
        title: "多 Agent",
        ok: s.muteki?.online || s.codex?.ok,
        detail: s.muteki?.online ? "Muteki 服务在线" : s.codex?.ok ? "Codex CLI 可用" : "无可用 Worker 引擎",
        icon: '<circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M8.2 7.2 10.8 16M15.8 7.2 13.2 16M8.5 6h7"/>',
      },
    ];
    $("#capabilityGrid").innerHTML = cards.map((card) => `
      <div class="cap-card" data-go-settings="1">
        <div class="cap-top">
          <strong>${esc(card.title)}</strong>
          <span class="cap-icon" style="background:${card.ok ? "var(--green-soft)" : "var(--red-soft)"};color:${card.ok ? "var(--green)" : "var(--red)"}">
            <svg viewBox="0 0 24 24">${card.icon}</svg>
          </span>
        </div>
        <small title="${esc(card.detail)}">${esc(card.detail)}</small>
      </div>
    `).join("");
    $$("[data-go-settings]").forEach((node) => {
      node.addEventListener("click", () => setView("settings"));
    });
  }

  // ---- compose ------------------------------------------------------------

  function renderFiles() {
    $("#fileChips").innerHTML = state.files.map((file, index) => `
      <span class="file-chip" title="${esc(file.name)} · ${fmtBytes(file.size)}">
        <span>${esc(file.name)}</span>
        <button type="button" data-remove-file="${index}" aria-label="移除">×</button>
      </span>
    `).join("");
    $$("[data-remove-file]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.files.splice(Number(btn.dataset.removeFile), 1);
        renderFiles();
      });
    });
  }

  function addFiles(files) {
    for (const file of files) {
      if (!state.files.some((f) => f.name === file.name && f.size === file.size)) {
        state.files.push(file);
      }
    }
    renderFiles();
  }

  async function dispatch() {
    if (state.busy) return;
    const description = $("#description").value.trim();
    const url = $("#challengeUrl").value.trim();
    const mode = $("#mode").value;
    if (!description && !url && state.files.length === 0) {
      toast("先写题面、给一个 URL，或添加附件。", "error");
      $("#description").focus();
      return;
    }
    if (mode === "muteki" && state.status && !state.status.muteki?.online) {
      toast("Muteki 服务未运行。先到设置里启动，或改用 Codex 蜂群。", "error");
      setView("settings");
      return;
    }
    if (mode === "codex" && state.status && !state.status.codex?.ok) {
      toast("找不到 Codex CLI；请先登录 Codex 或改用本地快解。", "error");
      return;
    }

    state.busy = true;
    $("#dispatchButton").disabled = true;
    const title = description.split("\n").find((line) => line.trim()) || state.files[0]?.name || url || "CTF run";
    const payload = {
      title: title.trim().slice(0, 120),
      description,
      url,
      category: $("#category").value,
      flag_format: $("#flagFormat").value.trim() || "flag{...}",
      mode,
      workers: Number($("#workers").value || 2),
      race_seconds: Number($("#raceSeconds").value || 300),
      total_seconds: Number($("#totalSeconds").value || 0),
      cost_budget_usd: Number($("#costBudget").value || 0),
      allow_input: $("#allowInput").checked,
      web_tools: $("#webTools").checked,
      offline: $("#offline").checked,
      container: $("#container").checked,
      multi_flag: $("#multiFlag").checked,
    };
    try {
      const created = await api("/api/runs", { method: "POST", body: payload });
      let run = created.run;
      for (const file of state.files) {
        const resp = await fetch(`/api/runs/${encodeURIComponent(run.id)}/files?name=${encodeURIComponent(file.name)}`, {
          method: "PUT",
          headers: { "X-Studio-Token": TOKEN },
          body: file,
        });
        if (!resp.ok) {
          let detail = "";
          try { detail = (await resp.json()).error || ""; } catch {}
          throw new Error(`上传 ${file.name} 失败：${detail || resp.status}`);
        }
      }
      const dispatched = await api(`/api/runs/${encodeURIComponent(run.id)}/dispatch`, {
        method: "POST",
        body: payload,
      });
      state.run = dispatched.run;
      state.runStartedAt = Date.now();
      state.lastSeq = 0;
      state.events = [];
      state.solvedToastShown = false;
      state.files = [];
      renderFiles();
      setView("run");
      renderRun();
      startPolling();
      if (mode === "codex") toast("Codex 蜂群已派发；Worker 会在各自目录中竞速。", "success");
      else if (mode === "muteki") toast("Muteki 蜂群已派发；事件流正在镜像。", "success");
      else toast("本地快解已派发。", "success");
    } catch (err) {
      toast(err.message, "error");
    } finally {
      state.busy = false;
      $("#dispatchButton").disabled = false;
    }
  }

  // ---- run polling and rendering -----------------------------------------

  function stopPolling() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    if (state.tickTimer) clearInterval(state.tickTimer);
    state.pollTimer = null;
    state.tickTimer = null;
  }

  function startPolling() {
    stopPolling();
    pollRun();
    state.pollTimer = setInterval(pollRun, 1000);
    state.tickTimer = setInterval(renderTimer, 500);
  }

  async function pollRun() {
    if (!state.run) return;
    try {
      const data = await api(`/api/runs/${encodeURIComponent(state.run.id)}?after=${state.lastSeq}`);
      const incoming = data.events || [];
      for (const event of incoming) {
        if (event.seq > state.lastSeq) state.lastSeq = event.seq;
        state.events.push(event);
      }
      if (state.events.length > 2500) state.events = state.events.slice(-2500);
      // Preserve the events already accumulated on the client; the server only
      // sends the tail after `lastSeq`.
      data.events = state.events;
      state.run = data;
      renderRun();
      if (!["running", "queued", "created"].includes(data.status)) {
        renderTimer();
        stopPolling();
        if (data.solved && !state.solvedToastShown) {
          state.solvedToastShown = true;
          toast(`拿到 flag：${data.flags.find((f) => f.status === "verified")?.value || ""}`, "success");
        }
      }
    } catch (err) {
      if (!String(err.message).includes("unknown run")) {
        // Keep polling; transient failures are common while the server is busy.
      }
    }
  }

  function renderTimer() {
    if (!state.run) return;
    if (state.run.status === "running" && state.runStartedAt) {
      $("#runTimer").textContent = fmtTime((Date.now() - state.runStartedAt) / 1000);
    } else {
      $("#runTimer").textContent = fmtTime(state.run.elapsed || 0);
    }
  }

  function laneOrder(lanes) {
    const order = { coordinator: 0, inventory: 1, strings: 2, knowledge: 3, binary: 4, web: 5, brief: 6, console: 7 };
    return Object.values(lanes || {}).sort((a, b) => {
      const oa = order[a.id] ?? (a.id.startsWith("w") ? 10 : 20);
      const ob = order[b.id] ?? (b.id.startsWith("w") ? 10 : 20);
      return oa - ob || String(a.id).localeCompare(String(b.id));
    });
  }

  function renderRun() {
    const run = state.run;
    if (!run) return;
    $("#runMode").textContent = run.mode;
    $("#runCategory").textContent = run.category || "auto";
    const status = run.status || "created";
    const statusNode = $("#runStatus");
    statusNode.textContent = STATUS_LABEL[status] || status;
    statusNode.className = `badge status-badge ${status}`;
    $("#runTitle").textContent = run.title || run.id;
    $("#runSub").textContent = (run.description || "").slice(0, 260) || run.url || "没有题面描述";
    $("#stopRun").style.display = ["running", "queued", "created"].includes(status) ? "" : "none";
    renderTimer();

    const lanes = laneOrder(run.lanes);
    $("#laneCount").textContent = `${lanes.length} lanes`;
    $("#lanes").innerHTML = lanes.length ? lanes.map((lane) => {
      const usage = lane.usage || {};
      const usageText = usage.output_tokens ? `out ${usage.output_tokens}` : (lane.events ? `${lane.events} ev` : "");
      const elapsed = lane.elapsed ? `${lane.elapsed}s` : "";
      return `
        <div class="lane ${esc(lane.status || "queued")}">
          <span class="lane-dot"></span>
          <div>
            <div class="lane-name">${esc(lane.name || lane.id)}</div>
            <div class="lane-role">${esc(lane.role || "")}</div>
            <div class="lane-last">${esc(lane.last || "等待输出…")}</div>
          </div>
          <div class="lane-meta">
            <span class="lane-state">${esc(STATUS_LABEL[lane.status] || lane.status || "queued")}</span>
            <div style="margin-top:5px">${esc(elapsed)} ${esc(usageText)}</div>
          </div>
        </div>
      `;
    }).join("") : '<div class="empty">派发后通道会出现在这里。</div>';

    const facts = (run.facts || []).slice(-90).reverse();
    $("#factCount").textContent = `${(run.facts || []).length} facts`;
    $("#facts").innerHTML = facts.length ? facts.map((fact) => `
      <div class="fact ${fact.verified ? "verified" : "unverified"}">
        <div class="fact-top">
          <span class="fact-lane">${esc(fact.lane)}</span>
          <span class="fact-src" title="${esc(fact.source || "")}">${esc(fact.source || "")}</span>
        </div>
        <div class="fact-text">${esc(fact.text)}</div>
      </div>
    `).join("") : '<div class="empty">还没有共享事实。先派发或运行分诊。</div>';

    const flags = run.flags || [];
    $("#flagCount").textContent = `${flags.length} flags`;
    $("#flags").innerHTML = flags.length ? flags.map((flag) => `
      <div class="flag-card ${esc(flag.status)}">
        <span class="flag-value">${esc(flag.value)}</span>
        <span class="flag-status">${flag.status === "verified" ? "已验证" : flag.status === "claimed" ? "待复核" : flag.status === "rejected" ? "已驳回" : "候选"}</span>
        ${flag.status !== "verified" && flag.status !== "rejected" ? `
          <button class="mini-btn" data-review="confirm" data-flag="${esc(flag.value)}">确认</button>
          <button class="mini-btn reject" data-review="reject" data-flag="${esc(flag.value)}">驳回</button>
        ` : ""}
        <button class="copy-btn" data-copy="${esc(flag.value)}" title="复制">
          <svg viewBox="0 0 24 24" style="width:15px;height:15px"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
        </button>
      </div>
    `).join("") : '<div class="empty">没有 flag。候选会标注为“候选”，不会冒充已验证。</div>';

    const actions = run.actions || [];
    $("#actionCount").textContent = `${actions.length} actions`;
    $("#actions").innerHTML = actions.length ? actions.map((action) => `
      <div class="action">
        <div class="action-top">
          <span class="action-title">${esc(action.title)}</span>
        </div>
        <div class="action-why">${esc(action.why || "")}</div>
        <div class="action-cmd">
          <code>${esc(action.command)}</code>
          <button class="mini-btn" data-copy="${esc(action.command)}">复制</button>
          <span class="action-shell">${action.shell === "windows" ? "WIN" : "KALI"}</span>
          <button class="mini-btn" data-run-cmd="${esc(action.command)}" data-run-shell="${esc(action.shell || "wsl")}">执行</button>
        </div>
      </div>
    `).join("") : '<div class="empty">协调器还没有给出下一手。</div>';

    const consoleEvents = state.events.filter((event) => event.lane === "console" && ["tool", "output", "error"].includes(event.kind));
    const terminalLines = consoleEvents.slice(-120).map((event) => {
      if (event.kind === "tool") return event.text;
      if (event.kind === "error") return `[error] ${event.text}`;
      return event.text;
    });
    $("#terminal").textContent = terminalLines.length ? terminalLines.join("\n\n") : "等待命令…";
    $("#terminal").scrollTop = $("#terminal").scrollHeight;

    $("#eventCount").textContent = `· ${state.events.length}`;
    const tail = state.events.slice(-160).map((event) => {
      const time = new Date((event.ts || 0) * 1000).toLocaleTimeString();
      return `${time} [${event.lane}/${event.kind}] ${event.text}`;
    }).join("\n");
    $("#events").textContent = tail || "还没有事件。";

    $$("[data-copy]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(btn.dataset.copy);
          toast("已复制", "success");
        } catch {
          toast("复制失败；请手动选择文本。", "error");
        }
      });
    });
    $$("[data-run-cmd]").forEach((btn) => {
      btn.addEventListener("click", () => {
        $("#commandInput").value = btn.dataset.runCmd;
        $("#consoleShell").value = btn.dataset.runShell || "wsl";
        $("#commandInput").focus();
      });
    });
    $$("[data-review]").forEach((btn) => {
      btn.addEventListener("click", () => reviewFlag(btn.dataset.flag, btn.dataset.review));
    });
  }

  async function reviewFlag(value, review) {
    if (!state.run) return;
    try {
      await api(`/api/runs/${encodeURIComponent(state.run.id)}/flag`, {
        method: "POST",
        body: { value, review },
      });
      toast(review === "confirm" ? "已确认并记入台账。" : "已驳回该候选。", "success");
      await pollRun();
    } catch (err) {
      toast(err.message, "error");
    }
  }

  // ---- transform workbench ------------------------------------------------

  function bytesToText(bytes) {
    try {
      return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(bytes));
    } catch {
      return String.fromCharCode(...bytes);
    }
  }

  function textToBytes(text) {
    return Array.from(new TextEncoder().encode(text));
  }

  function b64d(value) {
    let s = String(value).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    return bytesToText(Array.from(bin, (c) => c.charCodeAt(0)));
  }

  function b64e(value) {
    const bytes = textToBytes(String(value));
    let bin = "";
    for (const byte of bytes) bin += String.fromCharCode(byte);
    return btoa(bin);
  }

  function b32d(value) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let s = String(value).replace(/\s+/g, "").replace(/=+$/, "").toUpperCase();
    let bits = "";
    for (const ch of s) {
      const idx = alphabet.indexOf(ch);
      if (idx < 0) throw new Error(`Base32 字符非法: ${ch}`);
      bits += idx.toString(2).padStart(5, "0");
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return bytesToText(bytes);
  }

  function hexd(value) {
    const s = String(value).replace(/0x/gi, "").replace(/[^0-9a-f]/gi, "");
    if (!s.length || s.length % 2) throw new Error("Hex 长度不是偶数");
    return bytesToText(s.match(/../g).map((x) => parseInt(x, 16)));
  }

  function hexe(value) {
    return textToBytes(String(value)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  function urlD(value) {
    return decodeURIComponent(String(value).replace(/\+/g, " "));
  }

  function rot13(value) {
    return String(value).replace(/[a-z]/gi, (ch) => {
      const base = ch <= "Z" ? 65 : 97;
      return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
    });
  }

  function atbash(value) {
    return String(value).replace(/[a-z]/gi, (ch) => {
      const base = ch <= "Z" ? 65 : 97;
      return String.fromCharCode(base + (25 - (ch.charCodeAt(0) - base)));
    });
  }

  function caesarAll(value) {
    const lines = [];
    for (let shift = 1; shift < 26; shift++) {
      const out = String(value).replace(/[a-z]/gi, (ch) => {
        const base = ch <= "Z" ? 65 : 97;
        return String.fromCharCode(((ch.charCodeAt(0) - base + shift + 26) % 26) + base);
      });
      lines.push(`shift ${String(shift).padStart(2, " ")}: ${out}`);
    }
    return lines.join("\n");
  }

  const MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-..-.": "/", "-....-": "-", ".----.": "'", "-.--.": "(", "-.--.-": ")",
  };

  function morseD(value) {
    return String(value).trim().split(/\s+/).map((token) => {
      if (token === "/" || token === "|") return " ";
      return MORSE[token] ?? `[${token}]`;
    }).join("");
  }

  function binaryD(value) {
    const groups = String(value).replace(/[^01]/g, "").match(/.{8}/g) || [];
    return bytesToText(groups.map((g) => parseInt(g, 2)));
  }

  function decimalD(value) {
    const nums = String(value).match(/\d{2,3}/g) || [];
    return bytesToText(nums.map((n) => Number(n) & 0xff));
  }

  function entityD(value) {
    const area = document.createElement("textarea");
    area.innerHTML = String(value);
    return area.value;
  }

  function jwtD(value) {
    const parts = String(value).trim().split(".");
    if (parts.length < 2) throw new Error("不是 JWT（需要 header.payload.signature）");
    const decodePart = (part) => JSON.stringify(JSON.parse(b64d(part.replace(/-/g, "+").replace(/_/g, "/"))), null, 2);
    return `header:\n${decodePart(parts[0])}\n\npayload:\n${decodePart(parts[1])}`;
  }

  function brainfuckD(value) {
    const code = String(value).replace(/[^+\-<>.,[\]]/g, "");
    const cells = new Uint8Array(30000);
    let ptr = 0;
    let pc = 0;
    let out = "";
    let steps = 0;
    const stack = [];
    const jumps = {};
    for (let i = 0; i < code.length; i++) {
      if (code[i] === "[") stack.push(i);
      else if (code[i] === "]") {
        const start = stack.pop();
        if (start === undefined) throw new Error("Brainfuck 括号不匹配");
        jumps[start] = i;
        jumps[i] = start;
      }
    }
    while (pc < code.length && steps++ < 500000) {
      const op = code[pc];
      if (op === "+") cells[ptr] = (cells[ptr] + 1) & 0xff;
      else if (op === "-") cells[ptr] = (cells[ptr] - 1) & 0xff;
      else if (op === ">") ptr = (ptr + 1) % cells.length;
      else if (op === "<") ptr = (ptr - 1 + cells.length) % cells.length;
      else if (op === ".") out += String.fromCharCode(cells[ptr]);
      else if (op === "[") { if (!cells[ptr]) pc = jumps[pc]; }
      else if (op === "]") { if (cells[ptr]) pc = jumps[pc]; }
      pc++;
    }
    if (steps >= 500000) out += "\n[达到 500000 步上限]";
    return out;
  }

  function xorBrute(value) {
    const input = textToBytes(String(value));
    const results = [];
    for (let key = 0; key < 256; key++) {
      const bytes = input.map((b) => b ^ key);
      const text = bytesToText(bytes);
      const printable = [...text].filter((ch) => ch >= " " && ch <= "~" || "\n\r\t".includes(ch)).length / Math.max(1, text.length);
      let score = printable * 10;
      if (/(flag|ctf|key)\{/i.test(text)) score += 30;
      if (/[a-zA-Z]{4,}/.test(text)) score += 2;
      results.push({ key, text, score });
    }
    results.sort((a, b) => b.score - a.score);
    return results.slice(0, 8).map((r) => `key=0x${r.key.toString(16).padStart(2, "0")} score=${r.score.toFixed(1)}\n${r.text}`).join("\n\n");
  }

  function hashId(value) {
    const s = String(value).trim();
    const map = {
      32: ["MD5", "NTLM", "MD4"],
      40: ["SHA-1", "MySQL5"],
      56: ["SHA-224"],
      64: ["SHA-256", "SHA3-256", "BLAKE2s"],
      96: ["SHA-384", "SHA3-384"],
      128: ["SHA-512", "SHA3-512", "BLAKE2b"],
    };
    if (!/^[0-9a-f]+$/i.test(s)) throw new Error("不是纯 hex 哈希");
    return `${s.length} hex chars\n可能：${(map[s.length] || ["未知长度"]).join(" / ")}`;
  }

  function flagCandidates(value) {
    const re = /\b(?:flag|ctf|key|picoctf|htb|ductf|irisctf|corctf|sekai|uiuctf|n1ctf|hgame|moectf|nssctf)\{[^}\r\n]{1,240}\}/gi;
    return [...String(value).matchAll(re)].map((m) => m[0]).filter((v) => !v.includes("..."));
  }

  function hasCleanFlag(value) {
    for (const flag of flagCandidates(value)) {
      const index = value.indexOf(flag);
      const before = index > 0 ? value[index - 1] : "";
      const after = value[index + flag.length] || "";
      if (!"[]()<>".includes(before) && !"[]()<>".includes(after)) return true;
    }
    return false;
  }

  const TRANSFORM_OPS = [
    ["编码", "b64d", "Base64 解码", b64d],
    ["编码", "b64e", "Base64 编码", b64e],
    ["编码", "b32d", "Base32 解码", b32d],
    ["编码", "hexd", "Hex 解码", hexd],
    ["编码", "hexe", "Hex 编码", hexe],
    ["编码", "urld", "URL 解码", urlD],
    ["编码", "urle", "URL 编码", encodeURIComponent],
    ["编码", "binary", "二进制解码", binaryD],
    ["编码", "decimal", "十进制解码", decimalD],
    ["编码", "morse", "Morse 解码", morseD],
    ["编码", "entity", "HTML Entity 解码", entityD],
    ["古典", "rot13", "ROT13", rot13],
    ["古典", "atbash", "Atbash", atbash],
    ["古典", "caesar", "Caesar 全偏移", caesarAll],
    ["古典", "reverse", "反转文本", (s) => [...String(s)].reverse().join("")],
    ["分析", "xor", "单字节 XOR 暴力", xorBrute],
    ["分析", "hash", "哈希识别", hashId],
    ["分析", "jwt", "JWT 解码", jwtD],
    ["分析", "brainfuck", "Brainfuck 解释", brainfuckD],
    ["分析", "flags", "提取 Flag", (s) => flagCandidates(s).join("\n") || "没有发现 flag 形态"],
  ];
  const OP_MAP = Object.fromEntries(TRANSFORM_OPS.map(([cat, id, name, fn]) => [id, { cat, id, name, fn }]));

  function scoreText(text) {
    if (!text) return -100;
    const printable = [...text].filter((ch) => ch >= " " && ch <= "~" || "\n\r\t".includes(ch) || ch.charCodeAt(0) > 127).length / text.length;
    let score = printable * 8;
    if (/(flag|ctf|key)\{/i.test(text)) score += 40;
    if (/[a-zA-Z]{4,}/.test(text)) score += 4;
    if (/\b(the|and|this|that|with|flag|secret|password)\b/i.test(text)) score += 3;
    score -= Math.min(8, text.length / 2000);
    return score;
  }

  function magicTransform(value) {
    const direct = [];
    for (const [cat, id, name, fn] of TRANSFORM_OPS) {
      if (["b64e", "hexe", "urle", "caesar", "xor", "hash", "flags", "morse", "binary", "decimal", "brainfuck"].includes(id)) continue;
      try {
        const out = fn(value);
        if (out && out !== value) direct.push({ label: name, text: out, score: scoreText(out) });
      } catch {}
    }
    const results = [...direct];
    for (const first of direct.slice(0, 8)) {
      for (const [cat, id, name, fn] of TRANSFORM_OPS) {
        if (["b64e", "hexe", "urle", "caesar", "xor", "hash", "flags", "brainfuck"].includes(id)) continue;
        try {
          const out = fn(first.text);
          if (out && out !== first.text) results.push({ label: `${first.label} → ${name}`, text: out, score: scoreText(out) });
        } catch {}
      }
    }
    const seen = new Set();
    const scored = results
      .filter((r) => {
        const key = r.text.slice(0, 80);
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      })
      .sort((a, b) => b.score - a.score);
    const hasFlag = scored.some((r) => hasCleanFlag(r.text));
    const useful = hasFlag
      ? scored.filter((r) => hasCleanFlag(r.text) || (r.score >= 18 && !/\[[^\]]*flag\{/i.test(r.text)))
      : scored;
    return useful.slice(0, 6);
  }

  function renderTransformOps() {
    const host = $("#transformOps");
    const groups = {};
    for (const [cat, id, name] of TRANSFORM_OPS) {
      (groups[cat] ||= []).push([id, name]);
    }
    host.innerHTML = Object.entries(groups).map(([cat, ops]) => `
      <div class="op-group">
        <h4>${esc(cat)}</h4>
        ${ops.map(([id, name]) => `<button class="op-btn" data-op="${id}">${esc(name)}</button>`).join("")}
      </div>
    `).join("");
    $$("#transformOps [data-op]").forEach((btn) => {
      btn.addEventListener("click", () => addTransformOp(btn.dataset.op));
    });
  }

  function currentTransformInput() {
    return $("#transformInput").value;
  }

  function runRecipe() {
    let value = currentTransformInput();
    for (const item of state.recipe) {
      const op = OP_MAP[item.id];
      if (!op) continue;
      try {
        value = op.fn(value);
      } catch (err) {
        value = `[${op.name} 失败] ${err.message}\n\n${value}`;
        break;
      }
    }
    state.transformOutput = value;
    state.transformFlags = flagCandidates(value);
    renderTransform();
  }

  function addTransformOp(id) {
    if (!state.recipe.length && state.transformOutput && state.transformOutput !== currentTransformInput()) {
      // Continue from the magic output only if the operator chose it explicitly.
    }
    state.recipe.push({ id });
    runRecipe();
  }

  function renderTransform() {
    const input = currentTransformInput();
    const output = state.transformOutput || input;
    $("#inputMeta").textContent = `${input.length} chars`;
    $("#transformOutput").textContent = output || "等待输入…";
    $("#recipeChips").innerHTML = state.recipe.length
      ? state.recipe.map((item, index) => `<span class="recipe-chip">${esc(OP_MAP[item.id]?.name || item.id)}<button data-remove-op="${index}">×</button></span>`).join("")
      : '<span class="muted">raw</span>';
    $$("#recipeChips [data-remove-op]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.recipe.splice(Number(btn.dataset.removeOp), 1);
        runRecipe();
      });
    });
    const badge = $("#transformFlagBadge");
    if (state.transformFlags.length) {
      badge.textContent = state.transformFlags[0];
      badge.classList.remove("hidden");
    } else {
      badge.classList.add("hidden");
    }
  }

  async function saveTransformFlag() {
    const value = state.transformFlags[0];
    if (!value) {
      toast("输出里没有 flag 形态。", "error");
      return;
    }
    if (!state.run) {
      await navigator.clipboard.writeText(value).catch(() => {});
      toast("当前没有打开的运行；已复制 flag。", "error");
      return;
    }
    await reviewFlag(value, "confirm");
  }

  // ---- history ------------------------------------------------------------

  async function loadHistory() {
    try {
      const data = await api("/api/runs");
      const runs = data.runs || [];
      $("#historyList").innerHTML = runs.length ? runs.map((run) => `
        <div class="history-item" data-open-run="${esc(run.id)}">
          <div>
            <div class="history-title">${esc(run.title || run.id)}</div>
            <div class="history-sub">${esc(run.id)} · ${esc(run.created_at || "")}</div>
          </div>
          <div class="history-stats">
            <span>${esc(run.mode)}</span>
            <span>${run.facts} facts</span>
            <span>${run.flags} flags</span>
          </div>
          <span class="badge ${run.solved ? "soft" : ""}">${esc(STATUS_LABEL[run.status] || run.status)}</span>
        </div>
      `).join("") : '<div class="empty">还没有运行记录。</div>';
      $$("[data-open-run]").forEach((node) => {
        node.addEventListener("click", () => openRun(node.dataset.openRun));
      });
    } catch (err) {
      toast(`读取运行记录失败：${err.message}`, "error");
    }
  }

  async function openRun(id) {
    try {
      const data = await api(`/api/runs/${encodeURIComponent(id)}?after=0`);
      state.run = data;
      state.runStartedAt = Date.now() - (Number(data.elapsed || 0) * 1000);
      state.lastSeq = Math.max(0, ...(data.events || []).map((e) => e.seq || 0));
      state.events = data.events || [];
      state.solvedToastShown = Boolean(data.solved);
      setView("run");
      renderRun();
      if (["running", "queued"].includes(data.status)) startPolling();
      else stopPolling();
    } catch (err) {
      toast(`打开运行失败：${err.message}`, "error");
    }
  }

  // ---- corpus -------------------------------------------------------------

  async function search() {
    const query = $("#searchQuery").value.trim();
    if (!query) return;
    $("#searchResults").innerHTML = '<div class="empty">检索中…</div>';
    try {
      const data = await api("/api/search", {
        method: "POST",
        body: {
          query,
          mode: $("#searchMode").value,
          category: $("#searchCategory").value,
          n: 8,
        },
      });
      const items = data.items || [];
      if (!items.length) {
        $("#searchResults").innerHTML = `<div class="empty">没有命中。原始输出：<pre style="text-align:left;white-space:pre-wrap">${esc((data.raw || "").slice(0, 4000))}</pre></div>`;
        return;
      }
      $("#searchResults").innerHTML = items.map((item) => `
        <div class="search-item">
          <div class="si-top">
            <span class="badge soft">${esc(item.source || "corpus")}</span>
            ${item.score ? `<span class="score">[${item.score}]</span>` : ""}
            ${item.line ? `<span>line ${item.line}</span>` : ""}
            <button class="mini-btn" data-copy="${esc(item.path || "")}">复制路径</button>
          </div>
          <div class="si-path">${esc(item.path || "")}</div>
          <div class="si-text">${esc(item.snippet || item.text || "")}</div>
        </div>
      `).join("");
      $$("#searchResults [data-copy]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          await navigator.clipboard.writeText(btn.dataset.copy);
          toast("路径已复制", "success");
        });
      });
    } catch (err) {
      $("#searchResults").innerHTML = `<div class="empty">检索失败：${esc(err.message)}</div>`;
    }
  }

  // ---- settings -----------------------------------------------------------

  function renderSettings() {
    const s = state.status;
    if (!s) {
      $("#diagList").innerHTML = '<div class="empty">检测中…</div>';
      return;
    }
    const diags = [
      ["离线语料", s.corpus_ready, Object.entries(s.corpus || {}).map(([k, v]) => `${k}:${v ? "ok" : "empty"}`).join("  ")],
      ["分析器", Object.values(s.tools || {}).every(Boolean), `${Object.values(s.tools || {}).filter(Boolean).length}/${Object.keys(s.tools || {}).length} entries`],
      ["ctf-kali", s.wsl?.ok, `${s.wsl?.distro || "?"} / ${s.wsl?.user || "?"}`],
      ["Codex CLI", s.codex?.ok, s.codex?.path || "not found"],
      ["Muteki API", s.muteki?.online, s.muteki?.online ? "http://127.0.0.1:8000" : (s.muteki?.error || "offline")],
      ["运行目录", true, s.runs_dir],
    ];
    $("#diagList").innerHTML = diags.map(([name, ok, detail]) => `
      <div class="diag">
        <span class="dot ${ok ? "ok" : "bad"}"></span>
        <span class="diag-name">${esc(name)}</span>
        <span class="diag-detail">${esc(detail)}</span>
      </div>
    `).join("");
    const m = s.muteki || {};
    $("#mutekiPanel").innerHTML = m.online
      ? `<p><span class="dot ok" style="display:inline-block;margin-right:7px"></span>服务在线。UI：<a href="${esc(m.ui)}" target="_blank" rel="noreferrer">${esc(m.ui)}</a></p>
         <p>GUI 可以把当前题目直接派发给 Muteki 的异构 Worker，并镜像 SSE 事件流。</p>`
      : `<p><span class="dot bad" style="display:inline-block;margin-right:7px"></span>服务未运行。</p>
         <p>${esc(m.error || "需要先在 ctf-kali 中启动 Muteki，并配置至少一个已登录的 agent CLI 与 Planner 端点。")}</p>`;
    $("#pathBlock").textContent = [
      `启动 GUI:   bin\\ctf-studio.cmd`,
      `集成根:     ${s.root}`,
      `运行目录:   ${s.runs_dir}`,
      `本地 Python:${s.python?.path || ""} (${s.python?.version || ""})`,
      `WSL:        wsl.exe -d ${s.wsl?.distro || "ctf-kali"} -u ${s.wsl?.user || "ctf"}`,
      `Codex:      ${s.codex?.path || "not found"}`,
      `Muteki UI:  ${s.muteki?.ui || "http://127.0.0.1:3001/ctf"}`,
      `版本:       ${VERSION}`,
    ].join("\n");
  }

  async function startMuteki() {
    const btn = $("#startMuteki");
    btn.disabled = true;
    try {
      const data = await api("/api/muteki/start", { method: "POST", body: {} });
      if (data.started === false) {
        toast(data.error || "无法启动 Muteki。", "error");
        return;
      }
      toast(data.already ? "Muteki 已在运行。" : "已启动 Muteki；首次启动需要几分钟。", "success");
      if (data.log) toast(`日志：${data.log}`);
      if (state.mutekiPoll) clearInterval(state.mutekiPoll);
      let n = 0;
      state.mutekiPoll = setInterval(async () => {
        n += 1;
        await loadStatus(true);
        if (state.status?.muteki?.online || n > 60) {
          clearInterval(state.mutekiPoll);
          state.mutekiPoll = null;
        }
      }, 5000);
    } catch (err) {
      toast(`启动失败：${err.message}`, "error");
    } finally {
      btn.disabled = false;
    }
  }

  // ---- wire up ------------------------------------------------------------

  function wire() {
    $$(".rail-btn[data-view]").forEach((btn) => {
      btn.addEventListener("click", () => setView(btn.dataset.view));
    });
    $("#helpButton").addEventListener("click", openGuide);
    $("#firstRunOpen").addEventListener("click", openGuide);
    $("#guideClose").addEventListener("click", closeGuide);
    $("#guideStart").addEventListener("click", closeGuide);
    $("#guideBackdrop").addEventListener("click", (event) => {
      if (event.target === $("#guideBackdrop")) closeGuide();
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && !$("#guideBackdrop").classList.contains("hidden")) {
        closeGuide();
      }
    });
    $("#themeToggle").addEventListener("click", () => {
      const dark = !document.documentElement.classList.contains("dark");
      document.documentElement.classList.toggle("dark", dark);
      localStorage.setItem("ctf-studio-theme", dark ? "dark" : "light");
    });
    $("#mutekiButton").addEventListener("click", () => {
      const m = state.status?.muteki;
      if (m?.online) window.open(m.ui, "_blank", "noopener");
      else {
        setView("settings");
        toast("Muteki 未运行；这里可以启动服务。", "error");
      }
    });
    $("#attachButton").addEventListener("click", () => $("#fileInput").click());
    $("#fileInput").addEventListener("change", (event) => {
      addFiles(event.target.files || []);
      event.target.value = "";
    });
    const dropzone = $("#dropzone");
    for (const type of ["dragenter", "dragover"]) {
      dropzone.addEventListener(type, (event) => {
        event.preventDefault();
        dropzone.classList.add("dragging");
      });
    }
    for (const type of ["dragleave", "drop"]) {
      dropzone.addEventListener(type, (event) => {
        event.preventDefault();
        dropzone.classList.remove("dragging");
      });
    }
    dropzone.addEventListener("drop", (event) => addFiles(event.dataTransfer.files || []));
    $("#advancedToggle").addEventListener("click", () => {
      $("#advancedPanel").classList.toggle("hidden");
    });
    $("#mode").addEventListener("change", renderModeHint);
    $("#dispatchButton").addEventListener("click", dispatch);
    $("#description").addEventListener("keydown", (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
        event.preventDefault();
        dispatch();
      }
    });
    $("#stopRun").addEventListener("click", async () => {
      if (!state.run) return;
      try {
        await api(`/api/runs/${encodeURIComponent(state.run.id)}/cancel`, { method: "POST", body: {} });
        toast("已停止；Worker 进程会被终止。", "success");
        pollRun();
      } catch (err) {
        toast(err.message, "error");
      }
    });
    $("#backToCompose").addEventListener("click", () => {
      stopPolling();
      setView("compose");
    });
    $("#consoleForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const command = $("#commandInput").value.trim();
      if (!command || !state.run) return;
      $("#commandInput").value = "";
      try {
        await api(`/api/runs/${encodeURIComponent(state.run.id)}/command`, {
          method: "POST",
          body: { command, shell: $("#consoleShell").value || "wsl" },
        });
        toast("命令已下发到 ctf-kali。", "success");
        pollRun();
      } catch (err) {
        toast(err.message, "error");
      }
    });
    $("#flagForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const value = $("#manualFlag").value.trim();
      if (!value || !state.run) return;
      try {
        await api(`/api/runs/${encodeURIComponent(state.run.id)}/flag`, {
          method: "POST",
          body: { value },
        });
        $("#manualFlag").value = "";
        toast("已按人工确认记入台账。", "success");
        pollRun();
      } catch (err) {
        toast(err.message, "error");
      }
    });
    $("#refreshHistory").addEventListener("click", loadHistory);
    $("#searchForm").addEventListener("submit", (event) => {
      event.preventDefault();
      search();
    });
    $("#refreshStatus").addEventListener("click", () => loadStatus(true));
    $("#startMuteki").addEventListener("click", startMuteki);
    $("#transformInput").addEventListener("input", () => {
      runRecipe();
    });
    $("#magicButton").addEventListener("click", () => {
      const input = currentTransformInput();
      if (!input.trim()) {
        toast("先粘贴一段内容。", "error");
        return;
      }
      const results = magicTransform(input);
      if (!results.length) {
        state.transformOutput = "没有找到可读的变换结果。";
        state.transformFlags = [];
      } else {
        state.transformOutput = results
          .map((r) => `=== ${r.label}  (score ${r.score.toFixed(1)}) ===\n${r.text}`)
          .join("\n\n");
        state.transformFlags = [...new Set(results.flatMap((r) => flagCandidates(r.text)))];
      }
      renderTransform();
    });
    $("#clearRecipe").addEventListener("click", () => {
      state.recipe = [];
      state.transformOutput = currentTransformInput();
      state.transformFlags = flagCandidates(state.transformOutput);
      renderTransform();
    });
    $("#copyOutput").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText($("#transformOutput").textContent || "");
        toast("输出已复制", "success");
      } catch {
        toast("复制失败", "error");
      }
    });
    $("#useOutput").addEventListener("click", () => {
      $("#transformInput").value = $("#transformOutput").textContent || "";
      state.recipe = [];
      state.transformOutput = $("#transformInput").value;
      state.transformFlags = flagCandidates(state.transformOutput);
      renderTransform();
    });
    $("#sendToChallenge").addEventListener("click", () => {
      const text = $("#transformOutput").textContent || "";
      if (!text.trim()) return;
      $("#description").value = text;
      setView("compose");
      toast("已放进题面输入框。", "success");
    });
    $("#saveTransformFlag").addEventListener("click", saveTransformFlag);
  }

  function init() {
    const theme = localStorage.getItem("ctf-studio-theme");
    // The product default is the light, white-first workbench.  Dark mode is
    // opt-in through the rail toggle and persists only after the user chooses it.
    if (theme === "dark") {
      document.documentElement.classList.add("dark");
    }
    wire();
    renderFiles();
    renderModeHint();
    if (!localStorage.getItem("ctf-studio-guide-seen")) {
      $("#firstRunCard").classList.remove("hidden");
    }
    // WebView2 remembers a Ctrl+wheel zoom in its profile, which can leave the
    // whole UI looking "blown up" with no obvious way back.  The app has its
    // own layout, so block browser zoom shortcuts.
    window.addEventListener(
      "wheel",
      (event) => {
        if (event.ctrlKey) event.preventDefault();
      },
      { passive: false }
    );
    document.addEventListener(
      "keydown",
      (event) => {
        if (event.ctrlKey && ["+", "-", "=", "0"].includes(event.key)) {
          event.preventDefault();
        }
      },
      { capture: true }
    );
    setView("compose");
    loadStatus();
    loadHistory();
    api("/api/client-info", {
      method: "POST",
      body: {
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight,
        outerWidth: window.outerWidth,
        outerHeight: window.outerHeight,
        devicePixelRatio: window.devicePixelRatio,
        screen: [screen.width, screen.height],
        avail: [screen.availWidth, screen.availHeight],
        visualScale: window.visualViewport ? window.visualViewport.scale : null,
        userAgent: navigator.userAgent,
      },
    }).catch(() => {});
    setInterval(() => {
      if (state.view === "compose") loadStatus();
    }, 30000);
  }

  init();
})();
