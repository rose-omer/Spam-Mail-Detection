// SpamMailD analiz paneli. Mail içeriği güvenilmez veridir: DOM'a yalnız textContent ile yazılır.
"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const form = $("analiz-formu");
  const textarea = $("ham-mail");
  const fileInput = $("dosya");
  const dropZone = $("birakma-alani");
  const fileStatus = $("dosya-durumu");
  const pickButton = $("dosya-sec");
  const clearButton = $("dosya-kaldir");
  const submitButton = $("analiz-et");
  const formError = $("form-hatasi");
  const keyField = $("anahtar-alani");
  const keyInput = $("api-anahtari");
  const result = $("sonuc");
  const resultHeading = $("sonuc-baslik");
  const KEY_STORAGE = "spammaild.apiKey";
  const DEFAULT_DROP_TEXT = fileStatus.textContent;

  let selectedFile = null;
  let config = null;
  let busy = false;

  const LABELS = {
    band: { clean: "Temiz", suspicious: "Şüpheli", spam: "Spam / phishing" },
    bandIcon: { clean: "i-check", suspicious: "i-alert", spam: "i-x" },
    source: { content: "İçerik", auth: "Kimlik", url: "URL", attachment: "Ek" },
    auth: {
      pass: ["geçti", "pass", "i-check"],
      fail: ["başarısız", "fail", "i-x"],
      softfail: ["zayıf başarısız", "warn", "i-alert"],
      neutral: ["nötr", "none", "i-minus"],
      none: ["yok", "none", "i-minus"],
      policy: ["politika", "warn", "i-alert"],
      temperror: ["geçici hata", "warn", "i-alert"],
      permerror: ["kalıcı hata", "warn", "i-alert"],
      unknown: ["bilinmiyor", "none", "i-help"],
    },
    scan: {
      clean: ["temiz", "pass", "i-check"],
      infected: ["zararlı", "fail", "i-x"],
      unknown: ["bilinmiyor", "warn", "i-help"],
      error: ["hata", "warn", "i-alert"],
      skipped: ["taranmadı", "none", "i-minus"],
    },
    reputation: {
      malicious: ["zararlı listede", "fail", "i-x"],
      not_listed: ["listede yok", "pass", "i-check"],
      unknown: ["bilinmiyor", "warn", "i-help"],
      error: ["hata", "warn", "i-alert"],
      skipped: ["sorgulanmadı", "none", "i-minus"],
    },
    urlFlag: {
      text_mismatch: "Metin ve hedef farklı",
      ip_literal: "IP adresi",
      punycode: "Punycode",
      shortener: "Kısaltıcı",
      foreign_domain: "Başka alan adı",
    },
    fileFlag: {
      double_extension: "Çift uzantı",
      executable: "Çalıştırılabilir",
      macro: "Makro",
      encrypted_archive: "Parolalı arşiv",
      too_large: "Boyut sınırı aşıldı",
    },
    status: { unknown: "bilinmiyor", error: "hata" },
    language: { tr: "Türkçe", en: "İngilizce", unknown: "belirlenemedi" },
  };

  const numberTr = new Intl.NumberFormat("tr-TR", { maximumFractionDigits: 1 });

  // ---- küçük DOM yardımcıları ----
  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === "text") node.textContent = value;
      else if (key === "class") node.className = value;
      else if (key.startsWith("data-") || key.startsWith("aria-") || key === "role" || key === "id" || key === "tabindex" || key === "scope") {
        node.setAttribute(key, String(value));
      } else node[key] = value;
    }
    for (const child of [].concat(children)) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function icon(name, extraClass = "") {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", `icon ${extraClass}`.trim());
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#${name}`);
    svg.append(use);
    return svg;
  }

  function stateTag(map, value) {
    const [label, tone, iconName] = map[value] || map.unknown;
    return el("span", { class: "state", "data-tone": tone }, [icon(iconName), label]);
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${numberTr.format(bytes / 1024)} KB`;
    return `${numberTr.format(bytes / (1024 * 1024))} MB`;
  }

  // ---- anahtar saklama (yalnız bu sekme) ----
  function readKey() {
    try { return sessionStorage.getItem(KEY_STORAGE) || ""; } catch { return ""; }
  }
  function saveKey(value) {
    try { sessionStorage.setItem(KEY_STORAGE, value); } catch { /* depolama kapalı olabilir */ }
  }

  // ---- yapılandırma ----
  async function loadConfig() {
    try {
      const response = await fetch("/v1/config", { headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error(String(response.status));
      config = await response.json();
    } catch {
      renderStatus([{ text: "Sunucuya ulaşılamadı", tone: "warn" }]);
      return;
    }
    $("azami-boyut").textContent = numberTr.format(config.max_request_mb);
    keyField.hidden = !config.auth_required;
    if (config.auth_required) keyInput.value = readKey();

    const chips = [];
    if (config.demo_mode) chips.push({ text: "Demo modu: dış servisler kapalı", tone: "warn" });
    else {
      chips.push({ text: "ClamAV", on: config.clamav_enabled });
      chips.push({ text: "VirusTotal", on: config.virustotal_enabled });
      chips.push({ text: "URL itibarı", on: config.url_reputation_enabled });
    }
    if (!config.model.available) chips.push({ text: "İçerik modeli yüklenemedi", tone: "warn" });
    renderStatus(chips);

    const urlNote = config.url_reputation_enabled
      ? " Bağlantı adresleri (# sonrası hariç) itibar sorgusu için URLhaus'a ya da yerel listeye gönderilir; adresteki sorgu parametreleri de gider."
      : "";
    if (config.vt_upload) {
      const privacy = $("gizlilik");
      privacy.dataset.tone = "danger";
      $("gizlilik-metni").textContent =
        "Dikkat: VirusTotal'da kaydı olmayan ekler VirusTotal'a yüklenir ve VT topluluğuna açılır. Kişisel veri içeren mailleri göndermeyin. Mail metni sunucuda saklanmaz." + urlNote;
    } else if (urlNote) {
      $("gizlilik-metni").textContent += urlNote;
    }
  }

  // ---- tema ----
  const THEME_STORAGE = "spammaild.theme";
  const themeInputs = document.querySelectorAll('input[name="tema"]');
  function currentTheme() {
    const value = document.documentElement.dataset.theme;
    return value === "light" || value === "dark" ? value : "system";
  }
  for (const input of themeInputs) {
    input.checked = input.value === currentTheme();
    input.addEventListener("change", () => {
      if (!input.checked) return;
      if (input.value === "system") delete document.documentElement.dataset.theme;
      else document.documentElement.dataset.theme = input.value;
      try {
        if (input.value === "system") localStorage.removeItem(THEME_STORAGE);
        else localStorage.setItem(THEME_STORAGE, input.value);
      } catch { /* depolama kapalı olabilir: seçim yalnız bu sayfada geçerli */ }
    });
  }

  function renderStatus(chips) {
    const list = $("durum");
    list.replaceChildren(
      ...chips.map((chip) =>
        el("li", {}, [
          el("span", {
            class: "status-chip",
            "data-on": chip.on === undefined ? null : String(chip.on),
            "data-tone": chip.tone,
            text: chip.on === undefined ? chip.text : `${chip.text} ${chip.on ? "açık" : "kapalı"}`,
          }),
        ]),
      ),
    );
  }

  // ---- dosya seçimi ----
  function setFile(file) {
    selectedFile = file;
    dropZone.dataset.hasFile = String(Boolean(file));
    clearButton.hidden = !file;
    fileStatus.textContent = file ? `${file.name} (${formatBytes(file.size)})` : DEFAULT_DROP_TEXT;
    textarea.disabled = Boolean(file);
    if (file) clearSamplePressed();
  }

  pickButton.addEventListener("click", () => fileInput.click());
  clearButton.addEventListener("click", () => {
    fileInput.value = "";
    setFile(null);
    pickButton.focus();
  });
  fileInput.addEventListener("change", () => setFile(fileInput.files[0] || null));

  for (const type of ["dragenter", "dragover"]) {
    dropZone.addEventListener(type, (event) => {
      event.preventDefault();
      dropZone.dataset.dragging = "true";
    });
  }
  for (const type of ["dragleave", "drop"]) {
    dropZone.addEventListener(type, (event) => {
      event.preventDefault();
      if (type === "dragleave" && dropZone.contains(event.relatedTarget)) return;
      dropZone.dataset.dragging = "false";
    });
  }
  dropZone.addEventListener("drop", (event) => {
    const file = event.dataTransfer && event.dataTransfer.files[0];
    if (file) setFile(file);
  });

  // ---- örnekler ----
  function clearSamplePressed() {
    document.querySelectorAll("[data-sample]").forEach((button) => button.setAttribute("aria-pressed", "false"));
  }

  document.querySelectorAll("[data-sample]").forEach((button) => {
    button.setAttribute("aria-pressed", "false");
    button.addEventListener("click", async () => {
      if (busy) return;
      try {
        const response = await fetch(`/static/samples/${button.dataset.sample}.eml`);
        if (!response.ok) throw new Error(String(response.status));
        fileInput.value = "";
        setFile(null);
        textarea.value = await response.text();
      } catch {
        showFormError("Örnek mail yüklenemedi. Sayfayı yenileyip yeniden deneyin.");
        return;
      }
      clearSamplePressed();
      button.setAttribute("aria-pressed", "true");
      analyze();
    });
  });

  $("ornek-dene").addEventListener("click", () => {
    document.querySelector('[data-sample="sahte-banka"]').click();
  });

  textarea.addEventListener("input", clearSamplePressed);
  textarea.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      analyze();
    }
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    analyze();
  });

  // ---- analiz ----
  function showFormError(message) {
    formError.textContent = message;
  }

  function setBusy(state) {
    busy = state;
    submitButton.disabled = state;
    submitButton.setAttribute("aria-busy", String(state));
    submitButton.textContent = state ? "Analiz ediliyor" : "Analiz et";
    result.setAttribute("aria-busy", String(state));
  }

  async function analyze() {
    if (busy) return;
    showFormError("");
    const raw = textarea.value;
    if (!selectedFile && !raw.trim()) {
      showFormError("Önce ham maili yapıştırın ya da bir .eml dosyası seçin.");
      (selectedFile ? pickButton : textarea).focus();
      return;
    }
    if (config && config.auth_required && !keyInput.value.trim()) {
      showFormError("Bu sunucu API anahtarı istiyor. Anahtarı girin.");
      keyInput.focus();
      return;
    }

    const headers = { Accept: "application/json" };
    if (config && config.auth_required) {
      headers["X-API-Key"] = keyInput.value.trim();
      saveKey(keyInput.value.trim());
    }
    let body;
    if (selectedFile) {
      body = new FormData();
      body.append("file", selectedFile, selectedFile.name);
    } else {
      headers["Content-Type"] = "message/rfc822";
      body = raw;
    }

    setBusy(true);
    result.replaceChildren($("t-skeleton").content.cloneNode(true));
    try {
      const response = await fetch("/v1/analyze", { method: "POST", headers, body });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        renderError(response.status, payload);
      } else {
        renderResult(payload);
      }
    } catch {
      renderError(0, null);
    } finally {
      setBusy(false);
    }
    resultHeading.focus({ preventScroll: window.matchMedia("(min-width: 960px)").matches });
  }

  function renderError(status, payload) {
    const message = payload && payload.error ? payload.error.message : "";
    const titles = {
      0: ["Sunucuya ulaşılamadı", "Bağlantıyı denetleyin ve yeniden deneyin."],
      401: ["API anahtarı geçersiz", "Doğru anahtarı girip yeniden analiz edin."],
      413: ["Mail çok büyük", "Ekleri küçültün ya da daha küçük bir dosya seçin."],
      422: ["Mail okunamadı", "Ham maili başlıklarıyla birlikte yapıştırdığınızdan emin olun."],
      429: ["Çok fazla istek", "Bir dakika bekleyip yeniden deneyin."],
    };
    const [title, recovery] = titles[status] || ["Analiz tamamlanamadı", "Biraz sonra yeniden deneyin."];
    result.replaceChildren(
      el("div", { class: "alert", role: "alert" }, [
        icon("i-alert"),
        el("div", { class: "alert__body" }, [
          el("p", { class: "alert__title", text: title }),
          message ? el("p", { text: message }) : null,
          el("p", { text: recovery }),
        ]),
      ]),
    );
    if (status === 401) keyInput.focus();
  }

  // ---- sonuç ----
  function renderResult(data) {
    const container = el("div", { class: "result result__appear" }, [
      renderSummary(data),
      renderAuth(data.auth),
      renderReasons(data.reasons),
      renderUrls(data.urls),
      renderAttachments(data.attachments),
      renderFooter(data),
    ]);
    result.replaceChildren(container);
    const marker = container.querySelector(".ruler__marker");
    marker.getBoundingClientRect(); // başlangıç konumunu uygula; geçiş 0'dan başlasın
    marker.style.setProperty("--pos", String(data.risk));
  }

  function renderSummary(data) {
    const segments = [
      ["clean", "ruler__seg--clean"],
      ["suspicious", "ruler__seg--warn"],
      ["spam", "ruler__seg--risk"],
    ];
    const scale = el("div", { class: "ruler__scale", "aria-hidden": "true" });
    for (const value of [0, 35, 65, 100]) {
      const tick = el("span", { text: String(value) });
      tick.style.left = `${value}%`;
      scale.append(tick);
    }
    return el("section", { class: "summary", "aria-label": "Özet" }, [
      el("div", { class: "summary__head" }, [
        el("p", { class: "score" }, [
          el("span", { class: "score__value", text: String(data.risk) }),
          el("span", { class: "score__max", text: "/ 100 risk" }),
        ]),
        el("p", { class: "band", "data-band": data.band }, [
          icon(LABELS.bandIcon[data.band] || "i-help"),
          LABELS.band[data.band] || data.band,
        ]),
      ]),
      el("div", {
        class: "ruler",
        role: "meter",
        "aria-valuemin": 0,
        "aria-valuemax": 100,
        "aria-valuenow": data.risk,
        "aria-valuetext": `${data.risk} / 100, ${LABELS.band[data.band] || data.band}`,
        "aria-label": "Risk skoru",
      }, [
        el("div", { class: "ruler__track" },
          segments.map(([band, cls]) => el("span", { class: `ruler__seg ${cls}`, "data-active": String(band === data.band) }))),
        el("span", { class: "ruler__marker" }),
        scale,
      ]),
      el("dl", { class: "meta" }, [
        el("dt", { text: "Gönderen" }),
        el("dd", { text: formatSender(data.message) }),
        el("dt", { text: "Konu" }),
        el("dd", { text: data.message.subject || "konu yok" }),
      ]),
    ]);
  }

  function formatSender(message) {
    if (!message.sender) return "bilinmiyor";
    return message.sender_name ? `${message.sender_name} <${message.sender}>` : message.sender;
  }

  function renderAuth(auth) {
    const methods = ["spf", "dkim", "dmarc"];
    const badges = methods.map((method) => {
      const [label, tone, iconName] = LABELS.auth[auth[method].result] || LABELS.auth.unknown;
      return el("span", { class: "badge", "data-tone": tone }, [
        icon(iconName),
        el("span", { class: "badge__name", text: method.toUpperCase() }),
        el("span", { text: label }),
      ]);
    });
    // Kaynak bilgisi ipucunda saklanmaz; her cihazda görünür kısa notlar olarak yazılır.
    const notes = [];
    const sources = [...new Set(methods.map((method) => auth[method].source).filter(Boolean))];
    for (const source of sources) {
      notes.push(el("p", {}, ["Kaynak: ", el("code", { text: source })]));
    }
    if (!auth.trusted_authserv_id) {
      notes.push(el("p", { text: "TRUSTED_AUTHSERV_ID tanımlı değil; sonuçlar okunmadı." }));
    } else {
      const missing = methods.filter((method) => !auth[method].source).map((m) => m.toUpperCase());
      if (missing.length === methods.length) {
        notes.push(el("p", { text: `En üstteki Authentication-Results başlığı güvenilen ${auth.trusted_authserv_id} sunucusundan değil ya da yok.` }));
      } else if (missing.length) {
        notes.push(el("p", { text: `${auth.trusted_authserv_id} başlığında ${missing.join(", ")} sonucu yok.` }));
      }
    }
    return el("section", { "aria-labelledby": "h-kimlik" }, [
      el("h3", { id: "h-kimlik", text: "Kimlik doğrulama" }),
      el("div", { class: "badges" }, badges),
      el("div", { class: "auth-notes" }, notes),
    ]);
  }

  const LEAD_COUNT = 3;
  const LEAD_MIN_IMPACT = 0.5;
  const REST_OPEN_MAX = 4;

  function reasonItem(reason, maxImpact) {
    const dir = reason.impact > 0.05 ? "up" : reason.impact < -0.05 ? "down" : "flat";
    const dirText = dir === "up" ? "riski artırıyor" : dir === "down" ? "riski azaltıyor" : "etkisiz";
    const impactText = `${reason.impact > 0 ? "+" : ""}${numberTr.format(reason.impact)}`;
    const state = LABELS.status[reason.status];
    const meter = el("span", { class: "reason__meter", "data-dir": dir, "aria-hidden": "true" }, el("span"));
    meter.firstChild.style.setProperty("--w", String(maxImpact ? (Math.abs(reason.impact) / maxImpact) * 100 : 0));
    return el("li", { class: "reason" }, [
      el("span", { class: "reason__source", text: LABELS.source[reason.source] || reason.source }),
      el("p", { class: "reason__text" }, [
        reason.text,
        state ? el("span", { class: "reason__state", text: state }) : null,
      ]),
      meter,
      el("span", { class: "reason__impact", "data-dir": dir, title: dirText }, [
        dir === "flat" ? null : icon(dir === "up" ? "i-up" : "i-down"),
        el("span", { "aria-hidden": "true", text: impactText }),
        el("span", { class: "visually-hidden", text: `Etki ${impactText}, ${dirText}` }),
      ]),
    ]);
  }

  function renderReasons(reasons) {
    // Sunucu nedenleri etki büyüklüğüne göre sıralı gönderir.
    const maxImpact = Math.max(0, ...reasons.map((reason) => Math.abs(reason.impact)));
    let leadCount = 0;
    while (
      leadCount < Math.min(LEAD_COUNT, reasons.length) &&
      Math.abs(reasons[leadCount].impact) >= LEAD_MIN_IMPACT
    ) leadCount += 1;
    if (leadCount === 0) leadCount = Math.min(LEAD_COUNT, reasons.length);
    const lead = reasons.slice(0, leadCount);
    const rest = reasons.slice(leadCount);

    const children = [
      el("div", { class: "section-head" }, [
        el("h3", { id: "h-nedenler", text: "Nedenler" }),
        el("p", {
          class: "hint",
          id: "etki-aciklama",
          text: "Etki, nedenin skora katkısıdır. Artı değer riski yükseltir, eksi değer düşürür. Etkiler toplanıp 0–100 skora çevrilir; +1 kabaca spam/temiz oranını 2,7 kat artırır. Çubuk, en güçlü nedene göre boylanır.",
        }),
      ]),
      el("ul", { class: "reasons reasons--lead", "aria-label": "Skoru en çok etkileyen nedenler", "aria-describedby": "etki-aciklama" },
        lead.map((reason) => reasonItem(reason, maxImpact))),
    ];
    if (rest.length) {
      const details = el("details", { class: "more" }, [
        el("summary", {}, [`Diğer ${rest.length} bulgu`, icon("i-chevron")]),
        el("ul", { class: "reasons reasons--rest" }, rest.map((reason) => reasonItem(reason, maxImpact))),
      ]);
      details.open = rest.length <= REST_OPEN_MAX;
      children.push(details);
    }
    return el("section", { "aria-labelledby": "h-nedenler" }, children);
  }

  function flagList(flags, labels) {
    if (!flags.length) return el("span", { class: "muted", text: "yok" });
    return el("span", { class: "flags" }, flags.map((flag) => el("span", { class: "flag", text: labels[flag] || flag })));
  }

  function table(headings, rows) {
    return el("div", { class: "table-wrap" }, el("table", { class: "table" }, [
      el("thead", {}, el("tr", {}, headings.map((heading) => el("th", { scope: "col", text: heading })))),
      el("tbody", {}, rows.map((cells) =>
        el("tr", {}, cells.map((cell, index) => el("td", { "data-label": headings[index] }, cell))))),
    ]));
  }

  function renderUrls(urls) {
    const body = urls.length
      ? table(
          ["Görünen metin", "Gerçek hedef", "Alan adı", "İşaretler", "İtibar"],
          urls.map((url) => [
            url.text ? url.text : el("span", { class: "muted", text: "düz metin" }),
            el("span", { class: "mono", text: url.href }),
            url.domain || url.host || "–",
            flagList(url.flags, LABELS.urlFlag),
            stateTag(LABELS.reputation, url.reputation),
          ]),
        )
      : el("p", { class: "section-empty", text: "Mailde bağlantı yok." });
    return el("section", { "aria-labelledby": "h-url" }, [el("h3", { id: "h-url", text: "Bağlantılar" }), body]);
  }

  function renderAttachments(files) {
    const body = files.length
      ? table(
          ["Ad", "Tür", "Boyut", "İşaretler", "ClamAV", "VirusTotal"],
          files.map((file) => [
            el("span", { class: "mono", text: file.filename }),
            `${file.detected_type} (${file.content_type})`,
            formatBytes(file.size),
            flagList(file.flags, LABELS.fileFlag),
            stateTag(LABELS.scan, file.clamav.status),
            stateTag(LABELS.scan, file.virustotal.status),
          ]),
        )
      : el("p", { class: "section-empty", text: "Mailde ek yok." });
    return el("section", { "aria-labelledby": "h-ek" }, [el("h3", { id: "h-ek", text: "Ekler" }), body]);
  }

  function renderFooter(data) {
    const model = data.model;
    return el("footer", { class: "footer-meta" }, [
      el("span", {}, ["Model ", el("strong", { text: model.available ? model.name : "yüklenemedi" })]),
      el("span", {}, ["Sürüm ", el("strong", { text: model.version })]),
      el("span", {}, ["Dil ", el("strong", { text: LABELS.language[data.message.language] || data.message.language })]),
    ]);
  }

  loadConfig();
})();
