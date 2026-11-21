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
  const KEY_STORAGE = "spammaild.apiKey";

  let selectedFile = null;
  let config = null;
  let busy = false;

  const LABELS = {
    band: { clean: "Temiz", suspicious: "Şüpheli", spam: "Spam / phishing" },
    source: { content: "İçerik", auth: "Kimlik", url: "URL", attachment: "Ek" },
    auth: {
      pass: ["geçti", "pass"],
      fail: ["başarısız", "fail"],
      softfail: ["zayıf başarısız", "warn"],
      neutral: ["nötr", "none"],
      none: ["yok", "none"],
      policy: ["politika", "warn"],
      temperror: ["geçici hata", "warn"],
      permerror: ["kalıcı hata", "warn"],
      unknown: ["bilinmiyor", "none"],
    },
    scan: {
      clean: ["temiz", "pass"],
      infected: ["zararlı", "fail"],
      unknown: ["bilinmiyor", "warn"],
      error: ["hata", "warn"],
      skipped: ["taranmadı", "none"],
    },
    reputation: {
      malicious: ["zararlı listede", "fail"],
      not_listed: ["listede yok", "pass"],
      unknown: ["bilinmiyor", "warn"],
      error: ["hata", "warn"],
      skipped: ["sorgulanmadı", "none"],
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

  // Eylem önerisi bilerek genel: belirli kuruma, numaraya ya da adıma yönlendirmez.
  const ADVICE = {
    spam: "Bağlantılara tıklamayın, ekleri açmayın. Mail bir kurum adına geliyorsa kuruma kendi bildiğiniz bir kanaldan ulaşın.",
    suspicious: "Bağlantı ve eklerde dikkatli olun. Emin değilseniz gönderene başka bir kanaldan sorun.",
    clean: "Belirgin bir risk bulunmadı. Skor bir garanti değildir; beklemediğiniz istekleri yine de doğrulayın.",
  };
  const COUNT_WORDS = ["", "Bir", "İki", "Üç"];
  const BANDS = [
    ["clean", "Temiz 0–34"],
    ["suspicious", "Şüpheli 35–64"],
    ["spam", "Spam / phishing 65–100"],
  ];

  const numberTr = new Intl.NumberFormat("tr-TR", { maximumFractionDigits: 1 });
  const impactTr = new Intl.NumberFormat("tr-TR", { minimumFractionDigits: 1, maximumFractionDigits: 1 });

  // ---- küçük DOM yardımcıları ----
  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === "text") node.textContent = value;
      else if (key === "class") node.className = value;
      else if (key.startsWith("data-") || key.startsWith("aria-") || key === "role" || key === "id" || key === "tabindex" || key === "lang") {
        node.setAttribute(key, String(value));
      } else node[key] = value;
    }
    for (const child of [].concat(children)) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function stateText(map, value) {
    const [label, tone] = map[value] || map.unknown;
    return el("span", { "data-tone": tone, text: label });
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${numberTr.format(bytes / 1024)} KB`;
    return `${numberTr.format(bytes / (1024 * 1024))} MB`;
  }

  function impactInfo(impact) {
    const dir = impact > 0.05 ? "up" : impact < -0.05 ? "down" : "flat";
    const text = `${impact > 0 ? "+" : ""}${impactTr.format(impact)}`;
    const meaning = dir === "up" ? "riski artırıyor" : dir === "down" ? "riski azaltıyor" : "etkisiz";
    return { dir, text, meaning };
  }

  // "Spam / phishing" büyük harfe çevrilirken İngilizce sözcük Türkçe "İ" almasın.
  function bandLabel(band) {
    if (band === "spam") return ["Spam / ", el("span", { lang: "en", text: "phishing" })];
    return LABELS.band[band] || band;
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
    renderModel(config.model, null);

    const urlNote = config.url_reputation_enabled
      ? " Bağlantı adresleri (# sonrası hariç) itibar sorgusu için URLhaus'a ya da yerel listeye gönderilir; adresteki sorgu parametreleri de gider."
      : "";
    if (config.vt_upload) {
      const warning = "Dikkat: VirusTotal'da kaydı olmayan ekler VirusTotal'a yüklenir ve VT topluluğuna açılır. Kişisel veri içeren mailleri göndermeyin.";
      const upload = $("yukleme-uyarisi");
      upload.textContent = warning;
      upload.hidden = false;
      $("gizlilik-metni").textContent = `${warning} Mail metni sunucuda saklanmaz.${urlNote}`;
    } else if (urlNote) {
      $("gizlilik-metni").textContent += urlNote;
    }
  }

  function renderStatus(chips) {
    $("durum").replaceChildren(
      ...chips.map((chip) =>
        el("li", {
          "data-on": chip.on === undefined ? null : String(chip.on),
          "data-tone": chip.tone,
          text: chip.on === undefined ? chip.text : `${chip.text} ${chip.on ? "açık" : "kapalı"}`,
        }),
      ),
    );
  }

  function renderModel(model, language) {
    const parts = [el("span", { text: `Model ${model.available ? model.name : "yüklenemedi"} ${model.version}` })];
    if (language) parts.push(el("span", { text: `Dil ${LABELS.language[language] || language}` }));
    $("model-bilgisi").replaceChildren(...parts);
  }

  // ---- tema ----
  const THEME_STORAGE = "spammaild.theme";
  const themeInputs = document.querySelectorAll('input[name="tema"]');
  const currentTheme = document.documentElement.dataset.themePref || "system";
  for (const input of themeInputs) {
    input.checked = input.value === currentTheme;
    input.addEventListener("change", () => {
      if (!input.checked) return;
      if (window.spammaildTheme) window.spammaildTheme(input.value);
      try {
        if (input.value === "system") localStorage.removeItem(THEME_STORAGE);
        else localStorage.setItem(THEME_STORAGE, input.value);
      } catch { /* depolama kapalı olabilir: seçim yalnız bu sayfada geçerli */ }
    });
  }

  // ---- dosya seçimi ----
  function setFile(file) {
    selectedFile = file;
    clearButton.hidden = !file;
    fileStatus.textContent = file ? `Seçili dosya: ${file.name} (${formatBytes(file.size)}).` : "";
    fileStatus.hidden = !file;
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
      textarea.focus();
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
    renderLoading();
    let focusKey = false;
    try {
      const response = await fetch("/v1/analyze", { method: "POST", headers, body });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        renderError(response.status, payload);
        focusKey = response.status === 401;
      } else {
        renderResult(payload);
      }
    } catch {
      renderError(0, null);
    } finally {
      setBusy(false);
    }
    if (focusKey) keyInput.focus();
    else $("sonuc-baslik").focus({ preventScroll: true });
    if (!focusKey) $("sonuc-baslik").scrollIntoView({ block: "nearest" });
  }

  // ---- karar bandı (her durumda aynı iskelet) ----
  // Canlı bölge yok: analizden sonra odak başlığa geçer ve ekran okuyucu başlığın adını bir kez okur.
  // `label` başlığın erişilebilir adıdır (karar ve skor tek cümlede).
  function verdict({ state, band, from, title, label, quiet, score, advice, activeBand }) {
    const row = [];
    if (score !== undefined) {
      row.push(el("p", { class: "score" }, [
        el("span", { class: "score__value", text: String(score) }),
        el("span", { class: "score__max", text: "/ 100 risk" }),
      ]));
    }
    if (advice) row.push(el("div", { class: "verdict__advice" }, [].concat(advice).map((line) => el("p", { text: line }))));

    const scaleAttrs = activeBand
      ? {
          class: "scale",
          role: "meter",
          "aria-label": "Risk skoru",
          "aria-valuemin": 0,
          "aria-valuemax": 100,
          "aria-valuenow": score,
          "aria-valuetext": `${score} / 100, ${LABELS.band[activeBand] || activeBand}`,
        }
      : { class: "scale", "aria-hidden": "true" };
    const scaleTag = activeBand ? "div" : "ol";
    const itemTag = activeBand ? "span" : "li";
    const scale = el(scaleTag, scaleAttrs,
      BANDS.map(([key, label]) => el(itemTag, { "data-active": String(key === activeBand), text: label })));

    return el("section", {
      class: `verdict${state === "result" ? " verdict--reveal" : ""}`,
      "data-state": state,
      "data-band": band,
      "aria-labelledby": "sonuc-baslik",
    }, el("div", { class: "wrap" }, [
      from ? el("p", { class: "verdict__from", text: from }) : null,
      el("h2", {
        id: "sonuc-baslik",
        class: `verdict__title${quiet ? " verdict__title--state" : ""}`,
        tabindex: -1,
        "aria-label": label,
      }, title),
      row.length ? el("div", { class: "verdict__row" }, row) : null,
      state === "error" ? null : scale,
    ]));
  }

  function renderLoading() {
    result.replaceChildren(
      verdict({
        state: "loading",
        from: selectedFile ? selectedFile.name : "Mail okunuyor.",
        title: "Analiz ediliyor",
        quiet: true,
        advice: "İçerik, kimlik doğrulama, bağlantılar ve ekler ayrı ayrı puanlanıyor.",
      }),
      el("div", { class: "wrap skeleton", "aria-hidden": "true" }, [el("span"), el("span"), el("span"), el("span")]),
    );
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
    const section = verdict({
      state: "error",
      from: status ? `Sunucu yanıtı ${status}.` : "Yanıt alınamadı.",
      title,
      label: `Hata: ${title}`,
      quiet: true,
      advice: message ? [message, recovery] : recovery,
    });
    // 401'de odak anahtar alanına gider, başlığa değil; hatayı yalnız bu durumda duyur.
    if (status === 401) section.setAttribute("role", "alert");
    result.replaceChildren(section);
  }

  function formatSender(message) {
    if (!message.sender) return "Gönderen bilinmiyor";
    return message.sender_name ? `${message.sender_name} <${message.sender}>` : message.sender;
  }

  // ---- sonuç ----
  function renderResult(data) {
    const from = `${formatSender(data.message)}. Konu: ${data.message.subject || "konu yok"}`;
    const lead = leadReasons(data.reasons);
    const rest = data.reasons.slice(lead.length);
    result.replaceChildren(
      verdict({
        state: "result",
        band: data.band,
        from,
        title: bandLabel(data.band),
        label: `Sonuç: ${LABELS.band[data.band] || data.band}, risk ${data.risk} / 100`,
        score: data.risk,
        advice: ADVICE[data.band],
        activeBand: data.band,
      }),
      el("div", { class: "wrap findings" }, [
        renderLead(lead, data.band),
        el("div", { class: "split" }, [
          renderRest(rest),
          el("div", { class: "split__side" }, [
            renderAuth(data.auth),
            renderUrls(data.urls),
            renderAttachments(data.attachments),
          ]),
        ]),
      ]),
    );
    renderModel(data.model, data.message.language);
  }

  const LEAD_COUNT = 3;
  const LEAD_MIN_IMPACT = 0.5;

  // Sunucu nedenleri etki büyüklüğüne göre sıralı gönderir.
  function leadReasons(reasons) {
    let count = 0;
    while (count < Math.min(LEAD_COUNT, reasons.length) && Math.abs(reasons[count].impact) >= LEAD_MIN_IMPACT) count += 1;
    if (count === 0) count = Math.min(LEAD_COUNT, reasons.length);
    return reasons.slice(0, count);
  }

  function renderLead(lead, band) {
    const word = COUNT_WORDS[lead.length] || String(lead.length);
    const heading = band === "spam" ? `${word} neden yeter` : `Kararı belirleyen ${word.toLocaleLowerCase("tr")} neden`;
    return el("section", { "aria-labelledby": "h-neden" }, [
      el("h3", { id: "h-neden", class: "display-head", text: heading }),
      el("ul", { class: "columns" }, lead.map((reason) => {
        const impact = impactInfo(reason.impact);
        const state = LABELS.status[reason.status];
        return el("li", { class: "column" }, [
          el("p", { class: "column__lead", "data-dir": impact.dir }, [
            el("span", { "aria-hidden": "true", text: impact.text }),
            el("span", { class: "visually-hidden", text: `Etki ${impact.text}, ${impact.meaning}.` }),
            el("span", { class: "column__source", text: LABELS.source[reason.source] || reason.source }),
          ]),
          el("p", { class: "column__text" }, [
            reason.text,
            state ? el("span", { class: "state-note", text: state }) : null,
          ]),
        ]);
      })),
    ]);
  }

  function renderRest(rest) {
    const note = el("p", {
      class: "note",
      text: "Etki, nedenin skora katkısıdır. Artı değer riski yükseltir, eksi değer düşürür. +1 kabaca spam/temiz oranını 2,7 kat artırır.",
    });
    if (!rest.length) {
      return el("section", { class: "split__main", "aria-labelledby": "h-diger" }, [
        el("h3", { id: "h-diger", text: "Diğer bulgular" }),
        el("p", { class: "empty-line", text: "Başka bulgu yok." }),
        note,
      ]);
    }
    return el("section", { class: "split__main", "aria-labelledby": "h-diger" }, [
      el("h3", { id: "h-diger", text: `Diğer ${rest.length} bulgu` }),
      el("ul", { class: "rest" }, rest.map((reason) => {
        const impact = impactInfo(reason.impact);
        const state = LABELS.status[reason.status];
        return el("li", {}, [
          el("span", { class: "rest__text" }, [
            el("span", { class: "rest__source", text: `${LABELS.source[reason.source] || reason.source}. ` }),
            reason.text,
            state ? el("span", { class: "state-note", text: state }) : null,
          ]),
          el("span", { class: "impact", "data-dir": impact.dir }, [
            el("span", { "aria-hidden": "true", text: impact.text }),
            el("span", { class: "visually-hidden", text: `Etki ${impact.text}, ${impact.meaning}.` }),
          ]),
        ]);
      })),
      note,
    ]);
  }

  function renderAuth(auth) {
    const methods = ["spf", "dkim", "dmarc"];
    const cells = methods.map((method) => {
      const [label, tone] = LABELS.auth[auth[method].result] || LABELS.auth.unknown;
      return el("div", {}, [
        el("dt", { text: method.toUpperCase() }),
        el("dd", { "data-tone": tone, text: label }),
      ]);
    });
    // Kaynak bilgisi ipucunda saklanmaz; her cihazda görünür kısa notlar olarak yazılır.
    const notes = [];
    const sources = [...new Set(methods.map((method) => auth[method].source).filter(Boolean))];
    if (sources.length) notes.push(el("p", { class: "note" }, ["Kaynak: ", el("code", { text: sources.join(", ") }), "."]));
    if (!auth.trusted_authserv_id) {
      notes.push(el("p", { class: "note", text: "Kimlik doğrulama sonuçları okunamadı: sunucu güvenilen başlık kaynağı için ayarlanmamış." }));
    } else {
      const missing = methods.filter((method) => !auth[method].source).map((m) => m.toUpperCase());
      if (missing.length === methods.length) {
        notes.push(el("p", { class: "note", text: `En üstteki Authentication-Results başlığı güvenilen ${auth.trusted_authserv_id} sunucusundan değil ya da yok.` }));
      } else if (missing.length) {
        notes.push(el("p", { class: "note", text: `${auth.trusted_authserv_id} başlığında ${missing.join(", ")} sonucu yok.` }));
      }
    }
    return el("section", { "aria-labelledby": "h-kimlik" }, [
      el("h3", { id: "h-kimlik", text: "Kimlik doğrulama" }),
      el("dl", { class: "auth" }, cells),
      ...notes,
    ]);
  }

  function flagText(flags, labels) {
    return flags.map((flag) => `${labels[flag] || flag}.`).join(" ");
  }

  function renderUrls(urls) {
    const children = [el("h3", { id: "h-url", text: "Bağlantılar" })];
    if (!urls.length) {
      children.push(el("p", { class: "empty-line", text: "Mailde bağlantı yok." }));
    } else {
      children.push(el("dl", { class: "links" }, urls.map((url) => {
        const domain = url.domain || url.host;
        return el("div", {}, [
          el("dt", { text: url.text || "Düz metin bağlantı" }),
          el("dd", {}, [
            el("p", { class: `mono${url.flags.length ? " flagged" : ""}`, text: url.href }),
            el("p", { class: "detail" }, [
              domain ? `Alan adı ${domain}. ` : null,
              url.flags.length ? `${flagText(url.flags, LABELS.urlFlag)} ` : null,
              "İtibar: ",
              stateText(LABELS.reputation, url.reputation),
              ".",
            ]),
          ]),
        ]);
      })));
      if (config && config.demo_mode) children.push(el("p", { class: "note", text: "İtibar sorgulanmadı: demo modunda dış servisler kapalı." }));
    }
    return el("section", { "aria-labelledby": "h-url" }, children);
  }

  function renderAttachments(files) {
    const children = [el("h3", { id: "h-ek", text: files.length > 1 ? `Ekler (${files.length})` : "Ek" })];
    if (!files.length) {
      children.push(el("p", { class: "empty-line", text: "Mailde ek yok." }));
    } else {
      children.push(el("ul", { class: "files" }, files.map((file) => el("li", {}, [
        el("p", { class: `mono${file.flags.length ? " flagged" : ""}`, text: file.filename }),
        el("p", {}, [
          `${file.detected_type} (${file.content_type}), ${formatBytes(file.size)}. `,
          file.flags.length ? `${flagText(file.flags, LABELS.fileFlag)} ` : null,
          "ClamAV: ",
          stateText(LABELS.scan, file.clamav.status),
          ". VirusTotal: ",
          stateText(LABELS.scan, file.virustotal.status),
          ".",
        ]),
      ]))));
    }
    return el("section", { "aria-labelledby": "h-ek" }, children);
  }

  loadConfig();
})();
