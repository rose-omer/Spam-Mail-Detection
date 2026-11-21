// Tema seçimini boyamadan önce uygular (yanıp sönme olmasın). CSP inline betiğe izin vermez.
// data-theme her zaman çözülmüş değeri (light / dark) taşır; CSS yalnız [data-theme="dark"] okur.
// data-theme-pref kullanıcının seçimini (system / light / dark) taşır.
"use strict";
(() => {
  const root = document.documentElement;
  const media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function apply(pref) {
    const choice = pref === "light" || pref === "dark" ? pref : "system";
    root.dataset.themePref = choice;
    root.dataset.theme = choice === "system" ? (media && media.matches ? "dark" : "light") : choice;
  }

  let saved = null;
  try {
    saved = localStorage.getItem("spammaild.theme");
  } catch {
    /* depolama kapalı olabilir: sistem tercihi geçerli */
  }
  apply(saved);
  if (media) {
    media.addEventListener("change", () => {
      if (root.dataset.themePref === "system") apply("system");
    });
  }
  window.spammaildTheme = apply;
})();
