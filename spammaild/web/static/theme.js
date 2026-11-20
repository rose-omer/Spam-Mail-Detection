// Tema seçimini boyamadan önce uygular (yanıp sönme olmasın). CSP inline betiğe izin vermez.
"use strict";
(() => {
  try {
    const saved = localStorage.getItem("spammaild.theme");
    if (saved === "light" || saved === "dark") document.documentElement.dataset.theme = saved;
  } catch {
    /* depolama kapalı olabilir: sistem tercihi geçerli */
  }
})();
