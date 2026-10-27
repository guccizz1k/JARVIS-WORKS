import { animate, stagger } from "motion";

const pref = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
export function initialize(root = document) {
  const cards = Array.from(root.querySelectorAll("[data-motion-card]"));
  const status = root.querySelector("[data-demo-status]");
  const controls = Array.from(root.querySelectorAll("button.jw-action"));
  if (status) status.textContent = "디자인 시스템 준비 완료";
  for (const button of controls) {
    button.addEventListener("click", () => {
      if (status) status.textContent = "인터랙션 동작 확인 완료";
    });
  }
  if (!cards.length || pref()) {
    window.__jwDesignMotion = { mode: pref() ? "reduced" : "none", cards: cards.length };
    return;
  }
  animate(cards, { opacity: [0.85, 1], y: [10, 0] },
          { duration: 0.24, delay: stagger(0.06), ease: "easeOut" });
  window.__jwDesignMotion = { mode: "motion", cards: cards.length };
}
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => initialize(), { once: true });
} else {
  initialize();
}
