const targetDomain = new URLSearchParams(window.location.search)
  .get("domain")
  ?.trim()
  .toLowerCase()
  .replace(/\.$/, "");

if (targetDomain) {
  const reviewPanel = document.querySelector("#reviewPanel");

  const openTarget = () => {
    if (reviewPanel.hidden || typeof window.openDetails !== "function") return false;
    window.openDetails(targetDomain);
    const clean = new URL(window.location.href);
    clean.searchParams.delete("domain");
    history.replaceState({}, "", `${clean.pathname}${clean.search}${clean.hash}`);
    return true;
  };

  if (!openTarget()) {
    const observer = new MutationObserver(() => {
      if (openTarget()) observer.disconnect();
    });
    observer.observe(reviewPanel, { attributes: true, attributeFilter: ["hidden"] });
  }
}
