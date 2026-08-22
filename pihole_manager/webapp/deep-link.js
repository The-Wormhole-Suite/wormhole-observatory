const targetDomain = new URLSearchParams(window.location.search).get("domain")?.trim().toLowerCase();

if (targetDomain) {
  const reviewGrid = document.querySelector("#reviews");
  const observer = new MutationObserver(() => {
    const cards = [...reviewGrid.querySelectorAll(".review-card")];
    const match = cards.find((card) => {
      const title = card.querySelector("h3")?.textContent?.trim().toLowerCase();
      return title === targetDomain;
    });
    if (!match) return;
    observer.disconnect();
    match.click();
    const clean = new URL(window.location.href);
    clean.searchParams.delete("domain");
    history.replaceState({}, "", `${clean.pathname}${clean.search}${clean.hash}`);
  });
  observer.observe(reviewGrid, { childList: true });
}
