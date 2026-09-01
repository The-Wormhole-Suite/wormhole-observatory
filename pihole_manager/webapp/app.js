const state = {
  token: sessionStorage.getItem("wormholeToken") || "",
  items: [],
  query: "",
  deepLinkDomain: new URLSearchParams(window.location.search).get("domain")?.trim().toLowerCase() || "",
};

const authPanel = document.querySelector("#authPanel");
const reviewPanel = document.querySelector("#reviewPanel");
const authForm = document.querySelector("#authForm");
const tokenInput = document.querySelector("#token");
const authError = document.querySelector("#authError");
const connectionState = document.querySelector("#connectionState");
const reviews = document.querySelector("#reviews");
const summary = document.querySelector("#summary");
const updatedAt = document.querySelector("#updatedAt");
const emptyState = document.querySelector("#emptyState");
const search = document.querySelector("#search");
const detailDialog = document.querySelector("#detailDialog");
const detailDomain = document.querySelector("#detailDomain");
const detailBody = document.querySelector("#detailBody");

function setConnection(label, status) {
  connectionState.textContent = label;
  connectionState.dataset.state = status;
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Authorization", `Bearer ${state.token}`);
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
  let payload = {};
  try {
    payload = await response.json();
  } catch (_error) {
    payload = {};
  }
  if (!response.ok) {
    const error = new Error(payload.message || payload.error || `HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

function cleanText(value, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function tagsFor(item) {
  return Array.isArray(item.tags) ? item.tags.map(String).filter(Boolean) : [];
}

function matches(item) {
  const needle = state.query.trim().toLowerCase();
  if (!needle) return true;
  const haystack = [
    item.domain,
    item.short,
    item.service,
    item.policy,
    item.review_reason,
    ...tagsFor(item),
  ].filter(Boolean).join(" ").toLowerCase();
  return haystack.includes(needle);
}

function cardFor(item) {
  const card = document.createElement("button");
  card.type = "button";
  card.className = "review-card";
  card.addEventListener("click", () => openDetails(item.domain));

  const top = document.createElement("div");
  top.className = "card-top";
  const title = document.createElement("h3");
  title.textContent = cleanText(item.domain);
  const policy = document.createElement("span");
  policy.className = "policy";
  policy.dataset.policy = item.policy || "";
  policy.textContent = cleanText(item.policy, "review");
  top.append(title, policy);

  const description = document.createElement("p");
  description.className = "card-summary";
  description.textContent = cleanText(item.short || item.review_reason, "Awaiting review details");

  const tagBox = document.createElement("div");
  tagBox.className = "tags";
  for (const tag of tagsFor(item).slice(0, 6)) {
    const pill = document.createElement("span");
    pill.className = "tag";
    pill.textContent = tag;
    tagBox.append(pill);
  }

  const footer = document.createElement("div");
  footer.className = "card-footer";
  const service = document.createElement("span");
  service.textContent = cleanText(item.service, "Unknown service");
  const queueState = document.createElement("span");
  queueState.textContent = cleanText(item.queue_state || item.status, "pending");
  footer.append(service, queueState);

  card.append(top, description, tagBox, footer);
  return card;
}

function render() {
  const visible = state.items.filter(matches);
  reviews.replaceChildren(...visible.map(cardFor));
  summary.textContent = `${visible.length} shown · ${state.items.length} loaded`;
  emptyState.hidden = visible.length !== 0;
}

async function loadReviews() {
  setConnection("Loading", "loading");
  authError.textContent = "";
  try {
    await api("/v1/status");
    const payload = await api("/v1/reviews?limit=500");
    state.items = Array.isArray(payload.items) ? payload.items : [];
    authPanel.hidden = true;
    reviewPanel.hidden = false;
    updatedAt.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    setConnection("Connected", "online");
    render();
    if (state.deepLinkDomain) {
      const domain = state.deepLinkDomain;
      state.deepLinkDomain = "";
      await openDetails(domain);
      const clean = new URL(window.location.href);
      clean.searchParams.delete("domain");
      history.replaceState({}, "", `${clean.pathname}${clean.search}${clean.hash}`);
    }
  } catch (error) {
    setConnection(error.status === 401 ? "Locked" : "Offline", "offline");
    if (error.status === 401) {
      state.token = "";
      sessionStorage.removeItem("wormholeToken");
      authPanel.hidden = false;
      reviewPanel.hidden = true;
      authError.textContent = "Authentication failed. Check the API token.";
    } else {
      authError.textContent = `Could not reach Wormhole Observatory: ${error.message}`;
      if (!state.items.length) {
        authPanel.hidden = false;
        reviewPanel.hidden = true;
      }
    }
  }
}

function detailRows(item) {
  const fields = [
    ["Policy", item.policy],
    ["Tags", tagsFor(item).join(", ")],
    ["Service", item.service],
    ["Role", item.service_role],
    ["Summary", item.short],
    ["Details", item.details],
    ["Review reason", item.review_reason],
    ["Privacy risk", item.privacy_risk],
    ["Security risk", item.security_risk],
    ["Breakage risk", item.breakage_risk],
    ["Confidence", item.confidence],
    ["Provider", item.provider],
    ["Queue", item.queue_state || item.status],
  ];
  const list = document.createElement("dl");
  list.className = "detail-body";
  for (const [label, value] of fields) {
    if (value === undefined || value === null || value === "") continue;
    const row = document.createElement("div");
    row.className = "detail-row";
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    detail.textContent = cleanText(value);
    row.append(term, detail);
    list.append(row);
  }
  return list;
}

function decisionButton(label, decision, domain, options = {}) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  if (options.secondary) button.className = "secondary";
  button.addEventListener("click", async () => {
    if (options.confirm && !window.confirm(options.confirm)) return;
    await submitDecision(domain, decision, options.postponeSeconds || 0);
  });
  return button;
}

function decisionControls(domain) {
  const container = document.createElement("div");
  container.className = "detail-actions";

  container.append(
    decisionButton("Allow", "allow", domain),
    decisionButton("Deny", "deny", domain),
    decisionButton("Ignore", "ignore", domain, { secondary: true }),
  );

  const postpone = document.createElement("select");
  postpone.setAttribute("aria-label", "Postpone duration");
  for (const [label, seconds] of [["1 hour", 3600], ["1 day", 86400], ["7 days", 604800]]) {
    const option = document.createElement("option");
    option.value = String(seconds);
    option.textContent = label;
    if (seconds === 86400) option.selected = true;
    postpone.append(option);
  }
  const postponeButton = document.createElement("button");
  postponeButton.type = "button";
  postponeButton.className = "secondary";
  postponeButton.textContent = "Postpone";
  postponeButton.addEventListener("click", async () => {
    await submitDecision(domain, "postpone", Number(postpone.value));
  });
  container.append(postpone, postponeButton);

  container.append(
    decisionButton("Never ask again", "never_ask", domain, {
      secondary: true,
      confirm: `Never ask again about ${domain}? This can be reversed in stored preferences later.`,
    }),
  );
  return container;
}

async function submitDecision(domain, decision, postponeSeconds = 0) {
  const body = { decision };
  if (decision === "postpone") {
    body.postpone_until = Math.floor(Date.now() / 1000) + Math.max(60, postponeSeconds);
  }
  detailBody.dataset.busy = "true";
  try {
    await api(`/v1/reviews/${encodeURIComponent(domain)}/decision`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    detailDialog.close();
    await loadReviews();
  } catch (error) {
    const message = document.createElement("p");
    message.className = "error";
    message.textContent = `Decision failed: ${error.message}`;
    detailBody.prepend(message);
  } finally {
    delete detailBody.dataset.busy;
  }
}

async function openDetails(domain) {
  detailDomain.textContent = domain;
  detailBody.textContent = "Loading…";
  detailDialog.showModal();
  try {
    const payload = await api(`/v1/reviews/${encodeURIComponent(domain)}`);
    const item = payload.item || {};
    detailBody.replaceChildren(detailRows(item), decisionControls(domain));
  } catch (error) {
    detailBody.textContent = `Could not load details: ${error.message}`;
  }
}

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  state.token = tokenInput.value.trim();
  if (!state.token) return;
  sessionStorage.setItem("wormholeToken", state.token);
  tokenInput.value = "";
  await loadReviews();
});

document.querySelector("#refresh").addEventListener("click", loadReviews);
document.querySelector("#disconnect").addEventListener("click", () => {
  state.token = "";
  state.items = [];
  sessionStorage.removeItem("wormholeToken");
  authPanel.hidden = false;
  reviewPanel.hidden = true;
  setConnection("Locked", "locked");
});

search.addEventListener("input", () => {
  state.query = search.value;
  render();
});

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => navigator.serviceWorker.register("/sw.js"));
}

if (state.token) {
  loadReviews();
}
