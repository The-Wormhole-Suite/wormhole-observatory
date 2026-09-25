# Desktop capability inventory

This inventory is the Priority 9A baseline for the **one core, two frontends** architecture.

Classification:

- **shared-core** — business/application capability that must be available to Tk and Web through the same service/query boundary.
- **presentation-only** — frontend interaction or rendering behavior with no business decision or durable state of its own.
- **platform-specific** — capability whose implementation depends on the local desktop/host platform and is allowed to diverge when the dependency is documented and tested.

The "current boundary" column records whether the Tk path already uses an application service or still reaches directly into infrastructure/shared modules. It is intentionally an architectural migration map, not a promise that every presentation detail will exist in both frontends.

## Top-level desktop surfaces

| Surface | User-visible capability | Class | Current boundary / migration note |
| --- | --- | --- | --- |
| Global shell | Pi-hole connection health indicator | shared-core | Tk calls Pi-hole service directly; needs a shared health read model. |
| Global shell | Simulation-mode toggle | shared-core | Canonical setting already lives in shared config; mutation should move behind settings service. |
| Global shell | Worker startup/shutdown and background orchestration | shared-core | Shared workers exist, but Tk app owns lifecycle wiring; server lifecycle must use the same orchestration service. |
| Global shell | Automatic provider-registry refresh | shared-core | Shared registry logic exists; scheduling/observability need frontend-neutral service state. |
| Live Queries | Read current Pi-hole queries | shared-core | Tk calls `fetch_queries` directly. |
| Live Queries | Auto-refresh / auto-scroll preferences | presentation-only | Browser/Tk may implement independently. |
| Live Queries | Queue selected domains for review | shared-core | Tk calls database queue function directly; expose queue command service. |
| Live Queries | Whitelist / blacklist exact domains | shared-core | Tk calls Pi-hole mutation directly; move exact-rule mutation behind shared rule service. |
| Live Queries | Column visibility / sorting / context menu | presentation-only | Frontend-only view state. |
| History Browser | Query Pi-hole history with time/domain/client filters | shared-core | Tk calls `fetch_query_page` directly; needs paginated history query service. |
| History Browser | Unclassified-only / deduplicated history view | shared-core | Filtering semantics affect returned read model and must be shared. |
| History Browser | Queue selected/page domains for review | shared-core | Direct database queue path remains. |
| History Browser | Paging controls / visible columns | presentation-only | Frontend-only controls over shared pagination. |
| Lists | Read exact allow/deny lists | shared-core | Tk reads Pi-hole/list state directly. |
| Lists | Add/delete exact domain | shared-core | Direct Pi-hole mutation path remains. |
| Lists | Change allow/deny type | shared-core | Mutation must be shared and audited. |
| Lists | Lock/unlock managed domain | shared-core | Durable policy state; currently direct database/shared-module calls. |
| Lists | Queue selected or complete list for review | shared-core | Direct queue/database path remains. |
| Lists | Search both lists | shared-core | Query semantics should be exposed through shared read model. |
| Lists | Domain details | shared-core | Data is shared; dialog itself is presentation-only. |
| Lists | Column selection / selection state | presentation-only | Frontend-only view state. |
| Regex & Subscriptions | Read regex rules and subscribed lists | shared-core | **Application service exists:** `ManagedRuleApplicationService`. |
| Regex & Subscriptions | Add/update/delete regex rules and subscribed lists | shared-core | **Application service exists:** typed mutation contracts and stable conflicts. |
| Regex & Subscriptions | Enable/disable entries | shared-core | Routed through managed-rule application service. |
| Regex & Subscriptions | Assign groups | shared-core | Group selection dialog is presentation-only; group mutation still needs a shared service boundary. |
| Regex & Subscriptions | Scan rule conflicts | shared-core | Shared conflict scanner exists; expose query service/read model. |
| List Audit | Configure periodic audits | shared-core | Config is shared but Tk writes/worker calls directly. |
| List Audit | Run audit now / read audit status | shared-core | Shared worker exists; needs command/status service. |
| Audit Log | Read Pi-hole audit events | shared-core | Shared audit module exists; expose paginated query service. |
| Audit Log | Roll back selected action | shared-core | Shared rollback logic exists; frontend-neutral rollback command required. |
| Domain Database | Search/filter/paginate domain records | shared-core | Tk reads database directly. |
| Domain Database | Re-analyze selected domains | shared-core | Direct queue/worker path remains. |
| Domain Database | Re-collect / cancel evidence | shared-core | Research/cancellation modules are shared, but orchestration is in Tk callback. |
| Domain Database | Apply planned decision | shared-core | Business mutation must remain behind shared decision/rule services. |
| Domain Database | Whitelist / blacklist exact | shared-core | Direct exact-domain mutation remains. |
| Domain Database | Domain details | shared-core | Data/query must be shared; dialog rendering is presentation-only. |
| Review Queue | Read/filter/sort pending review items | shared-core | Tk reads database directly; needs review queue read model. |
| Review Queue | Analyze selected / full review | shared-core | Worker orchestration is shared but Tk starts jobs directly. |
| Review Queue | Collect / cancel evidence | shared-core | Needs shared job command/status boundary. |
| Review Queue | Apply planned / exact allow/deny | shared-core | Rule/application decisions must use shared services. |
| Review Queue | Dismiss review | shared-core | Durable queue mutation; shared command required. |
| Review Queue | Show evidence / domain details | shared-core | Data/query shared; dialogs presentation-only. |
| Review Queue | Review decisions: allow, deny, postpone, ignore, never ask again | shared-core | **Application service exists:** `ReviewDecisionApplicationService` and adapters. |
| Review Queue | CSV import/export through native file chooser | platform-specific | Data import/export should have shared serialization operations; local chooser remains desktop-specific. |
| Review Queue | Tree sorting / column visibility / toast feedback | presentation-only | Frontend-only interaction. |

## Settings

| Settings page | User-visible capability | Class | Current boundary / migration note |
| --- | --- | --- | --- |
| Pi-hole | Add/remove/select named Pi-hole instances | shared-core | Shared instance model exists; Tk manages it directly. |
| Pi-hole | Edit URL, password, timeout, custom CA bundle | shared-core | Canonical settings must be mutated through shared validation/service layer. |
| Pi-hole | Save, activate and connection-test an instance | shared-core | Connection test exists in shared service; orchestration is Tk-owned. |
| Pi-hole | Manage Pi-hole group assignments | shared-core | Current group-assignment UI talks to shared/Pi-hole modules directly. |
| Automation | Enable analysis worker | shared-core | Shared setting/lifecycle capability. |
| Automation | Collect live-query domains | shared-core | Shared worker setting/lifecycle capability. |
| Automation | Backfill unclassified history | shared-core | Shared worker setting/lifecycle capability. |
| Automation | Require decision-relevant evidence | shared-core | Policy/validation setting must stay canonical. |
| Automation | Select automation mode | shared-core | Canonical policy setting. |
| Automation | Simulation mode | shared-core | Canonical setting; also surfaced in global shell. |
| Automation | Queue/request/recheck limits | shared-core | Canonical operational settings. |
| Automation | Tag policy and recheck-age table | shared-core | Durable policy configuration. |
| LLM Providers | Add/duplicate/remove providers | shared-core | Tk edits config structures directly. |
| LLM Providers | Add provider preset / registry limit profile | shared-core | Shared provider registry/presets exist; mutation service missing. |
| LLM Providers | Discover local LLM servers | shared-core | Shared local-discovery module; command/result service missing. |
| LLM Providers | Edit API style/base URL/API key/model/generation settings | shared-core | Must be canonical settings with secret-safe API representation. |
| LLM Providers | Fetch provider models | shared-core | Shared provider API exists; query/service boundary missing. |
| LLM Providers | View provider health/quota information | shared-core | Shared health data exists; expose secret-free read model. |
| Analysis Pools | Add/edit/remove provider pools and dispatch settings | shared-core | Canonical analysis configuration. |
| Analysis Pools | Benchmark/test pool/provider behavior | shared-core | Shared benchmark/cancellation logic exists; orchestration/status service missing. |
| Prompt Profiles | Add/duplicate/remove profiles | shared-core | Canonical configuration. |
| Prompt Profiles | Edit system/user prompts | shared-core | Canonical configuration. |
| Prompt Profiles | Preview effective prompt | shared-core | Prompt construction is shared and should be available through query/preview service. |
| Evidence Sources | Enable/configure evidence adapters | shared-core | Canonical research-source configuration. |
| Evidence Sources | Test evidence sources and show results | shared-core | Shared adapters exist; test orchestration/read model needed. |
| Application | Theme / tooltip preference | presentation-only | Per-frontend visual preference. |
| Application | Rotating local log-file preference | platform-specific | Host-local operational behavior; server may expose a separate logging policy. |
| Application | Desktop self-update channel/check/download/install | platform-specific | Desktop updater remains local; container update behavior is separate by design. |
| Application | Authenticated external review trigger configuration | shared-core | Server/network capability; should converge with versioned administration/security configuration. |
| Notifications | Local desktop notifications and sound | platform-specific | Desktop-only notification surface. |
| Notifications | Review PWA base URL / push deep-link settings | shared-core | Shared notification configuration. |
| Notifications | ntfy configuration and test push | shared-core | Shared push service exists. |
| Notifications | UnifiedPush/Web Push configuration and test push | shared-core | Shared push service exists; secrets must never be returned by API. |

## Supporting dialogs and desktop-only presentation helpers

| Component | Capability | Class | Note |
| --- | --- | --- | --- |
| `domain_details.py` | Render domain detail view | presentation-only | Domain detail **data** belongs in a shared read model. |
| `evidence_dialog.py` | Render evidence/citation detail | presentation-only | Evidence **data** belongs in shared queries. |
| `group_assignment.py` | Choose groups interactively | presentation-only | Assignment mutation itself is shared-core. |
| `group_assignment_manager.py` | Desktop group-management dialog | presentation-only | Group CRUD/assignment logic must be shared-core. |
| `column_visibility.py` | Per-view visible columns | presentation-only | No cross-frontend parity required. |
| `tree_sorting.py` | Client-side table sorting state | presentation-only | Server queries still need canonical sort semantics where sorting changes result pages. |
| `theme.py`, `tooltips.py`, `feedback.py`, `scrollable.py` | Tk rendering/interaction helpers | presentation-only | Tk-specific. |

## Migration sequence derived from the inventory

The highest-value remaining Priority 9A boundaries are:

1. **Exact-domain mutation + review queue commands** — used by Live Queries, Lists, Domain Database and Review Queue.
2. **Pi-hole/history/domain read models** — remove direct DB/Pi-hole reads from the largest Tk tabs and provide future API contracts.
3. **Settings service** — one canonical validation/mutation path for Pi-hole instances, automation, providers, pools, prompts, evidence and notifications.
4. **Job-control service** — start/observe/cancel/retry analysis, evidence, audits and background work without frontend-owned orchestration.
5. **Audit/rollback and group-management services** — preserve transaction, audit and conflict semantics across Tk and HTTP.

Platform-specific behavior is deliberately kept out of the shared-core target: Tk widgets/dialogs, local desktop notifications, native file choosers, and the desktop self-updater.
