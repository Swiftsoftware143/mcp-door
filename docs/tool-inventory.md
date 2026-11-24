# Per-product MCP tool inventory

Written 2026-11-24 with the crate in this repo (`mcp-door` v0.1.0). Row counts and column names
below were **measured** on the live databases that day (`information_schema` + `count(*)`), not
copied from a spec. This document is the build order for the port cards: each app's table is what
that lane implements, nothing more.

## The rules every row obeys

1. **The token is the tenancy boundary.** No tool takes a workspace/tenant argument. Cross-workspace
   reads are separate admin-only tools and say so in their description.
2. **A foreign id answers `not_found`, never `forbidden`.** One implementation:
   `Scope::require`.
3. **The tenant filter goes inside the statement** (`Scope::sql_filter`), not in a check above it.
4. **Never project a secret or a credential reference.** No `password_hash`, `*_key`, `*_token`,
   `secret`, `key_hash`, sealed blobs, Stripe ids or payment references. Personal data (a reviewer's
   email, a caller's number) is not returned unless the tool exists to answer "who contacted us".
   Customer-written text is returned as an excerpt and the description says it is untrusted data.
5. **Erasure is not reachable.** No tool names an account: no delete-account, no erase, no plan
   change. The L3 tier (send, refund, plan move, delete) is not exposed on any door in this phase.
6. **Two doors, one audience each.** `/opt/swift/mcp` (:8099, `mcp_reader`, SELECT-only) stays the
   fleet-wide READ hub for operator agents. A product door is the app's OWN machine surface: its
   own key table, its own tenancy, its own audit. Read overlap is expected and intended — same
   tables, different credential and audience.
7. **Tool names carry the app slug** (`funnelswift_list_funnels`) so one agent conversation can
   hold several doors without ambiguity. Exception: CoreSwift's existing custom-object tools keep
   their shipped names (clients already call them).

## Summary

| App | Door | Audience | Credential table (measured columns) | Scope id | Tools (this phase) |
|---|---|---|---|---|---|
| CoreSwift | `/api/mcp` (merged into the app router) | customer | `personal_api_keys` (`tenant_id`, `key_prefix`, `is_active`; sealed with AES-GCM) | `tenant_id` | custom objects (11, **live**) + 12 domain reads |
| FunnelSwift | `/mcp` | customer | `api_keys` (`tenant_id`, `key_prefix`, `revoked_at`) | `tenant_id` | 11 reads |
| IncentiveSwift | `/mcp` | customer | `api_keys` (`tenant_id`, `prefix`, `is_active`) — **key table uses `tenant_id`, data uses `account_id`** | `account_id` | 10 reads |
| WorkflowSwift | `/mcp` | customer | `api_keys` (`aid`, `prefix`, `is_active`) | `aid` | 10 reads |
| ADASwift | `/mcp` | customer | `api_keys` (`tenant_id`, `key_prefix`, `revoked_at`) | `tenant_id` | 8 reads |
| MissedCall Respondr | `/mcp` | customer | `api_keys` (`tenant_id`, `key_prefix`, `revoked_at`) | `tenant_id` | 9 reads |
| Multi-Directory | `/admin/mcp` | **admin only** | `api_keys` (`tenant_id`, `key_prefix`, `is_active`) — tenant id is **not** a directory id | `directory_id` | 9 reads |
| XDispatch | `/admin/mcp` | **admin only** | `machine_keys` (`tenant_id`) + its own resolver | `tenant_id` | 8 reads |
| Engine | `/mcp` (re-based on the crate) | **admin only** (David's 9 workspaces) | `api_tokens` (`workspace_id`, sealed) — **already live** | `workspace_id` | 22 existing + 1 admin |
| Studio | `/admin/mcp` | **admin only** | no key table today — the port adds one single-purpose `door_tokens` row (sha256 hash, label, `revoked_at`); a session cookie is not an API credential | n/a (single store) | 6 reads |

Verified-live row counts are quoted per app to justify each tool and to tell a real zero from a
broken filter ("the table exists and holds 4 rows" vs "the table is empty fleet-wide").

---

## CoreSwift — customer app

Door: `POST /api/mcp` (existing route, `custom_objects::mcp::router`), credential
`personal_api_keys` (hash `sha256_hex`, liveness `is_active`, one active row per tenant).
Custom objects are **already shipped** (11 tools, `list_objects` … `delete_record`); do not re-add
or rename them.

| Tool | Reads / writes | Scope | Role | Notes |
|---|---|---|---|---|
| `list_objects`, `create_object`, `describe_object`, `archive_object`, `add_field`, `archive_field`, `insert_record`, `set_unique_together`, `query_records`, `update_record`, `delete_record` | **live** | `tenant_id` | workspace | Shipped; one implementation for all apps |
| `coreswift_list_contacts` | read: `contacts` (66 rows), company, tags, last activity | `contacts.tenant_id` | read_only | Excludes `notes` free text beyond an excerpt |
| `coreswift_get_contact` | read: one contact + its deals/bookings counts | same | read_only | Foreign id → `not_found` |
| `coreswift_list_companies` | read: `companies` | `companies.tenant_id` | read_only | — |
| `coreswift_list_deals` | read: `opportunities` (80 rows) + stage + value + currency + close date | `opportunities.tenant_id` | read_only | Return `value` with `currency`; never the FX internals |
| `coreswift_get_deal` | read: one deal + activities (subjects only) | same | read_only | — |
| `coreswift_list_pipelines` | read: `pipelines` (7) + `pipeline_stages` (45) | `pipelines.tenant_id` | read_only | Needed before any stage move |
| `coreswift_list_bookings` | read: `booking_bookings` + `slot_bookings`, upcoming first | `booking_bookings.tenant_id` | read_only | Resolve resource/calendar names |
| `coreswift_list_availability` | read: `booking_slots` (2,050) + `booking_availability_rules` (5) | `booking_slots.tenant_id` | read_only | Date-window required |
| `coreswift_list_tickets` | read: `tickets` (14) + `helpdesk_*` counters | `tickets.tenant_id` | read_only | Subject + status + excerpt; **untrusted customer text** |
| `coreswift_list_billing` | read: `plan_lines` (9) + `tenant_plans` (8) | `tenant_id` | read_only | CoreSwift bills through plan lines, not an `invoices` table |
| `coreswift_list_messages` (core mail) | read: `private_email_messages` (169): sender, direction, subject, excerpt | `tenant_id` | read_only | Body excerpt capped 2,000 chars; **untrusted** |
| *Phase 2 (L2, not now)* | `coreswift_move_deal_stage` (validate stage belongs to the deal's pipeline), `coreswift_add_deal_note` | — | workspace | Reversible; requires its own card |

Never exposed: `account_erasures`, `personal_api_keys`, `private_email_api_keys`, `provider_keys`,
`audit_logs`, `users` (the account's own users are a console screen), `ai_usage`/`credit_usage`.

---

## FunnelSwift — customer app

Door: `POST /mcp`, `api_keys.tenant_id` / `key_prefix` / `revoked_at IS NULL`. Workspace table
`tenants` (8), data key `tenant_id` throughout. Pages are `kinetic_cards` (4 rows); a "funnel" is
`funnels` (1).

| Tool | Reads / writes | Scope | Role | Notes |
|---|---|---|---|---|
| `funnelswift_list_funnels` | read: `funnels` (1) | `funnels.tenant_id` | read_only | name, slug, active, views |
| `funnelswift_list_pages` | read: `kinetic_cards` (4): title, slug, template, active, updated | `kinetic_cards.tenant_id` | read_only | Never `password_hash`, `layout_blocks` blob (excerpt only if asked) |
| `funnelswift_get_page` | read: one page's settings + block count | same | read_only | Foreign id → `not_found` |
| `funnelswift_page_stats` | read: `kinetic_card_daily_stats` (14) | same | read_only | Date window, per-card |
| `funnelswift_list_leads` | read: `leads` + stage/score/source | `leads.tenant_id` | read_only | Personal data limited to name/email/phone the tenant owns |
| `funnelswift_lead_events` | read: `lead_events` (182) | `lead_events.tenant_id` | read_only | Event name + timestamp + page |
| `funnelswift_list_form_submissions` | read: `web_to_lead_logs` | `tenant_id` | read_only | **0 rows fleet-wide** — a zero here is real, say so |
| `funnelswift_list_tags` | read: `tags` (10) + `tag_groups` | `tags.tenant_id` | read_only | — |
| `funnelswift_list_email_domains` | read: `private_email_domains` (25) — sending domains | `tenant_id` | read_only | Never the DKIM private key |
| `funnelswift_list_invoices` | read: `invoices` (8) | `invoices.tenant_id` | read_only | Amount + status + currency; no payment references |
| `funnelswift_list_affiliate_products` | read: `affiliate_products` (20) + rate bands | `tenant_id` | read_only | Commission rate is the account's own data |
| *Phase 2 (L2)* | `funnelswift_set_lead_stage`, `funnelswift_tag_lead` | — | workspace | Reversible; own card |

Never exposed: `api_keys`, `webhooks.secret`, `webhook_delivery_log` payload headers, `provider_keys`,
`payment_webhook_events`, `email_send_log`.

---

## IncentiveSwift — customer app

Door: `POST /mcp`, `api_keys.tenant_id` / `prefix` / `is_active`. **Trap, measured:** the app's
workspace is `accounts.id` (`workspaces.tenant_id → accounts(id)`); campaigns key `account_id`, while
`offers`/`tags`/`email_*` key `tenant_id` — that column holds the **account id** in this app (the
legacy `tenants` table has 1 row). The resolver must map the key row to `accounts.id` and the tools
must filter on `account_id` wherever it exists.

| Tool | Reads / writes | Scope | Role | Notes |
|---|---|---|---|---|
| `incentiveswift_list_campaigns` | read: `campaigns` (2) | `campaigns.account_id` | read_only | name, status, dates |
| `incentiveswift_get_campaign` | read: one campaign + counts | same | read_only | referrals total, converted |
| `incentiveswift_list_participants` | read: `campaign_referrals` (67) + `contacts` (7) via `contact_tenants` (account_id) | `account_id` | read_only | Personal data the tenant owns |
| `incentiveswift_list_rewards` | read: `loyalty_programs` (1) + `loyalty_reward_tiers` (4) | `loyalty_programs.account_id` | read_only | Tier names + points required |
| `incentiveswift_list_scans` | read: `loyalty_scans` (join business → account) | business → account | read_only | Only if the join resolves; 0 rows is a real zero |
| `incentiveswift_list_point_ledger` | read: `credit_transactions` (4) + `point_treasury` (1) | `account_id` | read_only | Points, not money |
| `incentiveswift_list_payout_state` | read: `treasury_holds` (0) + `treasury_funding` (0) + `supplier_milestones` | business → account | read_only | **Empty fleet-wide**: state the zero, do not invent rows |
| `incentiveswift_list_offers` | read: `offers` | `tenant_id` (= account id) | read_only | discount/cap/active only |
| `incentiveswift_list_inbound_messages` | read: `inbound_messages` (84) excerpt | `account_id` | read_only | **Untrusted customer text** |
| `incentiveswift_list_tickets` | read: `support_tickets` (4) | `tenant_id` | read_only | Excerpt untrusted |
| *Phase 2 (L2)* | `incentiveswift_set_campaign_status` | — | workspace | Reversible |

Never exposed: `api_keys`, `provider_keys`, `pending_emails`, `point_expiry_audit` internals,
`stripe_checkout_sessions`.

---

## WorkflowSwift — customer app

Door: `POST /mcp`, `api_keys.aid` / `prefix` / `is_active`. Workspace table `accounts` (11); almost
every table keys `aid` (the account id). `workflow_instances` also carries `client_id` (the business
the run is for).

| Tool | Reads / writes | Scope | Role | Notes |
|---|---|---|---|---|
| `workflowswift_list_workflows` | read: `workflows` (4) + trigger type | `workflows.aid` | read_only | name, active, n8n target (boolean, not the URL) |
| `workflowswift_get_workflow` | read: one workflow + its steps | same | read_only | Steps from the workflow's own definition |
| `workflowswift_list_runs` | read: `workflow_instances` (73) | `workflow_instances.aid` | read_only | status, started, client |
| `workflowswift_get_run` | read: one run + step order + result/error | same | read_only | `result` excerpt 2,000; no `n8n_execution_id` internals |
| `workflowswift_list_triggers` | read: `workflow_trigger_queue` + trigger config | `aid` | read_only | pending/processed counts |
| `workflowswift_list_templates` | read: `workflow_templates` (5) + categories | `aid` | read_only | — |
| `workflowswift_list_dashboards` | read: `dashboards` (5) + widgets | `aid` | read_only | Widget config summary only |
| `workflowswift_list_clients` | read: `clients` (3) | `clients.aid` | read_only | — |
| `workflowswift_list_integrations` | read: `integration_destinations` (17) | `aid` | read_only | Destination name + status; never the stored credential |
| `workflowswift_list_invoices` | read: `invoices` (3) | `invoices.aid` | read_only | No payment refs |
| *Phase 2 (L2)* | `workflowswift_start_run`, `workflowswift_pause_workflow` | — | workspace | A start spends credits: needs its own card + cap |

Never exposed: `api_keys`, `user_api_keys`, `n8n_account_config`, `provider_keys`, `webhooks`,
`credit_transactions` internals.

---

## ADASwift — customer app

Door: `POST /mcp`, `api_keys.tenant_id` / `key_prefix` / `revoked_at IS NULL`. Scans hang off
`client_scan_settings.client_id` and reports off `scan_reports.client_id`; `clients.tenant_id` is the
workspace link.

| Tool | Reads / writes | Scope | Role | Notes |
|---|---|---|---|---|
| `adaswift_list_websites` | read: `websites` (2) | `websites.tenant_id` | read_only | domain, compliance status, widget active |
| `adaswift_list_scans` | read: `scan_queue` (24) | `scan_queue.tenant_id` | read_only | status, domain, queued/completed |
| `adaswift_list_reports` | read: `scan_reports` (join `clients`) | `clients.tenant_id` | read_only | score, error/warning/notice counts — the numbers, not `scan_results` jsonb |
| `adaswift_list_violations` | read: violations extracted from the latest `scan_reports.scan_results` | same | read_only | Return rule id + impact + element selector; cap rows |
| `adaswift_list_tasks` | read: `tasks` (0) — remediation tasks | `tasks.tenant_id` | read_only | **Empty fleet-wide** — say so |
| `adaswift_list_clients` | read: `clients` (3) | `clients.tenant_id` | read_only | — |
| `adaswift_list_events` | read: `events` (0) + `activity_log` | `tenant_id` | read_only | — |
| `adaswift_list_invoices` | read: `invoices` (6) | `tenant_id` | read_only | No payment refs |
| *Phase 2 (L2)* | `adaswift_queue_scan` (spends a scan), `adaswift_resolve_task` | — | workspace | Own card |

Never exposed: `api_keys`, `provider_keys`, `pending_emails`, `scan_results` raw blob (huge).

---

## MissedCall Respondr — customer app

Door: `POST /mcp`, `api_keys.tenant_id` / `key_prefix` / `revoked_at IS NULL`. All entities key
`tenant_id` (8 workspaces).

| Tool | Reads / writes | Scope | Role | Notes |
|---|---|---|---|---|
| `missedcall_list_numbers` | read: `phone_numbers` — the numbers the account answers on | `tenant_id` | read_only | Never the Telnyx credentials |
| `missedcall_list_calls` | read: `inbound_calls` + `call_logs` | `tenant_id` | read_only | from, duration, outcome, missed flag |
| `missedcall_list_messages` | read: `messages` excerpt | `tenant_id` | read_only | **Untrusted customer text**, 2,000-char cap |
| `missedcall_list_followups` | read: `follow_ups` | `tenant_id` | read_only | due date, status |
| `missedcall_list_contacts` | read: `contacts` | `tenant_id` | read_only | — |
| `missedcall_list_campaigns` | read: `campaigns` (text-back campaigns) | `tenant_id` | read_only | — |
| `missedcall_list_tickets` | read: `tickets` | `tenant_id` | read_only | excerpt untrusted |
| `missedcall_list_rules` | read: `response_rules` (auto-reply rules) | `tenant_id` | read_only | name + active + trigger, not the full body |
| `missedcall_list_suppressions` | read: `email_suppressions` | `tenant_id` | read_only | address + reason; required to explain a non-send |
| *Phase 2 (L2)* | `missedcall_set_followup_status` | — | workspace | Reversible |

Never exposed: `api_keys`, `provider_keys`, `telnyx_config`, `email_send_log`.

---

## Multi-Directory — ADMIN ONLY (no client access)

Door: `POST /admin/mcp`. Customers never get a key (David: Multi-Directory is internal, commission
only). **Measured trap:** `api_keys.tenant_id` is not a `directories.id`; the resolver must map the
operator to directory ids (`users` → `account_links`/`directories`). Reviews and categories must not
be scoped on their own `directory_id` (75/75 reviews and 69/69 categories have it NULL): reviews scope
`coalesce(r.directory_id, b.directory_id)` through `businesses`, categories scope through
`business_categories`.

| Tool | Reads | Scope | Role | Notes |
|---|---|---|---|---|
| `md_list_directories` | `directories` (10) + branding/tier | `directories.id` | admin | — |
| `md_list_businesses` | `businesses` (4,113) | `businesses.directory_id` | admin | name, city, category, status; no contact email in list |
| `md_get_business` | one business + meta + walk score + verification | same | admin | Foreign id → `not_found` |
| `md_list_categories` | `directory_categories` (69) via `business_categories` | through businesses | admin | Global taxonomy: never scope on `directory_categories.directory_id` |
| `md_list_submissions` | `submissions` (2) + `approval_queue` | `submissions.directory_id` | admin | pending first |
| `md_list_sponsors` | `sponsors` + `sponsored_listings` (1) + `ad_zones` (60) | `sponsors.directory_id` / zone | admin | Never `external_payment_ref` |
| `md_list_ad_schedules` | `ad_schedules` + `ad_earnings` | `ad_schedules.directory_id` | admin | dates, price, status |
| `md_list_reviews` | `reviews` (75) | `coalesce(r.directory_id, b.directory_id)` | admin | excerpt; **untrusted**; never `reviewer_email` |
| `md_list_seo_submissions` | `seo_submission_urls` (4,547) + log (273) | through directory | admin | index status counts |
| *Phase 2 (L2)* | `md_approve_submission`, `md_set_business_status` | — | admin | Own card |

Never exposed: `api_keys`, `provider_keys`, `impersonation_sessions`, `google_places_cache`,
`visitor_*` raw events (analytics only in aggregate).

---

## XDispatch — ADMIN ONLY (Giraudy Capital operates it via MCP)

Door: `POST /admin/mcp` (separate from the `/dispatch` console). **Live keys are real consumers:**
`/home/bot-giraudy/.hermes/xdispatch-api.env` holds a super-admin key (read-only across companies) and
the Xride Drivers company key (read + write) — card `t_545154c2` closed; two connections only, and
`platform` must never mint a third. XDispatch's existing `machine.rs` resolver stays the credential
authority; the door reuses it. Scope `tenant_id` (1 tenant today).

| Tool | Reads | Scope | Role | Notes |
|---|---|---|---|---|
| `xd_list_companies` | `tenants` (1) + `tenant_settings` | all (super admin) | admin | Company identity only |
| `xd_list_drivers` | `drivers` (3) + `vehicles` + `driver_shifts` (8) | `tenant_id` | admin | **Never `password_hash`**, never `online` location history |
| `xd_list_jobs` | `jobs` (2) | `tenant_id` | admin | reference, status, window, price, invoice state |
| `xd_get_job` | one job + stops + POD | same | admin | Foreign id → `not_found` |
| `xd_list_quotes` | `quotes` (1) | `tenant_id` | admin | status, expires, price; never `public_token` |
| `xd_list_invoices` | `invoices` + `invoice_lines` | `tenant_id` | admin | totals + status; no `sent_pdf_sha256` |
| `xd_list_payments` | `payments` | `tenant_id` | admin | amount + status; no provider reference |
| `xd_list_notifications` | `notification_log` (328) | `tenant_id` | admin | kind + delivery state; no message bodies with personal data |
| *Phase 2* | writes stay in the existing machine route; the door adds none | — | — | Company-key writes are already shipped there |

Never exposed: `machine_keys`, `provider_credentials`, `client_portal_tokens`, `dispatch_sessions`.

---

## Engine — ADMIN ONLY (David's 9 workspaces)

Engine **already ships** `POST /mcp` (928 LOC, 22 tools, per-workspace token, verified 2026-11-23:
rule fired via `/rt/v1/content`, `rank_offers` arithmetic, `embed.js` injection). The port is not a
rewrite: replace the hand-rolled auth/transport/registry with the crate, keep all 22 tool behaviours,
and add the one admin tool. Scope `workspace_id`; credential `api_tokens` (9 sealed tokens in
`/opt/swift/secure/engine-mcp-tokens.env`).

| Tool | Reads / writes | Scope | Role | Notes |
|---|---|---|---|---|
| existing 22 (`engine_whoami`, `list_rules`, `get_rule`, `create_rule`, `update_rule`, `set_rule_status`, `decide_content`, `list_offers`, `list_giveaways`, `create_offer`, `set_offer_status`, `rank_offers`, `analytics`, `list_audiences`, `create_audience`, `list_integrations`, `pm_*` ×5) | **live** | `workspace_id` | workspace | Keep names; the crate supplies transport, 401/404 and audit |
| `engine_list_workspaces` | read: `workspaces` (9) + counts | all | admin | Replaces the console-only view; operator only |
| *Human-only, never a tool* | giveaway approval | — | — | No approve tool exists and none may be added |

Traps to keep: media is stored as `bytea` — `media_assets` returns metadata and the door's own asset
URL, never the bytes; `pm_render` is expensive — keep its timeout and row cap.

---

## Studio — ADMIN ONLY (no customer access)

**Correction to the card, measured 2026-11-24:** Studio is **not** databaseless. It owns
`/opt/swift/studio/data/studio.db` (SQLite, 14 tables: `assets` 5, `publish_workspaces` 14,
`publish_events` 2, `staged` 1, `sessions` 63, `users` 1, plus `api_quota`, `posts`, `twitter_queue`,
`engine_heartbeat`, `plan_events`, `platform_accounts`, `post_media_links`). The storage decision is
therefore: **keep SQLite; no migration for read tools.** The door runs in the Studio process and
uses its existing `rusqlite` handle on the blocking pool. If Studio ever moves to Postgres only the
tool handlers change — the crate is untouched.

| Tool | Reads | Scope | Role | Notes |
|---|---|---|---|---|
| `studio_list_assets` | `assets` + `post_media_links` | all (single store) | admin | filename, mime, bytes, tags; never the file bytes |
| `studio_list_publish_targets` | `publish_workspaces` (14) | all | admin | workspace + host + active |
| `studio_publish_status` | `publish_events` (2) + `engine_heartbeat` | all | admin | last result + timestamp |
| `studio_list_pages` | served pages (static, `include_str!`) with a content hash | all | admin | Reads the served root, so a stale copy is visible |
| `studio_list_posts` | `posts`, `twitter_queue`, `staged` | all | admin | queued/scheduled/done counts |
| `studio_list_sessions` | `sessions` count only | all | admin | Never the session token or the user row |
| *Phase 2* | publish is **not** a tool: it stays the console's `approved`-status action | — | — | A tool that publishes is L3 |

---

## Port order

1. **CoreSwift domain reads** (extends the live door; custom objects untouched).
2. **WorkflowSwift + MissedCall + ADASwift** (small, single-key-column apps; `aid`/`tenant_id`).
3. **FunnelSwift + IncentiveSwift** (IncentiveSwift needs the `account_id` mapping resolved first).
4. **Engine re-base** (behaviour-preserving; the only port that removes hand-rolled auth).
5. **Multi-Directory, XDispatch, Studio** (admin-only; each has its own id-space trap named above).

Each port is its own card in that app's lane, carries this table as its spec, and is done only when
`cargo test` (crate contract) **and** `scripts/door-contract.py` **and** the app-specific calls
(foreign id → `not_found`, second workspace blind, audit line present without the token) pass against
the live endpoint.
