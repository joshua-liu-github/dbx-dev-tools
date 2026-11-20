<script>
  import ToolShell from "../components/ToolShell.svelte";
  import CopyButton from "../components/CopyButton.svelte";
  import { SmError } from "../lib/sm.js";
  import { buildSmToken } from "../lib/jsj.js";
  import { t, onLangChange } from "../lib/i18n.js";
  import { persistState } from "../lib/persist.svelte.js";

  let s = $state(t());
  onLangChange(() => (s = t()));
  const tool = $derived(s.tools.jsjsign);
  const p = $derived(s.jsjsign);

  let method = $state("POST");
  let url = $state("");
  let params = $state("");
  let body = $state("");
  let result = $state(null);
  let error = $state("");

  function errText(e) {
    if (e instanceof SmError) {
      if (e.code === "badUrl") return p.badUrl;
      if (e.code === "badParams") return p.badParams;
    }
    return p.failed;
  }

  function run() {
    error = "";
    result = null;
    if (!url.trim()) return;
    try {
      result = buildSmToken({ method, url, params, body });
    } catch (e) {
      error = errText(e);
    }
  }

  // The request itself is transient; only the method is remembered.
  persistState("jsjsign", {
    get: () => ({ method }),
    set: (v) => { method = v.method ?? method; },
  });
</script>

<ToolShell title={tool.name} desc={tool.desc}>
  <div class="dbx-card">
    <div class="opts">
      <label>{p.method}
        <select class="dbx-input narrow" bind:value={method}>
          <option value="POST">POST</option>
          <option value="GET">GET</option>
        </select>
      </label>
    </div>

    <label class="dbx-label" for="jsj-url">{p.url}</label>
    <input id="jsj-url" class="dbx-input mono" bind:value={url} placeholder={p.urlHint} spellcheck="false" />

    <label class="dbx-label" for="jsj-params">{p.params}</label>
    <textarea id="jsj-params" class="dbx-textarea mono" rows="4" bind:value={params} placeholder={p.paramsHint} spellcheck="false"></textarea>

    {#if method !== "GET"}
      <label class="dbx-label" for="jsj-body">{p.body}</label>
      <textarea id="jsj-body" class="dbx-textarea mono" rows="5" bind:value={body} placeholder={p.bodyHint} spellcheck="false"></textarea>
    {/if}

    <div class="actions">
      <button type="button" class="dbx-btn dbx-btn--primary" onclick={run} disabled={!url.trim()}>{p.generate}</button>
    </div>

    {#if result}
      <div class="head">
        <h2 class="dbx-section-title" style="margin:0">{p.signature}</h2>
        <CopyButton text={result.sign} small />
      </div>
      <textarea class="dbx-textarea mono" rows="2" readonly value={result.sign}></textarea>

      <div class="head">
        <h2 class="dbx-section-title" style="margin:0">{p.header}</h2>
        <CopyButton text={`Sm-Token: ${result.sign}`} small />
      </div>
      <textarea class="dbx-textarea mono" rows="2" readonly value={`Sm-Token: ${result.sign}`}></textarea>

      <div class="head">
        <h2 class="dbx-section-title" style="margin:0">{p.canonical}</h2>
        <CopyButton text={result.canonical} small />
      </div>
      <textarea class="dbx-textarea mono" rows="4" readonly value={result.canonical}></textarea>
    {/if}

    <p class="hint">{p.hint}</p>
    {#if error}<p class="err">{error}</p>{/if}
  </div>
</ToolShell>

<style>
  .dbx-card { display: flex; flex-direction: column; gap: 10px; margin-bottom: 14px; }
  .opts { display: flex; gap: 16px; flex-wrap: wrap; }
  .opts label { display: flex; align-items: center; gap: 8px; font-size: 13px; }
  .narrow { width: 120px; flex: none; }
  .actions { display: flex; align-items: center; gap: 12px; }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .hint { margin: 0; font-size: 12px; color: var(--color-text-secondary, #64748b); }
  .err { color: var(--color-destructive, #dc2626); font-size: 13px; margin: 0; }
</style>
