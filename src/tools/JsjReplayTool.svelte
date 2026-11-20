<script>
  import ToolShell from "../components/ToolShell.svelte";
  import CopyButton from "../components/CopyButton.svelte";
  import { SmError } from "../lib/sm.js";
  import { buildReplayParams, uuidv4 } from "../lib/jsj.js";
  import { t, onLangChange } from "../lib/i18n.js";

  let s = $state(t());
  onLangChange(() => (s = t()));
  const tool = $derived(s.tools.jsjreplay);
  const p = $derived(s.jsjreplay);

  let publicKey = $state("");
  let timestamp = $state(String(Date.now()));
  let nonce = $state(uuidv4());
  let username = $state("");
  let result = $state(null);
  let error = $state("");

  function errText(e) {
    if (e instanceof SmError) {
      if (e.code === "badTimestamp") return p.badTimestamp;
      if (e.code === "badKey" || e.code === "needPub") return p.badPublicKey;
    }
    return p.failed;
  }

  function run() {
    error = "";
    result = null;
    if (!publicKey.trim()) return;
    try {
      result = buildReplayParams({ publicKey, timestamp, nonce, username });
    } catch (e) {
      error = errText(e);
    }
  }

  function now() {
    timestamp = String(Date.now());
  }

  function newNonce() {
    nonce = uuidv4();
  }

  const query = $derived(result
    ? `timestamp=${result.timestamp}&nonce=${encodeURIComponent(result.nonce)}&sign=${result.signEncoded}`
    : "");
</script>

<ToolShell title={tool.name} desc={tool.desc}>
  <div class="dbx-card">
    <label class="dbx-label" for="jsj-rpub">{p.publicKey} <span class="dim">{p.keyHint}</span></label>
    <textarea id="jsj-rpub" class="dbx-textarea mono" rows="4" bind:value={publicKey} spellcheck="false"></textarea>

    <label class="dbx-label" for="jsj-ts">{p.timestamp}</label>
    <div class="row">
      <input id="jsj-ts" class="dbx-input mono" bind:value={timestamp} spellcheck="false" />
      <button type="button" class="dbx-btn" onclick={now}>{p.now}</button>
    </div>

    <label class="dbx-label" for="jsj-nonce">{p.nonce}</label>
    <div class="row">
      <input id="jsj-nonce" class="dbx-input mono" bind:value={nonce} spellcheck="false" />
      <button type="button" class="dbx-btn" onclick={newNonce}>{p.generate}</button>
    </div>

    <label class="dbx-label" for="jsj-user">{p.username}</label>
    <input id="jsj-user" class="dbx-input mono" bind:value={username} placeholder={p.usernameHint} spellcheck="false" />

    <div class="actions">
      <button type="button" class="dbx-btn dbx-btn--primary" onclick={run} disabled={!publicKey.trim()}>{p.generateSign}</button>
    </div>

    {#if result}
      <div class="head">
        <h2 class="dbx-section-title" style="margin:0">{p.sign}</h2>
        <CopyButton text={result.sign} small />
      </div>
      <textarea class="dbx-textarea mono" rows="3" readonly value={result.sign}></textarea>

      <div class="head">
        <h2 class="dbx-section-title" style="margin:0">{p.signEncoded}</h2>
        <CopyButton text={result.signEncoded} small />
      </div>
      <textarea class="dbx-textarea mono" rows="3" readonly value={result.signEncoded}></textarea>

      <div class="head">
        <h2 class="dbx-section-title" style="margin:0">{p.query}</h2>
        <CopyButton text={query} small />
      </div>
      <textarea class="dbx-textarea mono" rows="3" readonly value={query}></textarea>

      <div class="head">
        <h2 class="dbx-section-title" style="margin:0">{p.payload}</h2>
        <CopyButton text={result.payload} small />
      </div>
      <textarea class="dbx-textarea mono" rows="2" readonly value={result.payload}></textarea>
    {/if}

    <p class="hint">{p.hint}</p>
    {#if error}<p class="err">{error}</p>{/if}
  </div>
</ToolShell>

<style>
  .dbx-card { display: flex; flex-direction: column; gap: 10px; margin-bottom: 14px; }
  .row { display: flex; gap: 8px; align-items: center; }
  .row .dbx-input { flex: 1; }
  .actions { display: flex; align-items: center; gap: 12px; }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .hint { margin: 0; font-size: 12px; color: var(--color-text-secondary, #64748b); }
  .err { color: var(--color-destructive, #dc2626); font-size: 13px; margin: 0; }
</style>
