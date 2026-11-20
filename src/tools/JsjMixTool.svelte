<script>
  import ToolShell from "../components/ToolShell.svelte";
  import CopyButton from "../components/CopyButton.svelte";
  import { SmError } from "../lib/sm.js";
  import { jsjEncrypt, jsjDecrypt } from "../lib/jsj.js";
  import { t, onLangChange } from "../lib/i18n.js";
  import { persistState } from "../lib/persist.svelte.js";

  let s = $state(t());
  onLangChange(() => (s = t()));
  const tool = $derived(s.tools.jsjmix);
  const p = $derived(s.jsjmix);

  let mode = $state("enc"); // "enc" | "dec"
  let publicKey = $state("");
  let privateKey = $state("");
  let plainIn = $state("");
  let eckIn = $state("");
  let encDataIn = $state("");
  let encResult = $state(null);
  let plainOut = $state("");
  let error = $state("");

  function errText(e) {
    if (e instanceof SmError) {
      const map = {
        badKey: p.badKey, needPub: p.badKey, needPriv: p.badKey,
        badPayload: p.badPayload, badEncoding: p.badPayload,
        badPad: p.badPayload, badUtf8: p.badPayload, badIv: p.badPayload,
      };
      return map[e.code] ?? p.failed;
    }
    return p.failed;
  }

  function setMode(next) {
    if (next === mode) return;
    mode = next;
    error = "";
    encResult = null;
    plainOut = "";
  }

  function run() {
    error = "";
    if (mode === "enc") {
      encResult = null;
      if (!plainIn || !publicKey.trim()) return;
      try {
        encResult = jsjEncrypt({ plaintext: plainIn, publicKey });
      } catch (e) {
        error = errText(e);
      }
    } else {
      plainOut = "";
      if (!privateKey.trim() || !eckIn.trim() || !encDataIn.trim()) return;
      try {
        plainOut = jsjDecrypt({ privateKey, eck: eckIn, encData: encDataIn }).plaintext;
      } catch (e) {
        error = errText(e);
      }
    }
  }

  // Keys and payloads stay in memory; only the active mode is persisted.
  persistState("jsjmix", {
    get: () => ({ mode }),
    set: (v) => { mode = v.mode ?? mode; },
  });
</script>

<ToolShell title={tool.name} desc={tool.desc}>
  <div class="dbx-card">
    <div class="seg">
      <button type="button" class="seg-btn" class:active={mode === "enc"} onclick={() => setMode("enc")}>{p.encrypt}</button>
      <button type="button" class="seg-btn" class:active={mode === "dec"} onclick={() => setMode("dec")}>{p.decrypt}</button>
    </div>

    {#if mode === "enc"}
      <label class="dbx-label" for="jsj-mpub">{p.publicKey} <span class="dim">{p.keyHint}</span></label>
      <textarea id="jsj-mpub" class="dbx-textarea mono" rows="4" bind:value={publicKey} spellcheck="false"></textarea>

      <label class="dbx-label" for="jsj-mplain">{p.plain}</label>
      <textarea id="jsj-mplain" class="dbx-textarea mono" rows="5" bind:value={plainIn} placeholder={p.plainHint} spellcheck="false"></textarea>

      <div class="actions">
        <button type="button" class="dbx-btn dbx-btn--primary" onclick={run} disabled={!plainIn || !publicKey.trim()}>{p.encrypt}</button>
      </div>

      {#if encResult}
        <div class="head">
          <h2 class="dbx-section-title" style="margin:0">{p.eck}</h2>
          <CopyButton text={encResult.eck} small />
        </div>
        <textarea class="dbx-textarea mono" rows="3" readonly value={encResult.eck}></textarea>

        <div class="head">
          <h2 class="dbx-section-title" style="margin:0">{p.encData}</h2>
          <CopyButton text={encResult.encData} small />
        </div>
        <textarea class="dbx-textarea mono" rows="2" readonly value={encResult.encData}></textarea>

        <div class="head">
          <h2 class="dbx-section-title" style="margin:0">{p.body}</h2>
          <CopyButton text={encResult.body} small />
        </div>
        <textarea class="dbx-textarea mono" rows="2" readonly value={encResult.body}></textarea>

        <div class="head">
          <h2 class="dbx-section-title" style="margin:0">{p.sm4Key}</h2>
          <CopyButton text={encResult.sm4KeyHex} small />
        </div>
        <textarea class="dbx-textarea mono" rows="1" readonly value={encResult.sm4KeyHex}></textarea>
      {/if}
    {:else}
      <label class="dbx-label" for="jsj-mpriv">{p.privateKey} <span class="dim">{p.keyHint}</span></label>
      <textarea id="jsj-mpriv" class="dbx-textarea mono" rows="4" bind:value={privateKey} spellcheck="false"></textarea>

      <label class="dbx-label" for="jsj-meck">{p.eck}</label>
      <textarea id="jsj-meck" class="dbx-textarea mono" rows="3" bind:value={eckIn} placeholder={p.eckHint} spellcheck="false"></textarea>

      <label class="dbx-label" for="jsj-mdata">{p.encData}</label>
      <textarea id="jsj-mdata" class="dbx-textarea mono" rows="3" bind:value={encDataIn} placeholder={p.encDataHint} spellcheck="false"></textarea>

      <div class="actions">
        <button type="button" class="dbx-btn dbx-btn--primary" onclick={run} disabled={!privateKey.trim() || !eckIn.trim() || !encDataIn.trim()}>{p.decrypt}</button>
      </div>

      {#if plainOut}
        <div class="head">
          <h2 class="dbx-section-title" style="margin:0">{p.plainOut}</h2>
          <CopyButton text={plainOut} small />
        </div>
        <textarea class="dbx-textarea mono" rows="5" readonly value={plainOut}></textarea>
      {/if}
    {/if}

    <p class="hint">{mode === "enc" ? p.encHint : p.decHint}</p>
    {#if error}<p class="err">{error}</p>{/if}
  </div>
</ToolShell>

<style>
  .dbx-card { display: flex; flex-direction: column; gap: 10px; margin-bottom: 14px; }
  .seg { display: flex; border: 1px solid var(--color-border, #e2e8f0); border-radius: 8px; overflow: hidden; width: fit-content; }
  .seg-btn { padding: 6px 16px; font-size: 13px; background: transparent; border: none; color: var(--color-text-secondary, #64748b); cursor: pointer; }
  .seg-btn.active { background: var(--color-primary, #3b82f6); color: #fff; }
  .actions { display: flex; align-items: center; gap: 12px; }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .hint { margin: 0; font-size: 12px; color: var(--color-text-secondary, #64748b); }
  .err { color: var(--color-destructive, #dc2626); font-size: 13px; margin: 0; }
</style>
