<script>
  import ToolShell from "../components/ToolShell.svelte";
  import CopyButton from "../components/CopyButton.svelte";
  import { SmError, sm2sm4Encrypt, sm2sm4Decrypt } from "../lib/sm.js";
  import { t, onLangChange } from "../lib/i18n.js";
  import { persistState } from "../lib/persist.svelte.js";

  let s = $state(t());
  onLangChange(() => (s = t()));
  const tool = $derived(s.tools.smhybrid);
  const h = $derived(s.smhybrid);

  let mode = $state("enc"); // "enc" | "dec"
  let cipherMode = $state("C1C3C2");
  let fieldEnc = $state("base64");
  let pretty = $state(true);
  let publicKey = $state("");
  let privateKey = $state("");
  let plainIn = $state("");
  let envelopeIn = $state("");
  let envelopeOut = $state("");
  let plainOut = $state("");
  let error = $state("");

  function errText(e) {
    if (e instanceof SmError) {
      const map = {
        badPayload: h.badEnvelope, badEncoding: h.badEnvelope, macMismatch: h.macMismatch,
        badKey: h.badKey, needPub: h.needPub, needPriv: h.needPriv,
        badPad: h.failed, padMultiple: h.failed, badUtf8: h.failed, badIv: h.failed,
        badSignature: h.failed,
      };
      return map[e.code] ?? h.failed;
    }
    return e?.message || h.failed;
  }

  function setMode(next) {
    if (next === mode) return;
    mode = next;
    error = "";
    if (next === "dec" && envelopeOut && !envelopeIn) envelopeIn = envelopeOut;
    if (next === "enc" && plainOut && !plainIn) plainIn = plainOut;
    envelopeOut = "";
    plainOut = "";
  }

  function run() {
    error = "";
    if (mode === "enc") {
      envelopeOut = "";
      if (!plainIn || !publicKey) return;
      try {
        envelopeOut = sm2sm4Encrypt(plainIn, publicKey, { cipherMode, fieldEncoding: fieldEnc, pretty });
      } catch (e) {
        error = errText(e);
      }
    } else {
      plainOut = "";
      if (!envelopeIn || !privateKey) return;
      try {
        plainOut = sm2sm4Decrypt(envelopeIn, privateKey);
      } catch (e) {
        error = errText(e);
      }
    }
  }

  // Keys, plaintext and envelopes stay in memory; only options are persisted.
  persistState("smhybrid", {
    get: () => ({ mode, cipherMode, fieldEnc, pretty }),
    set: (v) => {
      mode = v.mode ?? mode;
      cipherMode = v.cipherMode ?? cipherMode;
      fieldEnc = v.fieldEnc ?? fieldEnc;
      pretty = v.pretty ?? pretty;
    },
  });
</script>

<ToolShell title={tool.name} desc={tool.desc}>
  <div class="dbx-card">
    <div class="seg">
      <button type="button" class="seg-btn" class:active={mode === "enc"} onclick={() => setMode("enc")}>{h.encrypt}</button>
      <button type="button" class="seg-btn" class:active={mode === "dec"} onclick={() => setMode("dec")}>{h.decrypt}</button>
    </div>

    {#if mode === "enc"}
      <label class="dbx-label" for="smh-pub">{h.publicKey} <span class="dim">{h.keyHint}</span></label>
      <textarea id="smh-pub" class="dbx-textarea mono" rows="5" bind:value={publicKey} spellcheck="false"></textarea>
      <label class="dbx-label" for="smh-plain">{h.plain}</label>
      <textarea id="smh-plain" class="dbx-textarea mono" rows="4" bind:value={plainIn} placeholder={h.plainHint} spellcheck="false"></textarea>
      <div class="opts">
        <label>{h.cipherMode}
          <select class="dbx-input narrow" bind:value={cipherMode}>
            <option value="C1C3C2">{h.cmC1C3C2}</option>
            <option value="C1C2C3">{h.cmC1C2C3}</option>
          </select>
        </label>
        <label>{h.fieldEnc}
          <select class="dbx-input narrow" bind:value={fieldEnc}>
            <option value="base64">{h.encBase64}</option>
            <option value="hex">{h.encHex}</option>
          </select>
        </label>
        <label class="check"><input type="checkbox" bind:checked={pretty} />{h.pretty}</label>
      </div>
      <div class="actions">
        <button type="button" class="dbx-btn dbx-btn--primary" onclick={run} disabled={!plainIn || !publicKey}>{h.encrypt}</button>
      </div>
      {#if envelopeOut}
        <div class="head">
          <h2 class="dbx-section-title" style="margin:0">{h.envelope}</h2>
          <CopyButton text={envelopeOut} small />
        </div>
        <textarea class="dbx-textarea mono" rows="12" readonly value={envelopeOut}></textarea>
        <p class="hint">{h.macNote}</p>
      {/if}
    {:else}
      <label class="dbx-label" for="smh-env">{h.envelope}</label>
      <textarea id="smh-env" class="dbx-textarea mono" rows="12" bind:value={envelopeIn} placeholder={h.envelopeHint} spellcheck="false"></textarea>
      <label class="dbx-label" for="smh-priv">{h.privateKey} <span class="dim">{h.keyHint}</span></label>
      <textarea id="smh-priv" class="dbx-textarea mono" rows="5" bind:value={privateKey} spellcheck="false"></textarea>
      <div class="actions">
        <button type="button" class="dbx-btn dbx-btn--primary" onclick={run} disabled={!envelopeIn || !privateKey}>{h.decrypt}</button>
      </div>
      {#if plainOut}
        <div class="head">
          <h2 class="dbx-section-title" style="margin:0">{h.plain}</h2>
          <CopyButton text={plainOut} small />
        </div>
        <textarea class="dbx-textarea mono" rows="5" readonly value={plainOut}></textarea>
      {/if}
    {/if}

    {#if error}<p class="err">{error}</p>{/if}
  </div>
</ToolShell>

<style>
  .dbx-card { display: flex; flex-direction: column; gap: 10px; }
  .seg { display: flex; border: 1px solid var(--color-border, #e2e8f0); border-radius: 8px; overflow: hidden; width: fit-content; }
  .seg-btn { padding: 6px 16px; font-size: 13px; background: transparent; border: none; color: var(--color-text-secondary, #64748b); cursor: pointer; }
  .seg-btn.active { background: var(--color-primary, #3b82f6); color: #fff; }
  .opts { display: flex; gap: 16px; flex-wrap: wrap; align-items: center; }
  .opts label { display: flex; align-items: center; gap: 8px; font-size: 13px; }
  .opts .narrow { width: 120px; }
  .check { display: inline-flex; align-items: center; gap: 6px; }
  .actions { display: flex; }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .hint { margin: 0; font-size: 12px; color: var(--color-text-secondary, #64748b); }
  .dim { font-weight: 400; color: var(--color-text-secondary, #64748b); font-size: 12px; }
  .err { color: var(--color-destructive, #dc2626); font-size: 13px; margin: 0; }
</style>
