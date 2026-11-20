<script>
  import ToolShell from "../components/ToolShell.svelte";
  import CopyButton from "../components/CopyButton.svelte";
  import {
    PbeError, pbeEncrypt, pbeDecrypt, randomSaltHex,
    hexToBytes, bytesToHex, b64ToBytes, bytesToB64,
  } from "../lib/pbe.js";
  import { t, onLangChange } from "../lib/i18n.js";
  import { persistState } from "../lib/persist.svelte.js";

  let s = $state(t());
  onLangChange(() => (s = t()));
  const tool = $derived(s.tools.pbe);
  const p = $derived(s.pbe);

  let mode = $state("enc"); // "enc" | "dec"
  let password = $state("");
  let passwordMode = $state("java"); // "java" | "utf8"
  let salt = $state(randomSaltHex());
  let saltEnc = $state("hex"); // "hex" | "base64"
  let iterations = $state(1000);
  let ctEnc = $state("hex"); // "hex" | "base64"
  let encIn = $state("");
  let decIn = $state("");
  let output = $state("");
  let error = $state("");

  const input = $derived(mode === "enc" ? encIn : decIn);

  function errText(e) {
    if (e instanceof PbeError) {
      return {
        badEncoding: p.badEncoding, badSalt: p.badSalt, badIterations: p.badIterations,
        badCipher: p.badCipher, badPad: p.badPad, badUtf8: p.badUtf8,
      }[e.code] ?? p.failed;
    }
    return p.failed;
  }

  function setMode(next) {
    if (next === mode) return;
    mode = next;
    error = "";
    if (!output) return;
    if (next === "enc" && !encIn) encIn = output;
    else if (next === "dec" && !decIn) decIn = output;
  }

  function saltBytes(text, encoding) {
    return encoding === "base64" ? b64ToBytes(text) : hexToBytes(text);
  }

  function changeSaltEnc(next) {
    if (next === saltEnc) return;
    try {
      const bytes = saltBytes(salt, saltEnc);
      salt = next === "base64" ? bytesToB64(bytes) : bytesToHex(bytes);
    } catch {
      // Keep the raw text; the next run reports the invalid encoding.
    }
    saltEnc = next;
  }

  function generateSalt() {
    const hex = randomSaltHex();
    salt = saltEnc === "base64" ? bytesToB64(hexToBytes(hex)) : hex;
  }

  function run() {
    error = "";
    output = "";
    if (!input || !password) return;
    try {
      output = mode === "enc"
        ? pbeEncrypt(input, password, salt, Number(iterations), {
          passwordMode, saltEncoding: saltEnc, outEncoding: ctEnc,
        })
        : pbeDecrypt(input, password, salt, Number(iterations), {
          passwordMode, saltEncoding: saltEnc, inEncoding: ctEnc,
        });
    } catch (e) {
      error = errText(e);
    }
  }

  // Password, plaintext and ciphertext are secrets — only options and the
  // (non-secret) salt are remembered.
  persistState("pbe", {
    get: () => ({ mode, passwordMode, salt, saltEnc, iterations, ctEnc }),
    set: (v) => {
      mode = v.mode ?? mode;
      passwordMode = v.passwordMode ?? passwordMode;
      salt = v.salt ?? salt;
      saltEnc = v.saltEnc ?? saltEnc;
      iterations = v.iterations ?? iterations;
      ctEnc = v.ctEnc ?? ctEnc;
    },
  });
</script>

<ToolShell title={tool.name} desc={tool.desc}>
  <div class="dbx-card">
    <div class="seg">
      <button type="button" class="seg-btn" class:active={mode === "enc"} onclick={() => setMode("enc")}>{p.encrypt}</button>
      <button type="button" class="seg-btn" class:active={mode === "dec"} onclick={() => setMode("dec")}>{p.decrypt}</button>
    </div>

    <label class="dbx-label" for="pbe-pwd">{p.password}</label>
    <div class="keyrow">
      <input id="pbe-pwd" class="dbx-input mono" type="password" bind:value={password} spellcheck="false" autocomplete="off" />
      <label class="inline-opt">{p.passwordMode}
        <select class="dbx-input narrow" bind:value={passwordMode}>
          <option value="java">{p.pwdJava}</option>
          <option value="utf8">{p.pwdUtf8}</option>
        </select>
      </label>
    </div>
    <p class="hint">{p.pwdModeHint}</p>

    <label class="dbx-label" for="pbe-salt">{p.salt}</label>
    <div class="keyrow">
      <input id="pbe-salt" class="dbx-input mono" bind:value={salt} spellcheck="false" />
      <select class="dbx-input narrow" value={saltEnc} onchange={(e) => changeSaltEnc(e.currentTarget.value)}>
        <option value="hex">{p.hex}</option>
        <option value="base64">{p.base64}</option>
      </select>
      <button type="button" class="dbx-btn" onclick={generateSalt}>{p.generate}</button>
    </div>

    <div class="opts">
      <label>{p.iterations}
        <input class="dbx-input narrow" type="number" min="1" step="1" bind:value={iterations} />
      </label>
      <label>{p.cipherEncoding}
        <select class="dbx-input narrow" bind:value={ctEnc}>
          <option value="hex">{p.hex}</option>
          <option value="base64">{p.base64}</option>
        </select>
      </label>
    </div>

    <label class="dbx-label" for="pbe-in">{mode === "enc" ? p.plain : p.cipher}</label>
    {#if mode === "enc"}
      <textarea id="pbe-in" class="dbx-textarea mono" rows="5" bind:value={encIn} placeholder={p.plainHint} spellcheck="false"></textarea>
    {:else}
      <textarea id="pbe-in" class="dbx-textarea mono" rows="5" bind:value={decIn} placeholder={p.cipherHint} spellcheck="false"></textarea>
    {/if}

    <div class="actions">
      <button type="button" class="dbx-btn dbx-btn--primary" onclick={run} disabled={!input || !password}>
        {mode === "enc" ? p.encrypt : p.decrypt}
      </button>
    </div>

    {#if output}
      <div class="head">
        <h2 class="dbx-section-title" style="margin:0">{mode === "enc" ? p.cipher : p.plain}</h2>
        <CopyButton text={output} small />
      </div>
      <textarea class="dbx-textarea mono" rows="5" readonly value={output}></textarea>
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
  .opts { display: flex; gap: 16px; flex-wrap: wrap; }
  .opts label { display: flex; align-items: center; gap: 8px; font-size: 13px; }
  .inline-opt { display: flex; align-items: center; gap: 8px; font-size: 13px; white-space: nowrap; }
  .narrow { width: 150px; flex: none; }
  .keyrow { display: flex; gap: 8px; align-items: center; }
  .keyrow .dbx-input { flex: 1; }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .hint { margin: 0; font-size: 12px; color: var(--color-text-secondary, #64748b); }
  .err { color: var(--color-destructive, #dc2626); font-size: 13px; margin: 0; }
</style>