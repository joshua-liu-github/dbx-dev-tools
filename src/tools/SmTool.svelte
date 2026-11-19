<script>
  import ToolShell from "../components/ToolShell.svelte";
  import CopyButton from "../components/CopyButton.svelte";
  import {
    SmError, sm2GenerateKeyPair, formatSm2PrivateKey, formatSm2PublicKey,
    sm2Encrypt, sm2Decrypt, sm2Sign, sm2Verify, sm3Hash, sm3Hmac,
    sm4Encrypt, sm4Decrypt, bytesToHex, bytesToB64,
  } from "../lib/sm.js";
  import { saveFile } from "../lib/bridge.js";
  import { t, onLangChange } from "../lib/i18n.js";
  import { persistState } from "../lib/persist.svelte.js";

  let s = $state(t());
  onLangChange(() => (s = t()));
  const tool = $derived(s.tools.sm);
  const m = $derived(s.sm);

  let alg = $state("sm2"); // "sm2" | "sm3" | "sm4"
  let error = $state("");

  let sm2Mode = $state("gen"); // "gen" | "crypt" | "sign"
  let genFormat = $state("pem");
  let genBusy = $state(false);
  let keyPair = $state(null);

  let sm2CryptOp = $state("enc");
  let sm2Key = $state("");
  let sm2Plain = $state("");
  let sm2CipherIn = $state("");
  let sm2CryptOut = $state("");
  let sm2CipherMode = $state("C1C3C2");
  let c1Prefix = $state(false);
  let ctEncoding = $state("hex");

  let sm2SignOp = $state("sign");
  let signKey = $state("");
  let signMsg = $state("");
  let signSigIn = $state("");
  let signOut = $state("");
  let sigFormat = $state("raw");
  let userId = $state("");
  let verifyOk = $state(null);

  let sm3Mode = $state("hash"); // "hash" | "hmac"
  let sm3In = $state("");
  let sm3Key = $state("");
  let sm3InEnc = $state("text");
  let sm3KeyEnc = $state("text");
  let sm3OutEnc = $state("hex");
  let sm3Out = $state("");

  let sm4Op = $state("enc");
  let sm4Key = $state("");
  let sm4Iv = $state("");
  let sm4Mode = $state("cbc");
  let sm4Padding = $state("pkcs7");
  let sm4KeyEnc = $state("hex");
  let sm4IvEnc = $state("hex");
  let sm4InEnc = $state("text");
  let sm4OutEnc = $state("hex");
  let sm4EncIn = $state("");
  let sm4DecIn = $state("");
  let sm4Out = $state("");

  const privateDisplay = $derived(keyPair ? formatSm2PrivateKey(keyPair.privateKey, genFormat) : "");
  const publicDisplay = $derived(keyPair ? formatSm2PublicKey(keyPair.publicKey, genFormat) : "");
  const sm2CryptInput = $derived(sm2CryptOp === "enc" ? sm2Plain : sm2CipherIn);
  const sm4Input = $derived(sm4Op === "enc" ? sm4EncIn : sm4DecIn);

  function errText(e) {
    if (e instanceof SmError) {
      const map = {
        badEncoding: m.badEncoding, badKey: m.badKey, needPub: m.needPub, needPriv: m.needPriv,
        badIv: m.badIv, badSignature: m.badSignature, badPayload: m.badPayload,
        badPad: m.badPad, padMultiple: m.padMultiple, badUtf8: m.badUtf8,
      };
      return map[e.code] ?? m.failed;
    }
    return e?.message || m.failed;
  }

  function clearError() {
    error = "";
    verifyOk = null;
  }

  function setAlg(next) {
    alg = next;
    clearError();
  }

  function setSm2Mode(next) {
    sm2Mode = next;
    clearError();
  }

  function randomValue(enc) {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    if (enc === "base64") return bytesToB64(bytes);
    if (enc === "text") return [...bytes].map((b) => String.fromCharCode(33 + (b % 94))).join("");
    return bytesToHex(bytes);
  }

  function gen() {
    error = "";
    genBusy = true;
    try {
      const t0 = performance.now();
      keyPair = { ...sm2GenerateKeyPair(), ms: Math.round(performance.now() - t0) };
    } catch (e) {
      keyPair = null;
      error = errText(e);
    } finally {
      genBusy = false;
    }
  }

  function download(name, text) {
    saveFile({ fileName: name, contentType: "application/x-pem-file" }, text);
  }

  function setSm2CryptOp(op) {
    if (op === sm2CryptOp) return;
    sm2CryptOp = op;
    clearError();
    if (sm2CryptOut) {
      if (op === "dec" && !sm2CipherIn) sm2CipherIn = sm2CryptOut;
      else if (op === "enc" && !sm2Plain) sm2Plain = sm2CryptOut;
    }
    sm2CryptOut = "";
  }

  function runSm2Crypt() {
    error = "";
    sm2CryptOut = "";
    if (!sm2CryptInput || !sm2Key) return;
    try {
      sm2CryptOut = sm2CryptOp === "enc"
        ? sm2Encrypt(sm2Plain, sm2Key, { cipherMode: sm2CipherMode, outEncoding: ctEncoding, c1Prefix })
        : sm2Decrypt(sm2CipherIn, sm2Key, { cipherMode: sm2CipherMode, inEncoding: ctEncoding });
    } catch (e) {
      error = errText(e);
    }
  }

  function setSm2SignOp(op) {
    if (op === sm2SignOp) return;
    sm2SignOp = op;
    clearError();
    signOut = "";
  }

  function runSign() {
    error = "";
    signOut = "";
    verifyOk = null;
    if (!signMsg || !signKey || (sm2SignOp === "verify" && !signSigIn)) return;
    try {
      const uid = userId.trim();
      if (sm2SignOp === "sign") signOut = sm2Sign(signMsg, signKey, { userId: uid, sigFormat });
      else verifyOk = sm2Verify(signMsg, signSigIn, signKey, { userId: uid, sigFormat });
    } catch (e) {
      error = errText(e);
    }
  }

  function setSm3Mode(next) {
    sm3Mode = next;
    clearError();
    sm3Out = "";
  }

  function runSm3() {
    error = "";
    sm3Out = "";
    if (sm3Mode === "hmac" && !sm3Key) return;
    try {
      sm3Out = sm3Mode === "hash"
        ? sm3Hash(sm3In, { inputEncoding: sm3InEnc, outEncoding: sm3OutEnc })
        : sm3Hmac(sm3In, sm3Key, { inputEncoding: sm3InEnc, keyEncoding: sm3KeyEnc, outEncoding: sm3OutEnc });
    } catch (e) {
      error = errText(e);
    }
  }

  function setSm4Op(op) {
    if (op === sm4Op) return;
    sm4Op = op;
    clearError();
    if (op === "dec") {
      if (sm4InEnc === "text") sm4InEnc = "hex";
      if (sm4OutEnc === "hex") sm4OutEnc = "text";
      if (sm4Out && !sm4DecIn) sm4DecIn = sm4Out;
    } else {
      if (sm4InEnc === "hex") sm4InEnc = "text";
      if (sm4OutEnc === "text") sm4OutEnc = "hex";
      if (sm4Out && !sm4EncIn) sm4EncIn = sm4Out;
    }
    sm4Out = "";
  }

  function runSm4() {
    error = "";
    sm4Out = "";
    if (!sm4Input || !sm4Key || (sm4Mode === "cbc" && !sm4Iv)) return;
    try {
      const opts = {
        inputEncoding: sm4InEnc, keyEncoding: sm4KeyEnc,
        mode: sm4Mode, iv: sm4Iv, ivEncoding: sm4IvEnc,
        padding: sm4Padding, outputEncoding: sm4OutEnc,
      };
      sm4Out = sm4Op === "enc" ? sm4Encrypt(sm4Input, sm4Key, opts) : sm4Decrypt(sm4Input, sm4Key, opts);
    } catch (e) {
      error = errText(e);
    }
  }

  // Keys, plaintext and signatures stay in memory; only options are persisted.
  persistState("sm", {
    get: () => ({
      alg, sm2Mode, genFormat, sm2CryptOp, sm2CipherMode, c1Prefix, ctEncoding,
      sm2SignOp, sigFormat, userId, sm3Mode, sm3InEnc, sm3KeyEnc, sm3OutEnc,
      sm4Op, sm4Mode, sm4Padding, sm4KeyEnc, sm4IvEnc, sm4InEnc, sm4OutEnc,
    }),
    set: (v) => {
      alg = v.alg ?? alg;
      sm2Mode = v.sm2Mode ?? sm2Mode;
      genFormat = v.genFormat ?? genFormat;
      sm2CryptOp = v.sm2CryptOp ?? sm2CryptOp;
      sm2CipherMode = v.sm2CipherMode ?? sm2CipherMode;
      c1Prefix = v.c1Prefix ?? c1Prefix;
      ctEncoding = v.ctEncoding ?? ctEncoding;
      sm2SignOp = v.sm2SignOp ?? sm2SignOp;
      sigFormat = v.sigFormat ?? sigFormat;
      userId = v.userId ?? userId;
      sm3Mode = v.sm3Mode ?? sm3Mode;
      sm3InEnc = v.sm3InEnc ?? sm3InEnc;
      sm3KeyEnc = v.sm3KeyEnc ?? sm3KeyEnc;
      sm3OutEnc = v.sm3OutEnc ?? sm3OutEnc;
      sm4Op = v.sm4Op ?? sm4Op;
      sm4Mode = v.sm4Mode ?? sm4Mode;
      sm4Padding = v.sm4Padding ?? sm4Padding;
      sm4KeyEnc = v.sm4KeyEnc ?? sm4KeyEnc;
      sm4IvEnc = v.sm4IvEnc ?? sm4IvEnc;
      sm4InEnc = v.sm4InEnc ?? sm4InEnc;
      sm4OutEnc = v.sm4OutEnc ?? sm4OutEnc;
    },
  });
</script>

<ToolShell title={tool.name} desc={tool.desc}>
  <div class="dbx-card">
    <div class="seg">
      <button type="button" class="seg-btn" class:active={alg === "sm2"} onclick={() => setAlg("sm2")}>{m.sm2}</button>
      <button type="button" class="seg-btn" class:active={alg === "sm3"} onclick={() => setAlg("sm3")}>{m.sm3}</button>
      <button type="button" class="seg-btn" class:active={alg === "sm4"} onclick={() => setAlg("sm4")}>{m.sm4}</button>
    </div>

    {#if alg === "sm2"}
      <div class="seg">
        <button type="button" class="seg-btn" class:active={sm2Mode === "gen"} onclick={() => setSm2Mode("gen")}>{m.modeGen}</button>
        <button type="button" class="seg-btn" class:active={sm2Mode === "crypt"} onclick={() => setSm2Mode("crypt")}>{m.modeCrypt}</button>
        <button type="button" class="seg-btn" class:active={sm2Mode === "sign"} onclick={() => setSm2Mode("sign")}>{m.modeSign}</button>
      </div>

      {#if sm2Mode === "gen"}
        <div class="row">
          <label class="field slim">{m.keyFormat}
            <select class="dbx-input" bind:value={genFormat}>
              <option value="pem">{m.fmtPem}</option>
              <option value="hex">{m.fmtHex}</option>
              <option value="base64">{m.fmtBase64}</option>
            </select>
          </label>
          <button type="button" class="dbx-btn dbx-btn--primary gen-btn" onclick={gen} disabled={genBusy}>
            {genBusy ? m.generating : m.generate}
          </button>
        </div>
        <p class="hint">{m.pemOutputNote}</p>
      {:else if sm2Mode === "crypt"}
        <div class="row">
          <div class="seg">
            <button type="button" class="seg-btn" class:active={sm2CryptOp === "enc"} onclick={() => setSm2CryptOp("enc")}>{m.encrypt}</button>
            <button type="button" class="seg-btn" class:active={sm2CryptOp === "dec"} onclick={() => setSm2CryptOp("dec")}>{m.decrypt}</button>
          </div>
          <label class="field slim">{m.cipherMode}
            <select class="dbx-input" bind:value={sm2CipherMode}>
              <option value="C1C3C2">{m.cmC1C3C2}</option>
              <option value="C1C2C3">{m.cmC1C2C3}</option>
            </select>
          </label>
          <label class="field slim">{m.ctEncoding}
            <select class="dbx-input" bind:value={ctEncoding}>
              <option value="hex">{m.hex}</option>
              <option value="base64">{m.base64}</option>
            </select>
          </label>
          {#if sm2CryptOp === "enc"}
            <label class="check"><input type="checkbox" bind:checked={c1Prefix} />{m.c1Prefix}</label>
          {/if}
        </div>
        <label class="dbx-label" for="sm2-key">{sm2CryptOp === "enc" ? m.publicKey : m.privateKey} <span class="dim">{m.keyHint}</span></label>
        <textarea id="sm2-key" class="dbx-textarea mono" rows="5" bind:value={sm2Key} spellcheck="false"></textarea>
        <label class="dbx-label" for="sm2-in">{sm2CryptOp === "enc" ? m.plain : m.cipher}</label>
        {#if sm2CryptOp === "enc"}
          <textarea id="sm2-in" class="dbx-textarea mono" rows="4" bind:value={sm2Plain} placeholder={m.plainHint} spellcheck="false"></textarea>
        {:else}
          <textarea id="sm2-in" class="dbx-textarea mono" rows="4" bind:value={sm2CipherIn} placeholder={m.cipherHint} spellcheck="false"></textarea>
        {/if}
        <div class="actions">
          <button type="button" class="dbx-btn dbx-btn--primary" onclick={runSm2Crypt}
            disabled={!sm2CryptInput || !sm2Key}>{sm2CryptOp === "enc" ? m.encrypt : m.decrypt}</button>
        </div>
        {#if sm2CryptOut}
          <div class="head">
            <h2 class="dbx-section-title" style="margin:0">{sm2CryptOp === "enc" ? m.cipher : m.plain}</h2>
            <CopyButton text={sm2CryptOut} small />
          </div>
          <textarea class="dbx-textarea mono" rows="4" readonly value={sm2CryptOut}></textarea>
          {#if sm2CryptOp === "enc"}<p class="hint">{m.ctHint}</p>{/if}
        {/if}
      {:else}
        <div class="row">
          <div class="seg">
            <button type="button" class="seg-btn" class:active={sm2SignOp === "sign"} onclick={() => setSm2SignOp("sign")}>{m.sign}</button>
            <button type="button" class="seg-btn" class:active={sm2SignOp === "verify"} onclick={() => setSm2SignOp("verify")}>{m.verify}</button>
          </div>
          <label class="field slim">{m.sigFormat}
            <select class="dbx-input" bind:value={sigFormat}>
              <option value="raw">{m.sigRaw}</option>
              <option value="der">{m.sigDer}</option>
              <option value="der-b64">{m.sigDerB64}</option>
            </select>
          </label>
          <label class="field">{m.userId}
            <input class="dbx-input mono" bind:value={userId} placeholder="1234567812345678" spellcheck="false" />
          </label>
        </div>
        <label class="dbx-label" for="sm2-sign-key">{sm2SignOp === "sign" ? m.privateKey : m.publicKey} <span class="dim">{m.keyHint}</span></label>
        <textarea id="sm2-sign-key" class="dbx-textarea mono" rows="5" bind:value={signKey} spellcheck="false"></textarea>
        <label class="dbx-label" for="sm2-msg">{m.message}</label>
        <textarea id="sm2-msg" class="dbx-textarea mono" rows="4" bind:value={signMsg} spellcheck="false"></textarea>
        {#if sm2SignOp === "verify"}
          <label class="dbx-label" for="sm2-sig">{m.signature}</label>
          <textarea id="sm2-sig" class="dbx-textarea mono" rows="3" bind:value={signSigIn} spellcheck="false"></textarea>
        {/if}
        <div class="actions">
          <button type="button" class="dbx-btn dbx-btn--primary" onclick={runSign}
            disabled={!signMsg || !signKey || (sm2SignOp === "verify" && !signSigIn)}>
            {sm2SignOp === "sign" ? m.sign : m.verify}
          </button>
          {#if verifyOk !== null}
            <span class="badge {verifyOk ? 'ok' : 'bad'}">{verifyOk ? m.verifyOk : m.verifyBad}</span>
          {/if}
        </div>
        {#if signOut}
          <div class="head">
            <h2 class="dbx-section-title" style="margin:0">{m.signature}</h2>
            <CopyButton text={signOut} small />
          </div>
          <textarea class="dbx-textarea mono" rows="3" readonly value={signOut}></textarea>
        {/if}
      {/if}
    {:else if alg === "sm3"}
      <div class="seg">
        <button type="button" class="seg-btn" class:active={sm3Mode === "hash"} onclick={() => setSm3Mode("hash")}>{m.hash}</button>
        <button type="button" class="seg-btn" class:active={sm3Mode === "hmac"} onclick={() => setSm3Mode("hmac")}>{m.hmac}</button>
      </div>
      <label class="dbx-label" for="sm3-in">{m.message}</label>
      <textarea id="sm3-in" class="dbx-textarea mono" rows="5" bind:value={sm3In} spellcheck="false"></textarea>
      {#if sm3Mode === "hmac"}
        <label class="dbx-label" for="sm3-key">{m.key}</label>
        <div class="keyrow">
          <input id="sm3-key" class="dbx-input mono" bind:value={sm3Key} spellcheck="false" />
          <select class="dbx-input narrow" bind:value={sm3KeyEnc}>
            <option value="text">{m.text}</option>
            <option value="hex">{m.hex}</option>
            <option value="base64">{m.base64}</option>
          </select>
        </div>
      {/if}
      <div class="opts">
        <label>{m.inputEncoding}
          <select class="dbx-input narrow" bind:value={sm3InEnc}>
            <option value="text">{m.text}</option>
            <option value="hex">{m.hex}</option>
            <option value="base64">{m.base64}</option>
          </select>
        </label>
        <label>{m.outputEncoding}
          <select class="dbx-input narrow" bind:value={sm3OutEnc}>
            <option value="hex">{m.hex}</option>
            <option value="base64">{m.base64}</option>
          </select>
        </label>
      </div>
      <div class="actions">
        <button type="button" class="dbx-btn dbx-btn--primary" onclick={runSm3}
          disabled={sm3Mode === "hmac" && !sm3Key}>{m.compute}</button>
      </div>
      {#if sm3Out}
        <div class="head">
          <h2 class="dbx-section-title" style="margin:0">{m.digest}</h2>
          <CopyButton text={sm3Out} small />
        </div>
        <textarea class="dbx-textarea mono" rows="3" readonly value={sm3Out}></textarea>
      {/if}
      <p class="hint">{sm3Mode === "hmac" ? m.sm3HmacHint : m.sm3Hint}</p>
    {:else}
      <div class="seg">
        <button type="button" class="seg-btn" class:active={sm4Op === "enc"} onclick={() => setSm4Op("enc")}>{m.encrypt}</button>
        <button type="button" class="seg-btn" class:active={sm4Op === "dec"} onclick={() => setSm4Op("dec")}>{m.decrypt}</button>
      </div>
      <label class="dbx-label" for="sm4-key">{m.key} — 16 bytes</label>
      <div class="keyrow">
        <input id="sm4-key" class="dbx-input mono" bind:value={sm4Key} spellcheck="false" />
        <select class="dbx-input narrow" bind:value={sm4KeyEnc}>
          <option value="hex">{m.hex}</option>
          <option value="base64">{m.base64}</option>
          <option value="text">{m.text}</option>
        </select>
        <button type="button" class="dbx-btn" onclick={() => (sm4Key = randomValue(sm4KeyEnc))}>{m.generate}</button>
      </div>
      <div class="opts">
        <label>{m.sm4Mode}
          <select class="dbx-input narrow" bind:value={sm4Mode}>
            <option value="cbc">{m.cbc}</option>
            <option value="ecb">{m.ecb}</option>
          </select>
        </label>
        <label>{m.padding}
          <select class="dbx-input narrow" bind:value={sm4Padding}>
            <option value="pkcs7">{m.padPkcs7}</option>
            <option value="none">{m.padNone}</option>
          </select>
        </label>
      </div>
      {#if sm4Mode === "cbc"}
        <label class="dbx-label" for="sm4-iv">{m.iv} — 16 bytes</label>
        <div class="keyrow">
          <input id="sm4-iv" class="dbx-input mono" bind:value={sm4Iv} spellcheck="false" />
          <select class="dbx-input narrow" bind:value={sm4IvEnc}>
            <option value="hex">{m.hex}</option>
            <option value="base64">{m.base64}</option>
            <option value="text">{m.text}</option>
          </select>
          <button type="button" class="dbx-btn" onclick={() => (sm4Iv = randomValue(sm4IvEnc))}>{m.generate}</button>
        </div>
      {/if}
      <div class="opts">
        <label>{m.inputEncoding}
          <select class="dbx-input narrow" bind:value={sm4InEnc}>
            <option value="text">{m.text}</option>
            <option value="hex">{m.hex}</option>
            <option value="base64">{m.base64}</option>
          </select>
        </label>
        <label>{m.outputEncoding}
          <select class="dbx-input narrow" bind:value={sm4OutEnc}>
            <option value="hex">{m.hex}</option>
            <option value="base64">{m.base64}</option>
            <option value="text">{m.text}</option>
          </select>
        </label>
      </div>
      {#if sm4Op === "enc"}
        <textarea class="dbx-textarea mono" rows="5" bind:value={sm4EncIn} spellcheck="false"></textarea>
      {:else}
        <textarea class="dbx-textarea mono" rows="5" bind:value={sm4DecIn} spellcheck="false"></textarea>
      {/if}
      <div class="actions">
        <button type="button" class="dbx-btn dbx-btn--primary" onclick={runSm4}
          disabled={!sm4Input || !sm4Key || (sm4Mode === "cbc" && !sm4Iv)}>{sm4Op === "enc" ? m.encrypt : m.decrypt}</button>
      </div>
      {#if sm4Out}
        <div class="head">
          <h2 class="dbx-section-title" style="margin:0">{sm4Op === "enc" ? m.cipher : m.plain}</h2>
          <CopyButton text={sm4Out} small />
        </div>
        <textarea class="dbx-textarea mono" rows="5" readonly value={sm4Out}></textarea>
      {/if}
      <p class="hint">{sm4Padding === "none" ? m.padNoneHint : m.sm4Hint}</p>
    {/if}

    {#if error}<p class="err">{error}</p>{/if}
  </div>

  {#if alg === "sm2" && sm2Mode === "gen" && keyPair}
    <div class="dbx-card">
      <div class="head">
        <h2 class="dbx-section-title" style="margin:0">{m.publicKey}</h2>
        <div class="acts">
          <CopyButton text={publicDisplay} small />
          {#if genFormat === "pem"}
            <button type="button" class="dbx-btn" onclick={() => download("sm2-public.pem", publicDisplay)}>{m.download}</button>
          {/if}
        </div>
      </div>
      <textarea class="dbx-textarea mono" rows="7" readonly value={publicDisplay}></textarea>
    </div>
    <div class="dbx-card">
      <div class="head">
        <h2 class="dbx-section-title" style="margin:0">{m.privateKey}</h2>
        <div class="acts">
          <CopyButton text={privateDisplay} small />
          {#if genFormat === "pem"}
            <button type="button" class="dbx-btn" onclick={() => download("sm2-private.pem", privateDisplay)}>{m.download}</button>
          {/if}
        </div>
      </div>
      <textarea class="dbx-textarea mono" rows="12" readonly value={privateDisplay}></textarea>
      <p class="hint">{m.pkcs8Note} · {keyPair.ms} ms</p>
    </div>
  {/if}
</ToolShell>

<style>
  .dbx-card { display: flex; flex-direction: column; gap: 10px; margin-bottom: 14px; }
  .row { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
  .field { display: flex; flex-direction: column; gap: 6px; min-width: 200px; flex: 1; }
  .field.slim { min-width: 150px; flex: none; }
  .gen-btn { flex: none; }
  .seg { display: flex; border: 1px solid var(--color-border, #e2e8f0); border-radius: 8px; overflow: hidden; width: fit-content; }
  .seg-btn { padding: 6px 16px; font-size: 13px; background: transparent; border: none; color: var(--color-text-secondary, #64748b); cursor: pointer; }
  .seg-btn.active { background: var(--color-primary, #3b82f6); color: #fff; }
  .actions { display: flex; align-items: center; gap: 12px; }
  .opts { display: flex; gap: 16px; flex-wrap: wrap; }
  .opts label { display: flex; align-items: center; gap: 8px; font-size: 13px; }
  .opts .narrow, .keyrow .narrow { width: 120px; flex: none; }
  .keyrow { display: flex; gap: 8px; align-items: center; }
  .keyrow .dbx-input { flex: 1; }
  .check { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; padding-bottom: 8px; }
  .badge { display: inline-flex; align-items: center; height: 24px; padding: 0 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .badge.ok { background: rgba(22, 163, 74, .15); color: #16a34a; }
  .badge.bad { background: rgba(220, 38, 38, .15); color: var(--color-destructive, #dc2626); }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .acts { display: flex; gap: 8px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .hint { margin: 0; font-size: 12px; color: var(--color-text-secondary, #64748b); }
  .dim { font-weight: 400; color: var(--color-text-secondary, #64748b); font-size: 12px; }
  .err { color: var(--color-destructive, #dc2626); font-size: 13px; margin: 0; }
</style>
