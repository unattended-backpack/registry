// UI wiring. Small and dependency-free: it reads the directory over the RPC,
// signs and submits through the wallet, and drives the local prover. State is
// held in one object; there is no framework and no build step.

(function () {
  const $ = (id) => document.getElementById(id);
  const R = window.Registry;

  const state = {
    signerManage: null,
    signerRegister: null,
    registerProof: null,
    rotateProof: null
  };

  // JSON.stringify that survives BigInt, for showing proofs and signatures.
  const jstr = (o) => JSON.stringify(
    o, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2
  );

  function setStatus (msg, kind) {
    const s = $("status");
    s.textContent = msg || "";
    s.className = "status" + (kind ? " " + kind : "");
  }

  function short (addr) {
    return addr ? addr.slice(0, 6) + "…" + addr.slice(-4) : "";
  }

  // --- Tabs ---------------------------------------------------------------
  document.querySelectorAll("#tabs button").forEach((b) => {
    b.addEventListener("click", () => {
      document.querySelectorAll("#tabs button").forEach(
        (x) => x.classList.remove("active")
      );
      document.querySelectorAll(".tab").forEach(
        (x) => x.classList.remove("active")
      );
      b.classList.add("active");
      $(b.dataset.tab).classList.add("active");
      setStatus("");
    });
  });

  // --- Settings -----------------------------------------------------------
  function fillSettings () {
    const c = R.loadConfig();
    $("sChainId").value = c.chainId ?? "";
    $("sRpcUrl").value = c.rpcUrl ?? "";
    $("sRegistry").value = c.registryAddress ?? "";
    $("sArtifacts").value = c.proverArtifactBase ?? "";
    $("domainLabel").textContent = c.domain || "ethereum.org";
    $("cfgSummary").textContent = c.registryAddress
      ? `Registry ${short(c.registryAddress)} on chain ${c.chainId}`
      : "No Registry address set.";
  }

  $("sSave").addEventListener("click", () => {
    R.saveConfig({
      chainId: Number($("sChainId").value),
      rpcUrl: $("sRpcUrl").value.trim(),
      registryAddress: $("sRegistry").value.trim(),
      proverArtifactBase: $("sArtifacts").value.trim()
    });
    fillSettings();
    $("sSaved").textContent = "Saved to this browser.";
    setStatus("Settings saved.", "ok");
  });

  $("sReset").addEventListener("click", () => {
    localStorage.removeItem("registry.config");
    fillSettings();
    $("sSaved").textContent = "Reset to the shipped defaults.";
  });

  // --- Browse -------------------------------------------------------------
  function renderProfiles (list) {
    const box = $("profiles");
    box.innerHTML = "";
    if (!list.length) {
      box.innerHTML = "<p class='hint'>No profiles found.</p>";
      return;
    }
    for (const p of list) {
      const card = document.createElement("div");
      card.className = "profile";
      const flag = p.active
        ? "<span class='flag active'>active</span>"
        : "<span class='flag former'>former EF</span>";
      let dl = "";
      for (const [k, v] of Object.entries(p.records)) {
        dl += `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd>`;
      }
      dl += `<dt>controller</dt><dd class="mono">${p.controller}</dd>`;
      card.innerHTML = `<div class="row" style="justify-content:space-between">`
        + `<span class="pid">${p.id}</span>${flag}</div>`
        + (dl ? `<dl>${dl}</dl>` : "<p class='hint'>No records set.</p>");
      box.appendChild(card);
    }
  }

  function escapeHtml (s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }

  $("loadAll").addEventListener("click", async () => {
    try {
      setStatus("Loading the directory ...");
      renderProfiles(await R.listProfiles());
      setStatus("Directory loaded.", "ok");
    } catch (e) {
      setStatus(e.message, "err");
    }
  });

  $("lookupBtn").addEventListener("click", async () => {
    try {
      const id = $("lookupId").value.trim();
      if (!id) return;
      setStatus("Resolving ...");
      renderProfiles([await R.resolveProfile(id)]);
      setStatus("Resolved.", "ok");
    } catch (e) {
      setStatus(e.message, "err");
    }
  });

  // --- A reusable proof-acquisition block --------------------------------
  // Clones the template into `container`. Calls onProof(emailProof) whenever a
  // proof is obtained, by browser proving or by import. `commandFn` returns
  // the exact command the email must carry (for the browser prover).
  function mountProofBlock (container, commandFn, onProof) {
    const frag = $("proofBlock").content.cloneNode(true);
    const root = frag.querySelector(".proofblock");
    const fileInput = root.querySelector(".pbFile");
    const proveBtn = root.querySelector(".pbProve");
    const importArea = root.querySelector(".pbImport");
    const importBtn = root.querySelector(".pbImportBtn");
    const status = root.querySelector(".pbStatus");

    const accept = (proof) => {
      status.textContent = "Proof ready.\nProfile id (account salt): "
        + proof.accountSalt + "\nCommand: " + proof.maskedCommand;
      onProof(proof);
    };

    proveBtn.addEventListener("click", async () => {
      const file = fileInput.files && fileInput.files[0];
      if (!file) { status.textContent = "Choose an .eml file first."; return; }
      let command;
      try { command = commandFn(); } catch (e) {
        status.textContent = e.message; return;
      }
      try {
        const emlText = await file.text();
        status.textContent = "Starting the prover ...";
        const { proof } = await window.Prove.generateProof(
          emlText, command, (m) => { status.textContent = m; }
        );
        accept(proof);
      } catch (e) {
        status.textContent = "Proving failed: " + e.message;
      }
    });

    importBtn.addEventListener("click", () => {
      try {
        accept(window.Prove.importProof(importArea.value));
      } catch (e) {
        status.textContent = "Import failed: " + e.message;
      }
    });

    container.innerHTML = "";
    container.appendChild(frag);
  }

  // --- Manage: connect ----------------------------------------------------
  $("connectManage").addEventListener("click", async () => {
    try {
      state.signerManage = await R.connectWallet();
      $("walletManage").textContent = await state.signerManage.getAddress();
      setStatus("Wallet connected.", "ok");
    } catch (e) {
      setStatus(e.message, "err");
    }
  });

  // --- Manage: set text by transaction -----------------------------------
  $("mSetText").addEventListener("click", async () => {
    try {
      if (!state.signerManage) throw new Error("Connect a wallet first.");
      setStatus("Sending transaction ...");
      const r = await R.setText(
        state.signerManage, $("mProfileId").value.trim(),
        $("mKey").value.trim(), $("mValue").value
      );
      $("mOut").textContent = "Set in block " + r.blockNumber + ".";
      setStatus("Record set.", "ok");
    } catch (e) {
      setStatus(e.message, "err");
    }
  });

  // --- Manage: sign a record write for a relayer -------------------------
  $("mSignText").addEventListener("click", async () => {
    try {
      if (!state.signerManage) throw new Error("Connect a wallet first.");
      setStatus("Requesting signature ...");
      const signed = await R.signSetText(
        state.signerManage, $("mProfileId").value.trim(),
        $("mKey").value.trim(), $("mValue").value
      );
      $("mSignOut").classList.remove("hidden");
      $("mSignOut").textContent = jstr(signed);
      $("mSubmitRow").classList.remove("hidden");
      state.signedText = signed;
      setStatus("Signed. Hand this to any relayer, or submit it yourself.",
        "ok");
    } catch (e) {
      setStatus(e.message, "err");
    }
  });

  $("mSubmitSigned").addEventListener("click", async () => {
    try {
      if (!state.signerManage) throw new Error("Connect a wallet first.");
      const r = await R.submitSetTextSigned(state.signerManage,
        state.signedText);
      $("mOut").textContent = "Relayed in block " + r.blockNumber + ".";
      setStatus("Signed write submitted.", "ok");
    } catch (e) {
      setStatus(e.message, "err");
    }
  });

  // --- Manage: rotate controller -----------------------------------------
  mountProofBlock(
    $("rotateProofMount"),
    () => {
      const n = $("rNewController").value.trim();
      if (!n) throw new Error("Enter the new controller address first.");
      return R.setControllerCommand(n);
    },
    (proof) => {
      state.rotateProof = proof;
      $("rRotate").disabled = false;
      setStatus("Rotation proof ready.", "ok");
    }
  );

  $("rRotate").addEventListener("click", async () => {
    try {
      if (!state.signerManage) throw new Error("Connect a wallet first.");
      if (!state.rotateProof) throw new Error("Acquire a proof first.");
      const n = $("rNewController").value.trim();
      setStatus("Signing as the current controller ...");
      const sig = await R.signEmailAuthorization(
        state.signerManage, state.rotateProof.emailNullifier
      );
      setStatus("Submitting rotation ...");
      const r = await R.submitSetController(
        state.signerManage, state.rotateProof, n, sig
      );
      $("mOut").textContent = "Controller rotated in block " + r.blockNumber
        + ".";
      setStatus("Controller rotated.", "ok");
    } catch (e) {
      setStatus(e.message, "err");
    }
  });

  // --- Register -----------------------------------------------------------
  $("regBuildCommand").addEventListener("click", () => {
    try {
      const c = $("regController").value.trim();
      if (!c) throw new Error("Enter your controller address first.");
      $("regCommand").textContent = R.setControllerCommand(c);
      setStatus("Command built. Email it to yourself, then prove below.", "ok");
    } catch (e) {
      setStatus(e.message, "err");
    }
  });

  mountProofBlock(
    $("registerProofMount"),
    () => {
      const c = $("regController").value.trim();
      if (!c) throw new Error("Build your command first.");
      return R.setControllerCommand(c);
    },
    (proof) => {
      state.registerProof = proof;
      $("regSubmit").disabled = !(state.registerProof && state.signerRegister);
      setStatus("Registration proof ready.", "ok");
    }
  );

  $("regConnect").addEventListener("click", async () => {
    try {
      state.signerRegister = await R.connectWallet();
      $("walletRegister").textContent = await state.signerRegister.getAddress();
      $("regSubmit").disabled = !(state.registerProof && state.signerRegister);
      setStatus("Wallet connected.", "ok");
    } catch (e) {
      setStatus(e.message, "err");
    }
  });

  $("regSubmit").addEventListener("click", async () => {
    try {
      if (!state.registerProof) throw new Error("Acquire a proof first.");
      if (!state.signerRegister) throw new Error("Connect a wallet first.");
      const c = $("regController").value.trim();
      setStatus("Submitting registration ...");
      const r = await R.submitRegister(
        state.signerRegister, state.registerProof, c
      );
      $("regOut").textContent = "Registered in block " + r.blockNumber + "."
        + "\nProfile id: " + state.registerProof.accountSalt;
      setStatus("Registered.", "ok");
    } catch (e) {
      setStatus(e.message, "err");
    }
  });

  // --- Boot ---------------------------------------------------------------
  fillSettings();
})();
