/* Access panel: immediate-apply edits.
 *
 * The panel is rendered server-side (templates/access/_panel.html). Every user
 * action — adding a principal, dragging a row to a different permission
 * bucket, removing a row — POSTs a single-item batch to access:batch_save
 * straight away. On success the server returns the re-rendered panel HTML and
 * we swap it in; on error we re-fetch the panel from access:panel so the DOM
 * matches the server's canonical state.
 *
 * While a request is in flight the panel is "busy" (pointer-events: none on
 * the buckets, input + add button disabled) so users can't queue conflicting
 * actions mid-flight. Handlers use event delegation on document so they
 * survive panel swaps.
 */
(function () {
  "use strict";

  function panelFor(el) {
    return el.closest(".access-panel");
  }

  function bucketFor(permission, panel) {
    return panel.querySelector(`[data-permission-bucket="${permission}"]`);
  }

  function bucketRowsList(bucket) {
    return bucket.querySelector(".access-bucket__rows");
  }

  function refreshEmptyMarkers(panel) {
    panel.querySelectorAll(".access-bucket").forEach((bucket) => {
      const rows = bucketRowsList(bucket);
      const hasRow = !!rows.querySelector(".access-row");
      const marker = rows.querySelector("[data-empty-marker]");
      if (!hasRow && !marker) {
        const li = document.createElement("li");
        li.className = "access-bucket__empty";
        li.setAttribute("data-empty-marker", "");
        li.textContent = "—";
        rows.appendChild(li);
      } else if (hasRow && marker) {
        marker.remove();
      }
    });
  }

  // ---- Request orchestration -----------------------------------------

  function isBusy(panel) {
    return panel.classList.contains("access-panel--busy");
  }

  function setBusy(panel, busy) {
    panel.classList.toggle("access-panel--busy", busy);
    panel.querySelectorAll(
      "[data-principal-input], [data-add-grant], [data-add-permission]"
    ).forEach((el) => {
      el.disabled = busy;
    });
  }

  function setStatus(panel, text, level) {
    const status = panel.querySelector("[data-access-status]");
    if (!status) return;
    status.textContent = text || "";
    status.classList.toggle("access-panel__status--error", level === "error");
  }

  function swapPanel(oldPanel, freshHtml) {
    const wrapper = document.createElement("div");
    wrapper.innerHTML = freshHtml.trim();
    const fresh = wrapper.querySelector(".access-panel");
    if (fresh) {
      oldPanel.replaceWith(fresh);
      return fresh;
    }
    return oldPanel;
  }

  function refetchPanel(panel) {
    const url = panel.getAttribute("data-panel-url");
    if (!url) return Promise.resolve(panel);
    return fetch(url, {
      credentials: "same-origin",
      headers: { Accept: "text/html" },
    })
      .then((resp) => (resp.ok ? resp.text() : null))
      .then((html) => (html == null ? panel : swapPanel(panel, html)));
  }

  function sendBatch(panel, payload, { onSuccess } = {}) {
    if (isBusy(panel)) return Promise.resolve();
    const url = panel.getAttribute("data-save-url");
    const csrf = panel.getAttribute("data-csrf");

    setBusy(panel, true);
    setStatus(panel, "Saving…");

    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
      body: JSON.stringify(payload),
    })
      .then((resp) => {
        if (resp.ok) return resp.text().then((html) => ({ ok: true, html }));
        return resp.json().then(
          (data) => ({ ok: false, errors: data.errors || ["Save failed."] }),
          () => ({ ok: false, errors: ["Save failed."] })
        );
      })
      .then((result) => {
        if (result.ok) {
          const fresh = swapPanel(panel, result.html);
          setStatus(fresh, "Saved");
          if (onSuccess) onSuccess(fresh);
        } else {
          // Re-fetch to discard any optimistic DOM moves.
          return refetchPanel(panel).then((fresh) => {
            setStatus(fresh, result.errors.join(" "), "error");
          });
        }
      })
      .catch(() => {
        return refetchPanel(panel).then((fresh) => {
          setStatus(fresh, "Network error — try again.", "error");
        });
      });
  }

  // ---- Actions --------------------------------------------------------

  function postRevoke(panel, row) {
    const payload = {};
    if (row.hasAttribute("data-grant-id")) {
      payload.grants_revoke = [parseInt(row.getAttribute("data-grant-id"), 10)];
    } else if (row.hasAttribute("data-invitation-id")) {
      payload.invitations_revoke = [parseInt(row.getAttribute("data-invitation-id"), 10)];
    } else {
      return;
    }
    sendBatch(panel, payload);
  }

  function postPermissionUpdate(panel, row, newPermission) {
    const payload = {};
    if (row.hasAttribute("data-grant-id")) {
      payload.grants_update = [
        { id: parseInt(row.getAttribute("data-grant-id"), 10), permission: newPermission },
      ];
    } else if (row.hasAttribute("data-invitation-id")) {
      payload.invitations_update = [
        { id: parseInt(row.getAttribute("data-invitation-id"), 10), permission: newPermission },
      ];
    } else {
      return;
    }
    sendBatch(panel, payload);
  }

  function postGrantAdd(panel, principal, permission) {
    sendBatch(
      panel,
      { grants_add: [{ principal, permission }] },
      {
        onSuccess: (fresh) => {
          const input = fresh.querySelector("[data-principal-input]");
          if (input) {
            input.value = "";
            input.focus();
          }
        },
      }
    );
  }

  // ---- Remove ---------------------------------------------------------

  function handleRemove(button) {
    const row = button.closest(".access-row");
    if (!row) return;
    const panel = panelFor(row);
    if (isBusy(panel)) return;
    postRevoke(panel, row);
  }

  // ---- Drag and drop --------------------------------------------------

  function handleDragStart(ev) {
    const row = ev.target.closest(".access-row");
    if (!row) return;
    if (row.hasAttribute("data-locked")) {
      ev.preventDefault();
      return;
    }
    if (isBusy(panelFor(row))) {
      ev.preventDefault();
      return;
    }
    row.classList.add("access-row--dragging");
    ev.dataTransfer.effectAllowed = "move";
    try {
      // Required for Firefox to start the drag.
      ev.dataTransfer.setData("text/plain", "");
    } catch (_e) {
      /* ignore */
    }
  }

  function handleDragEnd(ev) {
    const row = ev.target.closest(".access-row");
    if (!row) return;
    row.classList.remove("access-row--dragging");
    panelFor(row).querySelectorAll(".access-bucket--dropping").forEach((b) => {
      b.classList.remove("access-bucket--dropping");
    });
  }

  function isDroppable(bucket) {
    // Owner is not a grantable permission — block drops on the owners bucket.
    return bucket.getAttribute("data-permission-bucket") !== "owner";
  }

  function handleDragOver(ev) {
    const bucket = ev.target.closest(".access-bucket");
    if (!bucket || !isDroppable(bucket)) return;
    const panel = panelFor(bucket);
    if (isBusy(panel)) return;
    const dragging = panel.querySelector(".access-row--dragging");
    if (!dragging) return;
    ev.preventDefault();
    ev.dataTransfer.dropEffect = "move";
    panel.querySelectorAll(".access-bucket--dropping").forEach((b) => {
      if (b !== bucket) b.classList.remove("access-bucket--dropping");
    });
    bucket.classList.add("access-bucket--dropping");
  }

  function handleDragLeave(ev) {
    const bucket = ev.target.closest(".access-bucket");
    if (!bucket) return;
    if (bucket.contains(ev.relatedTarget)) return;
    bucket.classList.remove("access-bucket--dropping");
  }

  function handleDrop(ev) {
    const bucket = ev.target.closest(".access-bucket");
    if (!bucket || !isDroppable(bucket)) return;
    const panel = panelFor(bucket);
    if (isBusy(panel)) return;
    const dragging = panel.querySelector(".access-row--dragging");
    if (!dragging) return;
    ev.preventDefault();
    bucket.classList.remove("access-bucket--dropping");

    const newPermission = bucket.getAttribute("data-permission-bucket");
    const previousPermission = dragging.getAttribute("data-permission");
    if (newPermission === previousPermission) {
      // Same bucket — nothing to do.
      return;
    }
    // Optimistic move so the row visually lands where the user dropped it.
    // The panel re-render after sendBatch reconciles with the server's view.
    dragging.setAttribute("data-permission", newPermission);
    bucketRowsList(bucket).appendChild(dragging);
    refreshEmptyMarkers(panel);

    postPermissionUpdate(panel, dragging, newPermission);
  }

  // ---- Add ------------------------------------------------------------

  function handleAdd(panel) {
    if (isBusy(panel)) return;
    const input = panel.querySelector("[data-principal-input]");
    const permSel = panel.querySelector("[data-add-permission]");
    const raw = (input.value || "").trim();
    setStatus(panel, "");

    if (!raw) {
      setStatus(panel, "Enter an email or @group.", "error");
      return;
    }
    const isGroup = raw.startsWith("@");
    if (isGroup && raw.length === 1) {
      setStatus(panel, "Group name is empty.", "error");
      return;
    }
    if (!isGroup && !raw.includes("@")) {
      setStatus(panel, "Use email@example.org for users or @group-name for groups.", "error");
      return;
    }

    // Reject duplicates: same principal already shown in the panel.
    const existing = panel.querySelectorAll(".access-row");
    for (const row of existing) {
      const label = row.querySelector(".access-row__principal");
      const text = label ? label.textContent.replace(/\binvited\b/, "").trim() : "";
      if (text.toLowerCase() === raw.toLowerCase()) {
        if (row.hasAttribute("data-locked")) {
          setStatus(panel, `${raw} is the project security team — it is always an owner.`, "error");
        } else {
          setStatus(panel, `${raw} already has access.`, "error");
        }
        return;
      }
    }

    postGrantAdd(panel, raw, permSel.value);
  }

  // ---- Event delegation -----------------------------------------------

  document.addEventListener("click", function (ev) {
    const removeBtn = ev.target.closest("[data-remove-grant], [data-remove-invitation]");
    if (removeBtn) {
      ev.preventDefault();
      handleRemove(removeBtn);
      return;
    }
    const addBtn = ev.target.closest("[data-add-grant]");
    if (addBtn) {
      ev.preventDefault();
      const panel = panelFor(addBtn);
      if (panel) handleAdd(panel);
      return;
    }
  });

  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "Enter") return;
    const input = ev.target.closest("[data-principal-input]");
    if (!input) return;
    ev.preventDefault();
    const panel = panelFor(input);
    if (panel) handleAdd(panel);
  });

  document.addEventListener("dragstart", function (ev) {
    if (!ev.target.closest(".access-panel")) return;
    handleDragStart(ev);
  });
  document.addEventListener("dragend", function (ev) {
    if (!ev.target.closest(".access-panel")) return;
    handleDragEnd(ev);
  });
  document.addEventListener("dragover", function (ev) {
    if (!ev.target.closest(".access-panel")) return;
    handleDragOver(ev);
  });
  document.addEventListener("dragleave", function (ev) {
    if (!ev.target.closest(".access-panel")) return;
    handleDragLeave(ev);
  });
  document.addEventListener("drop", function (ev) {
    if (!ev.target.closest(".access-panel")) return;
    handleDrop(ev);
  });
})();
