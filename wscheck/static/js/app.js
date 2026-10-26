(function () {
  "use strict";

  document.addEventListener("click", function (event) {
    const trigger = event.target.closest("[data-confirm]");
    if (trigger && !window.confirm(trigger.getAttribute("data-confirm"))) {
      event.preventDefault();
      event.stopPropagation();
    }
  });

  // 复制按钮把文本放在 data 属性里，避免把 URL 拼进 onclick 造成存储型 XSS
  document.addEventListener("click", function (event) {
    const button = event.target.closest("[data-copy]");
    if (!button) return;
    const text = button.getAttribute("data-copy") || "";
    const original = button.innerHTML;
    const done = function (ok) {
      button.textContent = ok ? "已复制" : "复制失败";
      window.setTimeout(function () { button.innerHTML = original; }, 1500);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { done(true); },
        function () { done(false); });
      return;
    }
    // http 页面或旧浏览器没有 Clipboard API，退回 execCommand
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (error) { ok = false; }
    document.body.removeChild(area);
    done(ok);
  });

  const checkAll = document.getElementById("checkAll");
  if (checkAll) {
    const rows = Array.from(document.querySelectorAll(".rowCheck"));
    const counter = document.getElementById("selectionCount");
    const sync = function () {
      const picked = rows.filter(function (row) { return row.checked; });
      if (counter) counter.textContent = picked.length;
      rows.forEach(function (row) {
        row.closest("tr") && row.closest("tr").classList.toggle("table-primary", row.checked);
      });
    };
    checkAll.addEventListener("change", function () {
      rows.forEach(function (row) { row.checked = checkAll.checked; });
      sync();
    });
    rows.forEach(function (row) { row.addEventListener("change", sync); });
    sync();
  }

  // 勾选行后再提交的表单（批量处理、批量导出）统一在这里补上 ids
  document.querySelectorAll("form[data-collect-ids]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      const picked = Array.from(document.querySelectorAll(".rowCheck")).filter(function (row) {
        return row.checked;
      });
      if (!picked.length) {
        event.preventDefault();
        window.alert("请先勾选要处理的结果");
        return;
      }
      const action = form.querySelector("[name=action]");
      if (action && action.value === "delete" &&
          !window.confirm("删除选中的 " + picked.length + " 条结果？该操作不可恢复。")) {
        event.preventDefault();
        return;
      }
      const hasNativeIds = form.elements && form.elements.namedItem("ids");
      picked.forEach(function (row) {
        if (hasNativeIds) return; // 复选框本身已会提交
        const input = document.createElement("input");
        input.type = "hidden";
        input.name = "ids";
        input.value = row.value;
        form.appendChild(input);
      });
    });
  });

  document.querySelectorAll("[data-picker]").forEach(function (box) {
    const endpoint = box.getAttribute("data-endpoint");
    const kind = box.getAttribute("data-kind");
    const field = box.getAttribute("data-name");
    const scope = document.getElementById(box.getAttribute("data-scope"));
    const pickValues = (box.getAttribute("data-pick-values") || "custom,manual").split(",");
    const search = box.querySelector(".picker-search");
    const results = box.querySelector(".picker-results");
    const selectedBox = box.querySelector(".picker-selected");
    let selected = [];
    let timer = null;

    try {
      selected = JSON.parse(box.getAttribute("data-selected") || "[]");
    } catch (error) {
      selected = [];
    }

    function picking() {
      return !scope || pickValues.indexOf(scope.value) >= 0;
    }

    function render() {
      const active = picking();
      selectedBox.textContent = "";
      if (!selected.length) {
        const hint = document.createElement("span");
        hint.className = "text-muted small";
        hint.textContent = !scope ? "尚未勾选：由扫描模式决定"
          : (active ? "尚未勾选，提交时该范围不做限定" : "未勾选：按上方范围整体执行");
        selectedBox.appendChild(hint);
      }
      selected.forEach(function (item) {
        const label = item.label || item.value;
        const chip = document.createElement("span");
        chip.className = "chip";
        chip.append(label);
        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "btn-close ms-1";
        remove.setAttribute("aria-label", "移除 " + label);
        remove.addEventListener("click", function () {
          selected = selected.filter(function (x) { return x.value !== item.value; });
          render();
        });
        chip.appendChild(remove);
        selectedBox.appendChild(chip);

        const input = document.createElement("input");
        input.type = "hidden";
        input.name = field;
        input.value = item.value;
        input.disabled = !active;
        selectedBox.appendChild(input);
      });
    }

    search.addEventListener("input", function () {
      window.clearTimeout(timer);
      const term = search.value.trim();
      results.textContent = "";
      results.classList.add("d-none");
      if (!term) return;
      timer = window.setTimeout(function () {
        fetch(endpoint + "?kind=" + encodeURIComponent(kind) + "&q=" + encodeURIComponent(term),
              { headers: { "Accept": "application/json" } })
          .then(function (response) { return response.json(); })
          .then(function (items) {
            results.textContent = "";
            items.forEach(function (item) {
              const row = document.createElement("button");
              row.type = "button";
              row.className = "list-group-item list-group-item-action text-start small";
              row.textContent = item.label + (item.extra ? " · " + item.extra : "");
              row.addEventListener("click", function () {
                if (!selected.some(function (x) { return x.value === item.value; })) {
                  selected.push({ value: item.value, label: item.label });
                  render();
                }
              });
              results.appendChild(row);
            });
            if (items.length >= 50) {
              const more = document.createElement("div");
              more.className = "list-group-item text-muted small";
              more.textContent = "仅显示前 50 条，可继续输入缩小范围";
              results.appendChild(more);
            }
            results.classList.toggle("d-none", items.length === 0);
          })
          .catch(function () { /* 搜索失败时保留当前列表 */ });
      }, 250);
    });

    if (scope) scope.addEventListener("change", render);
    render();
  });

  const fofaButton = document.querySelector("[data-fofa-import]");
  if (fofaButton) {
    const queryBox = document.getElementById("fofaQuery");
    const sizeBox = document.getElementById("fofaSize");
    const targetBox = document.getElementById("taskInput");
    const status = document.querySelector("[data-fofa-status]");

    const setStatus = function (text, kind) {
      if (!status) return;
      status.className = "small mt-1" + (kind ? " text-" + kind : "");
      status.textContent = text;
    };

    const importTargets = function () {
      const query = (queryBox.value || "").trim();
      if (!query) {
        setStatus("请先填写 FOFA 查询语句", "danger");
        queryBox.focus();
        return;
      }
      const limit = parseInt(sizeBox.value, 10) || 50;
      fofaButton.disabled = true;
      setStatus("正在查询 FOFA…", "muted");
      fetch(fofaButton.getAttribute("data-endpoint"), {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ query: query, limit: limit })
      })
        .then(function (response) {
          return readJson(response).then(function (data) {
            if (!response.ok) throw new Error(data.error || ("HTTP " + response.status));
            return data;
          });
        })
        .then(function (data) {
          const lines = targetBox.value.split(/\r?\n/).map(function (line) { return line.trim(); })
            .filter(Boolean);
          const seen = new Set(lines);
          let added = 0;
          (data.urls || []).forEach(function (url) {
            if (!seen.has(url)) {
              seen.add(url);
              lines.push(url);
              added += 1;
            }
          });
          targetBox.value = lines.join("\n");
          const fetched = (data.urls || []).length;
          let message = added ? "已导入 " + added + " 个目标" : "没有新增目标（可能都已在列表中）";
          if (data.total && data.total > fetched) {
            message += "；FOFA 共 " + data.total + " 条，可提高数量或缩小查询范围";
          }
          setStatus(message, added ? "success" : "muted");
        })
        .catch(function (error) { setStatus("导入失败：" + error.message, "danger"); })
        .finally(function () { fofaButton.disabled = false; });
    };

    fofaButton.addEventListener("click", importTargets);
    queryBox.addEventListener("keydown", function (event) {
      // 查询框里回车只触发导入，别把整个任务表单提交了
      if (event.key === "Enter" && !event.isComposing) {
        event.preventDefault();
        importTargets();
      }
    });
  }

  const modeRadios = document.querySelectorAll('input[name="scan_mode"]');
  const pocPanel = document.querySelector("[data-mode-panel]");
  if (modeRadios.length && pocPanel) {
    const syncMode = function () {
      const checked = document.querySelector('input[name="scan_mode"]:checked');
      const runsPoc = checked && ["vuln", "targeted"].indexOf(checked.value) >= 0;
      pocPanel.classList.toggle("d-none", !runsPoc);
      pocPanel.querySelectorAll("input, button").forEach(function (element) {
        element.disabled = !runsPoc;
      });
      const hint = document.querySelector("[data-mode-hint]");
      if (hint) hint.classList.toggle("d-none", !runsPoc);
    };
    modeRadios.forEach(function (radio) { radio.addEventListener("change", syncMode); });
    syncMode();
  }

  const host = document.getElementById("taskLive");
  if (host) {
    const endpoint = host.getAttribute("data-endpoint");
    const hint = document.getElementById("liveHint");
    const progress = document.querySelector("[data-live-progress]");
    let stopped = host.getAttribute("data-finished") === "true";
    let busy = false;
    let timer = null;

    const tick = function () {
      // 上一次请求还没回来或页面在后台时跳过，避免慢任务把请求堆满
      if (stopped || busy || document.hidden) return;
      busy = true;
      fetch(endpoint, { headers: { "Accept": "application/json" } })
        .then(function (response) { return response.json(); })
        .then(function (data) {
          // 进度卡和结果数在 #taskLive 之外，按文档查询而不是只查 host
          document.querySelectorAll("[data-live]").forEach(function (node) {
            const key = node.getAttribute("data-live");
            if (data[key] !== undefined && data[key] !== null) node.textContent = data[key];
          });
          const counts = data.severity_counts || {};
          document.querySelectorAll("[data-live-severity]").forEach(function (node) {
            const key = node.getAttribute("data-live-severity");
            if (counts[key] !== undefined) node.textContent = counts[key];
          });
          const bar = progress && progress.querySelector(".progress-bar");
          if (bar) {
            bar.style.width = (data.progress || 0) + "%";
            bar.textContent = (data.progress || 0) + "%";
          }
          if (hint) hint.textContent = "自动刷新中 · 结果 " + (data.findings || 0) + " 条 · " + new Date().toLocaleTimeString();
          if (data.finished) {
            stopped = true;
            window.clearInterval(timer);
            window.location.reload();
          }
        })
        .catch(function () {
          if (hint) hint.textContent = "自动刷新暂停：任务可能已被删除或服务已重启";
        })
        .finally(function () { busy = false; });
    };

    const start = function () {
      if (stopped) return;
      window.clearInterval(timer);
      timer = window.setInterval(tick, 3000);
      if (hint) hint.textContent = "自动刷新中，页面停留即可看到最新进度";
    };

    start();
    window.addEventListener("pagehide", function () { window.clearInterval(timer); });
    // bfcache 恢复后 pagehide 已清掉定时器，需要重新启动，否则进度永久停住
    window.addEventListener("pageshow", function (event) {
      if (event.persisted) start();
    });
  }
  const actionHost = document.getElementById("pocActionModal");
  if (actionHost && window.bootstrap) {
    const modal = new window.bootstrap.Modal(actionHost);
    const titleBox = document.getElementById("pocActionTitle");
    const targetBox = document.getElementById("pocActionTarget");
    const fieldsBox = document.getElementById("pocActionFields");
    const statusBox = document.getElementById("pocActionStatus");
    const outputBox = document.getElementById("pocActionOutput");
    const runButton = document.getElementById("pocActionRun");
    let context = null;

    document.addEventListener("click", function (event) {
      const trigger = event.target.closest("[data-poc-action]");
      if (trigger) {
        openPanel(trigger.getAttribute("data-poc-action"), trigger.getAttribute("data-panel"),
                  trigger.getAttribute("data-exec"));
      }
    });

    function openPanel(mode, panelUrl, execUrl) {
      context = { mode: mode, exec: execUrl, poc: null };
      statusBox.textContent = "正在读取 POC 参数…";
      outputBox.textContent = "尚无输出";
      fetch(panelUrl, { headers: { "Accept": "application/json" } })
        .then(readJson)
        .then(function (data) {
          context.poc = data.poc || {};
          const label = data.poc.name || data.poc.poc_id || "";
          titleBox.textContent = (mode === "command" ? "命令控制台 · " : "攻击执行 · ") + label;
          targetBox.textContent = data.target_url;
          renderFields(mode, context.poc);
          renderEntries((data.actions || []).slice().reverse());
          if (context.poc.exists && context.poc.loadable === false) {
            runButton.disabled = true;
            statusBox.textContent = "pocsuite3 不会加载这个脚本："
              + (context.poc.load_error || "正文里没有 register_poc 调用");
            return;
          }
          runButton.disabled = false;
          statusBox.textContent = (data.actions || []).length
            ? "已载入 " + data.actions.length + " 条历史执行"
            : "尚无执行记录";
        })
        .catch(function (error) { statusBox.textContent = "读取失败：" + error.message; });
      modal.show();
    }

    function renderFields(mode, poc) {
      fieldsBox.textContent = "";
      const options = mode === "command"
        ? [{ name: "command", label: "命令（写入 POC 参数 " + poc.command_option + "）",
             default: commandDefault(poc) }]
        : (poc.options || []).map(function (option) {
            return { name: option.name,
                     label: option.name + (option.description ? " · " + option.description : ""),
                     default: option.default };
          });
      if (!options.length) {
        const hint = document.createElement("div");
        hint.className = "small text-muted";
        hint.textContent = "该 POC 没有可填写的参数，直接执行即可";
        fieldsBox.appendChild(hint);
        return;
      }
      options.forEach(function (option) {
        const cell = document.createElement("div");
        cell.className = option.name === "command" ? "col-12" : "col-md-6";
        const label = document.createElement("label");
        label.className = "form-label small mb-1";
        label.textContent = option.label;
        const input = document.createElement("input");
        input.className = "form-control form-control-sm";
        input.value = option.default || "";
        input.setAttribute("data-option", option.name);
        cell.appendChild(label);
        cell.appendChild(input);
        fieldsBox.appendChild(cell);
      });
    }

    function commandDefault(poc) {
      const hit = (poc.options || []).filter(function (option) {
        return option.name === poc.command_option;
      })[0];
      return hit ? hit.default : "";
    }

    function collectOptions() {
      const options = {};
      fieldsBox.querySelectorAll("[data-option]").forEach(function (input) {
        options[input.getAttribute("data-option")] = input.value;
      });
      return options;
    }

    fieldsBox.addEventListener("keydown", function (event) {
      if (event.key === "Enter" && !event.isComposing) {
        event.preventDefault();
        // 参数框回车直接执行 attack 风险太高，至少让用户确认一次
        if (window.confirm("确认立即执行该操作？可能对目标写入文件或执行命令。")) runButton.click();
      }
    });

    runButton.addEventListener("click", function () {
      if (!context) return;
      runButton.disabled = true;
      statusBox.textContent = "执行中…单发执行与扫描任务共用同一把 POC 锁，可能排队";
      fetch(context.exec, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ mode: context.mode, options: collectOptions() })
      })
        .then(readJson)
        .then(function (data) {
          if (data.error) {
            statusBox.textContent = data.error;
            return;
          }
          renderEntries([data.action]);
          statusBox.textContent = (data.action.status === "success" ? "执行成功 · " : "未成功 · ")
            + data.action.duration_ms + " ms";
        })
        .catch(function (error) { statusBox.textContent = "执行失败：" + error.message; })
        .finally(function () { runButton.disabled = false; });
    });

    function renderEntries(entries) {
      if (!entries.length) return;
      if (outputBox.textContent === "尚无输出") outputBox.textContent = "";
      entries.forEach(function (entry) {
        const block = document.createElement("div");
        block.className = "console-entry mb-2";
        const head = document.createElement("div");
        head.className = "fw-semibold";
        head.textContent = "#" + entry.id + " " + (entry.mode === "command" ? "命令" : "攻击")
          + " · " + entry.created_at + " · " + entry.duration_ms + "ms · "
          + (entry.status === "success" ? "成功" : "未成功");
        const command = document.createElement("div");
        command.textContent = "$ " + formatCommand(entry);
        const body = document.createElement("div");
        const chunks = [];
        if (entry.error) chunks.push(entry.error);
        if (Object.keys(entry.output || {}).length) {
          chunks.push(JSON.stringify(entry.output, null, 2));
        }
        body.textContent = chunks.length ? chunks.join("\n\n") : "POC 未返回内容";
        block.append(head, command, body);
        const packets = packetDetails(entry.packets);
        if (packets) block.append(packets);
        outputBox.appendChild(block);
      });
      outputBox.scrollTop = outputBox.scrollHeight;
    }
  } else if (actionHost) {
    // CDN 不可达时至少给出明确提示，不要让按钮点了完全没反应
    document.addEventListener("click", function (event) {
      if (event.target.closest("[data-poc-action]")) {
        window.alert("Bootstrap 脚本未加载，交互执行窗口不可用。请检查网络或改用离线部署。");
      }
    });
  }

  function packetDetails(packets) {
    if (!packets || !packets.length) return null;
    const details = document.createElement("details");
    details.className = "mt-2";
    const summary = document.createElement("summary");
    summary.className = "small text-muted";
    summary.textContent = "HTTP 报文 · " + packets.length
      + " 次请求/响应（POC 输出被截断时可在这里查看原始内容）";
    const pre = document.createElement("pre");
    pre.className = "evidence evidence-sm mt-2 mb-0";
    pre.textContent = packets.map(function (packet) {
      return "===== 请求 " + packet.index + "/" + packet.total + " =====\n" + packet.request
        + "\n\n===== 响应 " + packet.index + "/" + packet.total + " =====\n" + packet.response;
    }).join("\n\n");
    details.append(summary, pre);
    return details;
  }

  function readJson(response) {
    return response.json().catch(function () {
      throw new Error("服务返回了非 JSON 内容（HTTP " + response.status + "）");
    });
  }

  function formatCommand(entry) {
    const pairs = Object.entries(entry.options || {});
    if (!pairs.length) return "（无参数）";
    if (entry.mode === "command") return pairs[0][1];
    return pairs.map(function (pair) { return pair[0] + "=" + pair[1]; }).join("  ");
  }
})();
