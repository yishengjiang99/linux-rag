// All user and model text goes through textContent; nothing is parsed as HTML.
const $ = (id) => document.getElementById(id);

async function api(path, body) {
  const opt = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const r = await fetch("api/" + path, { credentials: "same-origin", ...opt });
  let d = {};
  try { d = await r.json(); } catch (e) { d = { error: "bad response (" + r.status + ")" }; }
  if (!r.ok) throw new Error(d.error || "error " + r.status);
  return d;
}

function setStatus(t) { $("status").textContent = t; }

function renderSources(list) {
  const ol = $("sources");
  ol.replaceChildren();
  for (const s of list || []) {
    const li = document.createElement("li");
    li.value = s.n;
    const tag = document.createElement("span");
    tag.className = "tag " + s.corpus;
    tag.textContent = s.corpus;
    li.append(tag);
    if (s.url && s.url.startsWith("https://")) {
      const a = document.createElement("a");
      a.href = s.url; a.target = "_blank"; a.rel = "noopener noreferrer";
      a.textContent = s.label;
      li.append(a);
    } else {
      li.append(document.createTextNode(s.label));
    }
    ol.append(li);
  }
}

async function ask() {
  const q = $("q").value.trim();
  if (!q) return;
  $("ask").disabled = true;
  $("answer").textContent = "";
  renderSources([]);
  setStatus("thinking…");
  try {
    const d = await api("ask", { q });
    $("answer").textContent = d.answer;
    renderSources(d.sources);
    setStatus(d.remaining + " questions left today");
  } catch (e) {
    setStatus("");
    $("answer").textContent = e.message;
  } finally {
    $("ask").disabled = false;
  }
}

async function refresh() {
  try {
    const d = await api("status");
    $("adminstate").textContent = d.admin ? "logged in as admin" : (d.admin_enabled ? "" : "admin login not configured");
    $("files").textContent = d.files.length ? "Uploaded: " + d.files.join(", ") : "";
    setStatus(d.remaining + " questions left today");
  } catch (e) { setStatus(e.message); }
}

$("ask").onclick = ask;
$("q").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) ask(); });
for (const b of $("examples").querySelectorAll("button")) b.onclick = () => { $("q").value = b.textContent; ask(); };

$("file").onchange = async () => {
  const f = $("file").files[0];
  if (!f) return;
  if (f.size > 1000000) { $("files").textContent = "File too large (max 1 MB)."; return; }
  try {
    const text = await f.text();
    const d = await api("upload", { name: f.name, text });
    $("files").textContent = "Uploaded: " + d.files.join(", ");
  } catch (e) { $("files").textContent = e.message; }
  $("file").value = "";
};
$("clear").onclick = async () => { await api("upload/clear", {}); refresh(); };
$("login").onclick = async () => {
  try { await api("login", { password: $("pw").value }); $("pw").value = ""; } catch (e) { $("adminstate").textContent = e.message; return; }
  refresh();
};
$("logout").onclick = async () => { await api("logout", {}); refresh(); };
refresh();
