from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Dict, Iterable, List


def _iter_components(items: Iterable[dict]) -> Iterable[dict]:
    for item in items or []:
        if not isinstance(item, dict):
            continue
        yield item
        children = item.get("components")
        if isinstance(children, list):
            yield from _iter_components(children)


def _graph_data(sbom: dict, vulnerabilities: List[dict]) -> dict:
    metadata = sbom.get("metadata") or {}
    root = metadata.get("component") or {}
    root_ref = str(root.get("bom-ref") or "")

    components: Dict[str, dict] = {}
    if isinstance(root, dict) and root_ref:
        components[root_ref] = root
    for comp in _iter_components(sbom.get("components") or []):
        ref = str(comp.get("bom-ref") or "")
        if ref:
            components[ref] = comp

    vuln_index: Dict[tuple[str, str], List[dict]] = {}
    for finding in vulnerabilities:
        key = (str(finding.get("library") or "").lower(), str(finding.get("installed_version") or ""))
        vuln_index.setdefault(key, []).append({
            "id": str(finding.get("id") or ""),
            "severity": str(finding.get("severity") or "UNKNOWN"),
            "fixed_version": finding.get("fixed_version"),
        })

    nodes = []
    for ref, comp in components.items():
        name = str(comp.get("name") or "?")
        version = str(comp.get("version") or "?")
        vulns = vuln_index.get((name.lower(), version), [])
        nodes.append({
            "id": ref,
            "name": name,
            "version": version,
            "type": str(comp.get("type") or "library"),
            "vulnerabilities": vulns,
        })

    edges = []
    known = set(components)
    for dep in sbom.get("dependencies") or []:
        if not isinstance(dep, dict):
            continue
        parent = str(dep.get("ref") or "")
        if parent not in known:
            continue
        for child in dep.get("dependsOn") or []:
            child = str(child)
            if child in known:
                edges.append({"from": parent, "to": child})

    return {"root": root_ref, "nodes": nodes, "edges": edges}


def write_dependency_graph_html(path: Path, sbom: dict, vulnerabilities: List[dict]) -> None:
    """Write a standalone interactive top-down SVG dependency graph.

    The file has no external JS/CSS dependencies. Vulnerable components are red.
    Hovering a node shows package/version and correlated vulnerability IDs,
    severities and fixed versions. Wide dependency levels are wrapped so large
    repositories remain visible without a tens-of-thousands-pixel canvas.
    """
    data = _graph_data(sbom, vulnerabilities)
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    title = html.escape(str(((sbom.get("metadata") or {}).get("component") or {}).get("name") or "Dependency graph"))

    document = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__ dependency graph</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #fff; color: #111827; }
  header { position: sticky; top: 0; z-index: 5; min-height: 58px; padding: 10px 16px; background: rgba(255,255,255,.97); border-bottom: 1px solid #d1d5db; display: flex; align-items: center; gap: 18px; flex-wrap: wrap; }
  header strong { font-size: 18px; }
  .legend { font-size: 13px; color: #4b5563; white-space: nowrap; }
  .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin: 0 5px 0 12px; vertical-align: -1px; }
  .normal-dot { background: #64748b; }
  .vuln-dot { background: #dc2626; }
  .root-dot { background: #111827; }
  .controls { margin-left: auto; display: flex; align-items: center; gap: 8px; font-size: 13px; }
  button { border: 1px solid #cbd5e1; background: #fff; color: #334155; border-radius: 6px; padding: 6px 10px; cursor: pointer; }
  button.active { background: #111827; border-color: #111827; color: #fff; }
  #stats { color: #64748b; min-width: 160px; text-align: right; }
  #viewport { width: 100vw; height: calc(100vh - 59px); overflow: auto; background: #f8fafc; }
  svg { display: block; min-width: 100%; }
  .edge { stroke: #cbd5e1; stroke-width: 1; fill: none; opacity: .65; }
  .edge.to-vulnerable { stroke: #fca5a5; opacity: .9; }
  .node { stroke: #fff; stroke-width: 1.5; cursor: pointer; transition: r .08s ease, stroke-width .08s ease; }
  .node.normal { fill: #64748b; }
  .node.vulnerable { fill: #dc2626; }
  .node.root { fill: #111827; }
  .node:hover { stroke: #111827; stroke-width: 3; }
  .node-ring { fill: none; stroke: #fecaca; stroke-width: 2; opacity: .8; pointer-events: none; }
  #tooltip { position: fixed; display: none; max-width: 520px; white-space: pre-line; padding: 10px 12px; background: #111827; color: white; border-radius: 7px; font-size: 13px; line-height: 1.45; pointer-events: none; z-index: 20; box-shadow: 0 4px 18px rgba(0,0,0,.25); }
  #error { margin: 24px; padding: 14px 16px; border: 1px solid #fecaca; background: #fef2f2; color: #991b1b; border-radius: 8px; display: none; white-space: pre-wrap; }
  @media (max-width: 900px) {
    .controls { margin-left: 0; width: 100%; }
    #stats { margin-left: auto; }
  }
</style>
</head>
<body>
<header>
  <strong>__TITLE__</strong>
  <span class="legend"><span class="dot root-dot"></span>service/root<span class="dot normal-dot"></span>dependency<span class="dot vuln-dot"></span>vulnerable dependency</span>
  <div class="controls">
    <button id="allBtn" class="active" type="button">All dependencies</button>
    <button id="vulnBtn" type="button">Vulnerable paths only</button>
    <span id="stats"></span>
  </div>
</header>
<div id="viewport"><div id="error"></div><svg id="graph" xmlns="http://www.w3.org/2000/svg"></svg></div>
<div id="tooltip"></div>
<script id="graph-data" type="application/json">__PAYLOAD__</script>
<script>
(() => {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';
  const viewport = document.getElementById('viewport');
  const svg = document.getElementById('graph');
  const tooltip = document.getElementById('tooltip');
  const errorBox = document.getElementById('error');
  const stats = document.getElementById('stats');
  const allBtn = document.getElementById('allBtn');
  const vulnBtn = document.getElementById('vulnBtn');

  function showError(err) {
    svg.replaceChildren();
    errorBox.style.display = 'block';
    errorBox.textContent = `Dependency graph rendering failed.\n${err && err.message ? err.message : String(err)}`;
  }

  try {
    const data = JSON.parse(document.getElementById('graph-data').textContent);
    const byId = new Map(data.nodes.map(n => [n.id, n]));
    const adjacency = new Map(data.nodes.map(n => [n.id, []]));
    const reverse = new Map(data.nodes.map(n => [n.id, []]));
    for (const e of data.edges) {
      if (adjacency.has(e.from) && byId.has(e.to)) adjacency.get(e.from).push(e.to);
      if (reverse.has(e.to) && byId.has(e.from)) reverse.get(e.to).push(e.from);
    }

    const vulnerableIds = new Set(data.nodes.filter(n => (n.vulnerabilities || []).length > 0).map(n => n.id));

    function vulnerablePathIds() {
      const keep = new Set(vulnerableIds);
      const q = [...vulnerableIds];
      for (let i = 0; i < q.length; i++) {
        for (const parent of reverse.get(q[i]) || []) {
          if (!keep.has(parent)) { keep.add(parent); q.push(parent); }
        }
      }
      if (data.root) keep.add(data.root);
      return keep;
    }

    function tooltipText(n) {
      let text = `${n.name}@${n.version}`;
      const vulns = n.vulnerabilities || [];
      if (vulns.length) {
        for (const v of vulns) {
          text += `\n${v.severity}  ${v.id}  fix: ${v.fixed_version || 'not specified'}`;
        }
      } else {
        text += `\nNo HIGH/CRITICAL vulnerability in this scan`;
      }
      return text;
    }

    function render(mode) {
      errorBox.style.display = 'none';
      tooltip.style.display = 'none';
      svg.replaceChildren();

      const keep = mode === 'vulnerable' ? vulnerablePathIds() : new Set(data.nodes.map(n => n.id));
      const nodes = data.nodes.filter(n => keep.has(n.id));
      const edges = data.edges.filter(e => keep.has(e.from) && keep.has(e.to));
      const visible = new Set(nodes.map(n => n.id));

      const level = new Map();
      if (data.root && visible.has(data.root)) {
        level.set(data.root, 0);
        const q = [data.root];
        for (let i = 0; i < q.length; i++) {
          const current = q[i];
          const nextLevel = level.get(current) + 1;
          for (const child of adjacency.get(current) || []) {
            if (!visible.has(child)) continue;
            if (!level.has(child) || nextLevel < level.get(child)) {
              level.set(child, nextLevel);
              q.push(child);
            }
          }
        }
      }

      let fallbackLevel = Math.max(0, ...level.values());
      for (const n of nodes) if (!level.has(n.id)) level.set(n.id, ++fallbackLevel);

      const groups = new Map();
      for (const n of nodes) {
        const l = level.get(n.id);
        if (!groups.has(l)) groups.set(l, []);
        groups.get(l).push(n);
      }
      for (const arr of groups.values()) {
        arr.sort((a, b) => {
          const av = (a.vulnerabilities || []).length ? 0 : 1;
          const bv = (b.vulnerabilities || []).length ? 0 : 1;
          return av - bv || `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`);
        });
      }

      const marginX = 42;
      const marginY = 42;
      const xGap = 62;
      const rowGap = 54;
      const levelGap = 78;
      const viewportWidth = Math.max(960, viewport.clientWidth || window.innerWidth || 1200);
      const width = viewportWidth;
      const maxCols = Math.max(10, Math.floor((width - marginX * 2) / xGap));
      const pos = new Map();
      let yCursor = marginY;

      for (const [l, arr] of [...groups.entries()].sort((a, b) => a[0] - b[0])) {
        const chunks = [];
        for (let i = 0; i < arr.length; i += maxCols) chunks.push(arr.slice(i, i + maxCols));
        for (const chunk of chunks) {
          const rowWidth = Math.max(0, (chunk.length - 1) * xGap);
          const startX = (width - rowWidth) / 2;
          chunk.forEach((n, i) => pos.set(n.id, { x: startX + i * xGap, y: yCursor }));
          yCursor += rowGap;
        }
        yCursor += levelGap;
      }

      const height = Math.max(viewport.clientHeight || 600, yCursor + marginY);
      svg.setAttribute('width', String(width));
      svg.setAttribute('height', String(height));
      svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

      const edgeLayer = document.createElementNS(NS, 'g');
      const nodeLayer = document.createElementNS(NS, 'g');
      svg.appendChild(edgeLayer);
      svg.appendChild(nodeLayer);

      for (const e of edges) {
        const a = pos.get(e.from), b = pos.get(e.to);
        if (!a || !b) continue;
        const midY = (a.y + b.y) / 2;
        const path = document.createElementNS(NS, 'path');
        path.setAttribute('class', `edge${vulnerableIds.has(e.to) ? ' to-vulnerable' : ''}`);
        path.setAttribute('d', `M ${a.x} ${a.y} C ${a.x} ${midY}, ${b.x} ${midY}, ${b.x} ${b.y}`);
        edgeLayer.appendChild(path);
      }

      for (const n of nodes) {
        const p = pos.get(n.id);
        if (!p) continue;
        const isRoot = n.id === data.root;
        const isVulnerable = (n.vulnerabilities || []).length > 0;
        if (isVulnerable) {
          const ring = document.createElementNS(NS, 'circle');
          ring.setAttribute('cx', p.x); ring.setAttribute('cy', p.y); ring.setAttribute('r', '10');
          ring.setAttribute('class', 'node-ring');
          nodeLayer.appendChild(ring);
        }
        const c = document.createElementNS(NS, 'circle');
        c.setAttribute('cx', p.x); c.setAttribute('cy', p.y);
        c.setAttribute('r', isRoot ? '9' : (isVulnerable ? '7' : '5'));
        c.setAttribute('class', `node ${isRoot ? 'root' : (isVulnerable ? 'vulnerable' : 'normal')}`);
        c.addEventListener('mouseenter', () => {
          tooltip.textContent = tooltipText(n);
          tooltip.style.display = 'block';
        });
        c.addEventListener('mousemove', ev => {
          const pad = 14;
          const tw = tooltip.offsetWidth || 300;
          const th = tooltip.offsetHeight || 80;
          let left = ev.clientX + pad;
          let top = ev.clientY + pad;
          if (left + tw > window.innerWidth - 8) left = ev.clientX - tw - pad;
          if (top + th > window.innerHeight - 8) top = ev.clientY - th - pad;
          tooltip.style.left = `${Math.max(8, left)}px`;
          tooltip.style.top = `${Math.max(8, top)}px`;
        });
        c.addEventListener('mouseleave', () => { tooltip.style.display = 'none'; });
        nodeLayer.appendChild(c);
      }

      const vulnCount = nodes.filter(n => (n.vulnerabilities || []).length > 0).length;
      stats.textContent = `${nodes.length} nodes · ${edges.length} edges · ${vulnCount} vulnerable`;
      viewport.scrollTo({ top: 0, left: 0 });
    }

    allBtn.addEventListener('click', () => {
      allBtn.classList.add('active');
      vulnBtn.classList.remove('active');
      render('all');
    });
    vulnBtn.addEventListener('click', () => {
      vulnBtn.classList.add('active');
      allBtn.classList.remove('active');
      render('vulnerable');
    });
    window.addEventListener('resize', () => {
      window.clearTimeout(window.__graphResizeTimer);
      window.__graphResizeTimer = window.setTimeout(() => render(vulnBtn.classList.contains('active') ? 'vulnerable' : 'all'), 120);
    });

    render('all');
  } catch (err) {
    showError(err);
  }
})();
</script>
</body>
</html>
'''
    document = document.replace("__TITLE__", title).replace("__PAYLOAD__", payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")
