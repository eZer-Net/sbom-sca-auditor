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
    """Write a standalone interactive dependency explorer.

    Graph structure is derived from CycloneDX components/dependencies. Vulnerable
    nodes are correlated from the Trivy findings passed to this function. The
    explorer starts compact and expands dependencies on demand; a second view
    shows only dependency paths that lead from the project root to vulnerable
    components.
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
  header { position: sticky; top: 0; z-index: 5; min-height: 60px; padding: 10px 16px; background: rgba(255,255,255,.97); border-bottom: 1px solid #d1d5db; display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
  header strong { font-size: 18px; }
  .legend { font-size: 13px; color: #4b5563; white-space: nowrap; }
  .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin: 0 5px 0 12px; vertical-align: -1px; }
  .normal-dot { background: #2563eb; }
  .vuln-dot { background: #dc2626; }
  .root-dot { background: #111827; }
  .controls { margin-left: auto; display: flex; align-items: center; gap: 8px; font-size: 13px; flex-wrap: wrap; }
  button { border: 1px solid #cbd5e1; background: #fff; color: #334155; border-radius: 6px; padding: 6px 10px; cursor: pointer; }
  button.active { background: #111827; border-color: #111827; color: #fff; }
  #stats { color: #64748b; min-width: 180px; text-align: right; }
  #viewport { width: 100vw; height: calc(100vh - 61px); overflow: auto; background: #f8fafc; }
  svg { display: block; }
  .edge { stroke: #2563eb; stroke-width: 1.8; fill: none; opacity: .88; }
  .node-card { fill: #fff; stroke: #93c5fd; stroke-width: 1.5; cursor: pointer; }
  .node-card:hover { stroke: #1d4ed8; stroke-width: 2.2; }
  .node-card.root { stroke: #111827; }
  .node-card.vulnerable { stroke: #fca5a5; }
  .node-dot.normal { fill: #2563eb; }
  .node-dot.vulnerable { fill: #dc2626; }
  .node-dot.root { fill: #111827; }
  .node-label { font-size: 12px; font-weight: 600; fill: #111827; pointer-events: none; }
  .node-version { font-size: 10px; fill: #64748b; pointer-events: none; }
  .toggle { font-size: 14px; font-weight: 700; fill: #475569; pointer-events: none; }
  .cycle-label { font-size: 10px; fill: #b45309; pointer-events: none; }
  #tooltip { position: fixed; display: none; max-width: 520px; white-space: pre-line; padding: 10px 12px; background: #111827; color: #fff; border-radius: 7px; font-size: 13px; line-height: 1.45; pointer-events: none; z-index: 20; box-shadow: 0 4px 18px rgba(0,0,0,.25); }
  #empty { margin: 24px; padding: 14px 16px; border: 1px solid #e2e8f0; background: #fff; color: #475569; border-radius: 8px; display: none; }
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
    <button id="explorerBtn" class="active" type="button">Dependency Explorer</button>
    <button id="vulnBtn" type="button">Vulnerable paths only</button>
    <button id="zoomOutBtn" type="button" title="Zoom out">−</button>
    <button id="zoomResetBtn" type="button" title="Reset zoom">100%</button>
    <button id="zoomInBtn" type="button" title="Zoom in">+</button>
    <button id="resetBtn" type="button">Reset view</button>
    <span id="stats"></span>
  </div>
</header>
<div id="viewport"><div id="empty"></div><div id="error"></div><svg id="graph" xmlns="http://www.w3.org/2000/svg"></svg></div>
<div id="tooltip"></div>
<script id="graph-data" type="application/json">__PAYLOAD__</script>
<script>
(() => {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';
  const viewport = document.getElementById('viewport');
  const svg = document.getElementById('graph');
  const tooltip = document.getElementById('tooltip');
  const emptyBox = document.getElementById('empty');
  const errorBox = document.getElementById('error');
  const stats = document.getElementById('stats');
  const explorerBtn = document.getElementById('explorerBtn');
  const vulnBtn = document.getElementById('vulnBtn');
  const zoomOutBtn = document.getElementById('zoomOutBtn');
  const zoomResetBtn = document.getElementById('zoomResetBtn');
  const zoomInBtn = document.getElementById('zoomInBtn');
  const resetBtn = document.getElementById('resetBtn');

  const CARD_W = 158;
  const CARD_H = 42;
  const X_GAP = 34;
  const Y_GAP = 88;
  const MARGIN_X = 36;
  const MARGIN_Y = 34;
  const MIN_ZOOM = 0.25;
  const MAX_ZOOM = 2.5;
  const ZOOM_STEP = 0.1;
  let zoom = 1;
  let baseWidth = 960;
  let baseHeight = 600;


  function clampZoom(value) {
    return Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, value));
  }

  function updateZoomLabel() {
    zoomResetBtn.textContent = `${Math.round(zoom * 100)}%`;
  }

  function applySvgSize() {
    svg.setAttribute('width', String(Math.max(1, baseWidth * zoom)));
    svg.setAttribute('height', String(Math.max(1, baseHeight * zoom)));
    svg.setAttribute('viewBox', `0 0 ${baseWidth} ${baseHeight}`);
    updateZoomLabel();
  }

  function setZoom(nextZoom, clientX = null, clientY = null) {
    const oldZoom = zoom;
    const newZoom = clampZoom(nextZoom);
    if (Math.abs(newZoom - oldZoom) < 0.0001) return;

    const rect = viewport.getBoundingClientRect();
    const anchorX = clientX == null ? rect.left + viewport.clientWidth / 2 : clientX;
    const anchorY = clientY == null ? rect.top + viewport.clientHeight / 2 : clientY;
    const localX = anchorX - rect.left;
    const localY = anchorY - rect.top;
    const graphX = (viewport.scrollLeft + localX) / oldZoom;
    const graphY = (viewport.scrollTop + localY) / oldZoom;

    zoom = newZoom;
    applySvgSize();
    viewport.scrollLeft = Math.max(0, graphX * zoom - localX);
    viewport.scrollTop = Math.max(0, graphY * zoom - localY);
  }

  function resetZoom() {
    zoom = 1;
    applySvgSize();
  }

  function showError(err) {
    svg.replaceChildren();
    errorBox.style.display = 'block';
    errorBox.textContent = `Dependency graph rendering failed.\n${err && err.message ? err.message : String(err)}`;
  }

  function severityRank(value) {
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
    return Object.prototype.hasOwnProperty.call(order, value) ? order[value] : 5;
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

    function labelForId(id) {
      const n = byId.get(id);
      return n ? `${n.name}@${n.version}` : id;
    }
    for (const values of adjacency.values()) values.sort((a, b) => labelForId(a).localeCompare(labelForId(b)));

    const vulnerableIds = new Set(data.nodes.filter(n => (n.vulnerabilities || []).length > 0).map(n => n.id));
    const expandedKeys = new Set();
    let mode = 'explorer';
    let vulnerablePathIdsCache = new Set();

    function shortName(value, max = 22) {
      if (!value) return '?';
      return value.length > max ? `${value.slice(0, max - 1)}…` : value;
    }

    function tooltipText(n) {
      let text = `${n.name}@${n.version}`;
      const vulns = [...(n.vulnerabilities || [])].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || String(a.id).localeCompare(String(b.id)));
      if (vulns.length) {
        for (const v of vulns) text += `\n${v.severity}  ${v.id}  fix: ${v.fixed_version || 'not specified'}`;
      } else {
        text += `\nNo HIGH/CRITICAL vulnerability in this scan`;
      }
      return text;
    }

    function vulnerablePathIds() {
      const keep = new Set(vulnerableIds);
      const queue = [...vulnerableIds];
      for (let i = 0; i < queue.length; i++) {
        for (const parent of reverse.get(queue[i]) || []) {
          if (!keep.has(parent)) {
            keep.add(parent);
            queue.push(parent);
          }
        }
      }
      if (data.root) keep.add(data.root);
      return keep;
    }

    function buildOccurrence(id, key, depth, stack, vulnerableOnly, keep) {
      const node = byId.get(id);
      const occurrence = { id, key, depth, node, children: [], cycle: false, leafCount: 1, x: 0, y: 0 };
      if (!node) return occurrence;
      const pathStack = new Set(stack);
      if (pathStack.has(id)) {
        occurrence.cycle = true;
        return occurrence;
      }
      pathStack.add(id);

      const shouldExpand = vulnerableOnly || expandedKeys.has(key);
      if (!shouldExpand) return occurrence;

      let childIds = adjacency.get(id) || [];
      if (vulnerableOnly) childIds = childIds.filter(child => keep.has(child));
      childIds.forEach((childId, index) => {
        occurrence.children.push(buildOccurrence(childId, `${key}/${index}:${childId}`, depth + 1, pathStack, vulnerableOnly, keep));
      });
      return occurrence;
    }

    function computeLeafCounts(item) {
      if (!item.children.length) {
        item.leafCount = 1;
        return 1;
      }
      item.leafCount = item.children.reduce((sum, child) => sum + computeLeafCounts(child), 0);
      return item.leafCount;
    }

    function assignPositions(item, startLeaf) {
      item.y = MARGIN_Y + item.depth * Y_GAP;
      if (!item.children.length) {
        item.x = MARGIN_X + startLeaf * (CARD_W + X_GAP) + CARD_W / 2;
        return startLeaf + 1;
      }
      let cursor = startLeaf;
      for (const child of item.children) cursor = assignPositions(child, cursor);
      item.x = (item.children[0].x + item.children[item.children.length - 1].x) / 2;
      return cursor;
    }

    function flatten(item, nodes, edges) {
      nodes.push(item);
      for (const child of item.children) {
        edges.push({ from: item, to: child });
        flatten(child, nodes, edges);
      }
    }

    function positionTooltip(ev) {
      const pad = 14;
      const tw = tooltip.offsetWidth || 300;
      const th = tooltip.offsetHeight || 80;
      let left = ev.clientX + pad;
      let top = ev.clientY + pad;
      if (left + tw > window.innerWidth - 8) left = ev.clientX - tw - pad;
      if (top + th > window.innerHeight - 8) top = ev.clientY - th - pad;
      tooltip.style.left = `${Math.max(8, left)}px`;
      tooltip.style.top = `${Math.max(8, top)}px`;
    }

    function drawEdge(layer, edge) {
      const a = edge.from;
      const b = edge.to;
      const path = document.createElementNS(NS, 'path');
      const startY = a.y + CARD_H;
      const endY = b.y;
      const midY = (startY + endY) / 2;
      path.setAttribute('class', 'edge');
      path.setAttribute('d', `M ${a.x} ${startY} C ${a.x} ${midY}, ${b.x} ${midY}, ${b.x} ${endY}`);
      layer.appendChild(path);
    }

    function drawNode(layer, item, vulnerableOnly) {
      const n = item.node;
      if (!n) return;
      const g = document.createElementNS(NS, 'g');
      g.setAttribute('transform', `translate(${item.x - CARD_W / 2},${item.y})`);
      const isRoot = item.id === data.root;
      const isVulnerable = vulnerableIds.has(item.id);
      const hasChildren = (adjacency.get(item.id) || []).some(child => !vulnerableOnly || vulnerablePathIdsCache.has(child));
      const isExpanded = vulnerableOnly || expandedKeys.has(item.key);

      const rect = document.createElementNS(NS, 'rect');
      rect.setAttribute('width', String(CARD_W));
      rect.setAttribute('height', String(CARD_H));
      rect.setAttribute('rx', '8');
      rect.setAttribute('class', `node-card${isRoot ? ' root' : ''}${isVulnerable ? ' vulnerable' : ''}`);
      g.appendChild(rect);

      const dot = document.createElementNS(NS, 'circle');
      dot.setAttribute('cx', '14');
      dot.setAttribute('cy', '16');
      dot.setAttribute('r', isRoot ? '5.5' : '5');
      dot.setAttribute('class', `node-dot ${isRoot ? 'root' : (isVulnerable ? 'vulnerable' : 'normal')}`);
      g.appendChild(dot);

      const label = document.createElementNS(NS, 'text');
      label.setAttribute('x', '26');
      label.setAttribute('y', '17');
      label.setAttribute('class', 'node-label');
      label.textContent = shortName(n.name);
      g.appendChild(label);

      const version = document.createElementNS(NS, 'text');
      version.setAttribute('x', '26');
      version.setAttribute('y', '32');
      version.setAttribute('class', 'node-version');
      version.textContent = shortName(n.version, 24);
      g.appendChild(version);

      if (!vulnerableOnly && hasChildren) {
        const toggle = document.createElementNS(NS, 'text');
        toggle.setAttribute('x', String(CARD_W - 16));
        toggle.setAttribute('y', '25');
        toggle.setAttribute('text-anchor', 'middle');
        toggle.setAttribute('class', 'toggle');
        toggle.textContent = isExpanded ? '−' : '+';
        g.appendChild(toggle);
      }
      if (item.cycle) {
        const cycle = document.createElementNS(NS, 'text');
        cycle.setAttribute('x', String(CARD_W - 8));
        cycle.setAttribute('y', '10');
        cycle.setAttribute('text-anchor', 'end');
        cycle.setAttribute('class', 'cycle-label');
        cycle.textContent = 'cycle';
        g.appendChild(cycle);
      }

      g.addEventListener('mouseenter', ev => {
        tooltip.textContent = tooltipText(n);
        tooltip.style.display = 'block';
        positionTooltip(ev);
      });
      g.addEventListener('mousemove', positionTooltip);
      g.addEventListener('mouseleave', () => { tooltip.style.display = 'none'; });
      if (!vulnerableOnly && hasChildren) {
        g.addEventListener('click', ev => {
          ev.stopPropagation();
          if (expandedKeys.has(item.key)) expandedKeys.delete(item.key);
          else expandedKeys.add(item.key);
          render({ preserveScroll: true });
        });
      }
      layer.appendChild(g);
    }

    function render(options = {}) {
      const preserveScroll = options.preserveScroll === true;
      const savedTop = viewport.scrollTop;
      const savedLeft = viewport.scrollLeft;
      errorBox.style.display = 'none';
      emptyBox.style.display = 'none';
      tooltip.style.display = 'none';
      svg.replaceChildren();

      if (!data.root || !byId.has(data.root)) {
        emptyBox.style.display = 'block';
        emptyBox.textContent = 'No project root was found in the SBOM.';
        stats.textContent = '0 nodes';
        return;
      }

      const vulnerableOnly = mode === 'vulnerable';
      vulnerablePathIdsCache = vulnerableOnly ? vulnerablePathIds() : new Set();
      if (vulnerableOnly && vulnerableIds.size === 0) {
        emptyBox.style.display = 'block';
        emptyBox.textContent = 'No HIGH/CRITICAL vulnerable dependencies were found in this scan.';
        stats.textContent = '0 vulnerable';
        return;
      }

      const rootKey = `root:${data.root}`;
      if (!vulnerableOnly && expandedKeys.size === 0) expandedKeys.add(rootKey);
      const root = buildOccurrence(data.root, rootKey, 0, new Set(), vulnerableOnly, vulnerablePathIdsCache);
      const leaves = computeLeafCounts(root);
      assignPositions(root, 0);
      const nodeItems = [];
      const edgeItems = [];
      flatten(root, nodeItems, edgeItems);

      const width = Math.max(viewport.clientWidth || 960, MARGIN_X * 2 + leaves * (CARD_W + X_GAP));
      const maxDepth = nodeItems.reduce((m, item) => Math.max(m, item.depth), 0);
      const height = Math.max(viewport.clientHeight || 600, MARGIN_Y * 2 + (maxDepth + 1) * Y_GAP + CARD_H);
      baseWidth = width;
      baseHeight = height;
      applySvgSize();

      const edgeLayer = document.createElementNS(NS, 'g');
      const nodeLayer = document.createElementNS(NS, 'g');
      svg.appendChild(edgeLayer);
      svg.appendChild(nodeLayer);
      edgeItems.forEach(edge => drawEdge(edgeLayer, edge));
      nodeItems.forEach(item => drawNode(nodeLayer, item, vulnerableOnly));

      const shownVulnerable = new Set(nodeItems.filter(item => vulnerableIds.has(item.id)).map(item => item.id)).size;
      if (vulnerableOnly) stats.textContent = `${nodeItems.length} path nodes · ${shownVulnerable} vulnerable`;
      else stats.textContent = `${nodeItems.length} visible nodes · click a library to expand`;

      if (preserveScroll) viewport.scrollTo({ top: savedTop, left: savedLeft });
      else viewport.scrollTo({ top: 0, left: 0 });
    }

    zoomOutBtn.addEventListener('click', () => setZoom(zoom - ZOOM_STEP));
    zoomInBtn.addEventListener('click', () => setZoom(zoom + ZOOM_STEP));
    zoomResetBtn.addEventListener('click', () => setZoom(1));
    viewport.addEventListener('wheel', ev => {
      if (!(ev.ctrlKey || ev.metaKey)) return;
      ev.preventDefault();
      const factor = Math.exp(-ev.deltaY * 0.0025);
      setZoom(zoom * factor, ev.clientX, ev.clientY);
    }, { passive: false });

    explorerBtn.addEventListener('click', () => {
      mode = 'explorer';
      explorerBtn.classList.add('active');
      vulnBtn.classList.remove('active');
      expandedKeys.clear();
      render();
    });
    vulnBtn.addEventListener('click', () => {
      mode = 'vulnerable';
      vulnBtn.classList.add('active');
      explorerBtn.classList.remove('active');
      render();
    });
    resetBtn.addEventListener('click', () => {
      tooltip.style.display = 'none';
      zoom = 1;
      if (mode === 'explorer') expandedKeys.clear();
      render();
    });
    window.addEventListener('keydown', ev => {
      if (ev.key === 'Escape') {
        tooltip.style.display = 'none';
        if (mode === 'explorer') expandedKeys.clear();
        render({ preserveScroll: true });
      }
    });
    window.addEventListener('resize', () => {
      window.clearTimeout(window.__graphResizeTimer);
      window.__graphResizeTimer = window.setTimeout(() => render({ preserveScroll: true }), 120);
    });

    render();
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
