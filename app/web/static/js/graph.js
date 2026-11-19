/**
 * ZEROVANT — Screen 05: Attack Graph (Cytoscape.js DAG)
 * High-tech cybersecurity attack chain DAG with glowing nodes & bezier edges.
 */

let cy = null;
let currentScan = null;
let currentChains = [];

async function init(params) {
  const scanId = params ? (params.get('scan_id') || params.get('scanId')) : null;

  if (!scanId) {
    const statsRes = await window.api.getStats();
    if (statsRes.ok && statsRes.data.recent_scans && statsRes.data.recent_scans.length > 0) {
      return loadScanGraph(statsRes.data.recent_scans[0].id);
    }
    showEmptyGraph('No scan selected. Trigger an audit to visualize attack paths.');
    return;
  }

  await loadScanGraph(scanId);
}

async function loadScanGraph(scanId) {
  const res = await window.api.getScan(scanId);
  if (!res.ok) {
    showEmptyGraph(`Failed to load attack graph for scan '${scanId}'.`);
    return;
  }

  currentScan = res.data;
  currentChains = currentScan.chains || [];

  // Populate Chain Selector Dropdown
  const selectEl = document.getElementById('chain-filter-select');
  if (selectEl) {
    while (selectEl.firstChild) selectEl.removeChild(selectEl.firstChild);

    if (currentChains.length === 0) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = 'No Attack Chains Correlated';
      selectEl.appendChild(opt);
    } else {
      const optAll = document.createElement('option');
      optAll.value = 'all';
      optAll.textContent = `All Correlated Attack Chains (${currentChains.length})`;
      selectEl.appendChild(optAll);

      currentChains.forEach((c) => {
        const opt = document.createElement('option');
        opt.value = c.id;
        opt.textContent = `${(c.name || c.chain_type).toUpperCase()} (Score: ${c.composite_score || c.score || 85})`;
        selectEl.appendChild(opt);
      });

      selectEl.onchange = () => renderSelectedChain(selectEl.value);
    }
  }

  renderSelectedChain(currentChains.length > 0 ? 'all' : '');

  const btnFit = document.getElementById('btn-fit-graph');
  if (btnFit) {
    btnFit.onclick = () => {
      if (cy) cy.fit(undefined, 40);
    };
  }
}

function renderSelectedChain(chainChoice) {
  const container = document.getElementById('cy-attack-graph');
  if (!container || !window.cytoscape) return;

  if (currentChains.length === 0) {
    showEmptyGraph('Zero attack chains correlated for this repository. Secure posture verified!');
    return;
  }

  let targetChains = currentChains;
  if (chainChoice && chainChoice !== 'all') {
    targetChains = currentChains.filter((c) => c.id === chainChoice);
  }

  const elements = buildCytoscapeElements(targetChains, currentScan.findings || []);

  if (cy) {
    cy.destroy();
  }

  cy = window.cytoscape({
    container: container,
    elements: elements,
    style: [
      {
        selector: 'node',
        style: {
          'label': 'data(label)',
          'color': '#F0F4F1',
          'font-size': '12px',
          'font-family': 'sans-serif',
          'font-weight': '600',
          'text-valign': 'center',
          'text-halign': 'center',
          'background-color': '#111815',
          'border-width': 2,
          'border-color': '#9BE5B5',
          'width': 'data(width)',
          'height': 'data(height)',
          'shape': 'round-rectangle',
          'corner-radius': '10px',
          'text-wrap': 'wrap',
          'text-max-width': '140px',
          'shadow-blur': 16,
          'shadow-color': 'rgba(155, 229, 181, 0.25)',
          'shadow-opacity': 0.8,
        },
      },
      {
        selector: 'node[type="entry"]',
        style: {
          'border-color': '#2ECC71',
          'background-color': 'rgba(46, 204, 113, 0.12)',
          'shadow-color': 'rgba(46, 204, 113, 0.4)',
        },
      },
      {
        selector: 'node[type="execution"]',
        style: {
          'shape': 'ellipse',
          'border-color': '#A0ADA5',
          'background-color': '#18211D',
          'width': 60,
          'height': 60,
        },
      },
      {
        selector: 'node[type="privilege"]',
        style: {
          'border-color': '#FFA94D',
          'background-color': 'rgba(255, 169, 77, 0.12)',
          'shadow-color': 'rgba(255, 169, 77, 0.4)',
        },
      },
      {
        selector: 'node[type="secret"]',
        style: {
          'border-color': '#FF5C5C',
          'background-color': 'rgba(255, 92, 92, 0.14)',
          'shadow-color': 'rgba(255, 92, 92, 0.4)',
        },
      },
      {
        selector: 'node[type="sink"]',
        style: {
          'border-color': '#9BE5B5',
          'background-color': 'rgba(155, 229, 181, 0.18)',
          'border-width': 3,
          'shadow-color': 'rgba(155, 229, 181, 0.65)',
        },
      },
      {
        selector: 'edge',
        style: {
          'width': 2.5,
          'line-color': 'rgba(160, 173, 165, 0.4)',
          'curve-style': 'bezier',
          'target-arrow-shape': 'triangle',
          'target-arrow-color': '#9BE5B5',
          'arrow-scale': 1.2,
        },
      },
      {
        selector: 'edge[severity="critical"]',
        style: {
          'line-color': 'rgba(255, 92, 92, 0.65)',
          'target-arrow-color': '#FF5C5C',
          'width': 3,
        },
      },
    ],
    layout: {
      name: 'breadthfirst',
      directed: true,
      padding: 50,
      spacingFactor: 1.4,
    },
  });

  cy.on('tap', 'node', (evt) => {
    const node = evt.target;
    const ruleId = node.data('ruleId');
    if (ruleId) {
      window.router.navigate(`remediation?rule_id=${encodeURIComponent(ruleId)}`);
    }
  });
}

function buildCytoscapeElements(chains, findings) {
  const nodes = [];
  const edges = [];
  const nodeSet = new Set();

  chains.forEach((chain, cIdx) => {
    const members = chain.finding_ids || chain.findings || [];
    const chainType = chain.chain_type || 'chain';

    // 1. Entry Point Node
    const entryId = `entry_${cIdx}`;
    if (!nodeSet.has(entryId)) {
      nodeSet.add(entryId);
      nodes.push({
        data: {
          id: entryId,
          label: chain.trigger_label || 'Untrusted Trigger',
          type: 'entry',
          width: 170,
          height: 48,
        },
      });
    }

    // 2. Middle execution step
    const execId = `exec_${cIdx}`;
    if (!nodeSet.has(execId)) {
      nodeSet.add(execId);
      nodes.push({
        data: {
          id: execId,
          label: 'Workflow\nExecution',
          type: 'execution',
          width: 65,
          height: 65,
        },
      });
      edges.push({
        data: {
          id: `edge_${entryId}_${execId}`,
          source: entryId,
          target: execId,
        },
      });
    }

    // 3. Vulnerability findings in the chain
    members.forEach((mId, mIdx) => {
      const fNodeId = `node_${mId}_${cIdx}`;
      const fObj = findings.find((f) => f.id === mId || f.rule_id === mId) || {};
      const ruleId = fObj.rule_id || mId;
      const title = fObj.title || ruleId;
      const sev = (fObj.severity || 'high').toLowerCase();

      let nodeType = 'privilege';
      if (ruleId.includes('SECRET') || ruleId.includes('CREDENTIAL')) nodeType = 'secret';

      if (!nodeSet.has(fNodeId)) {
        nodeSet.add(fNodeId);
        nodes.push({
          data: {
            id: fNodeId,
            label: `${title}\n(${ruleId})`,
            type: nodeType,
            ruleId: ruleId,
            width: 180,
            height: 52,
          },
        });
        edges.push({
          data: {
            id: `edge_${execId}_${fNodeId}`,
            source: execId,
            target: fNodeId,
            severity: sev,
          },
        });
      }

      // 4. Connect to Compromise Sink
      const sinkId = `sink_${cIdx}`;
      if (!nodeSet.has(sinkId)) {
        nodeSet.add(sinkId);
        nodes.push({
          data: {
            id: sinkId,
            label: chain.impact_label || 'Supply-Chain\nCompromise',
            type: 'sink',
            width: 180,
            height: 54,
          },
        });
      }
      edges.push({
        data: {
          id: `edge_${fNodeId}_${sinkId}`,
          source: fNodeId,
          target: sinkId,
          severity: sev,
        },
      });
    });
  });

  return [...nodes, ...edges];
}

function showEmptyGraph(msg) {
  const container = document.getElementById('cy-attack-graph');
  if (container) {
    container.innerHTML = `
      <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: var(--text-muted); text-align: center; padding: 2rem;">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#9BE5B5" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom: 1rem; opacity: 0.6;">
          <rect width="6" height="6" x="16" y="16" rx="1"/>
          <rect width="6" height="6" x="2" y="16" rx="1"/>
          <rect width="6" height="6" x="9" y="2" rx="1"/>
          <path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/>
          <path d="M12 12V8"/>
        </svg>
        <p style="font-size: 1rem; max-width: 440px;">${msg}</p>
      </div>
    `;
  }
}

export const AttackGraphModule = {
  init,
};
window.AttackGraphModule = AttackGraphModule;
