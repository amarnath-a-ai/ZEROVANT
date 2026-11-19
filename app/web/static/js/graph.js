/**
 * ZEROVANT — Screen 05: Attack Graph (Cytoscape.js)
 */

window.AttackGraphModule = (function () {
  let cy = null;
  let currentScan = null;
  let currentChains = [];

  async function init(params) {
    const scanId = params ? params.get('scanId') : null;

    if (!scanId) {
      const statsRes = await window.api.getStats();
      if (statsRes.ok && statsRes.data.recent_scans && statsRes.data.recent_scans.length > 0) {
        return loadScanGraph(statsRes.data.recent_scans[0].id);
      }
      showEmptyGraph('No scan selected. Run a scan to visualize attack paths.');
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
    const selectEl = document.getElementById('graph-chain-selector');
    if (selectEl) {
      while (selectEl.firstChild) selectEl.removeChild(selectEl.firstChild);

      if (currentChains.length === 0) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'No Attack Chains Detected';
        selectEl.appendChild(opt);
      } else {
        const optAll = document.createElement('option');
        optAll.value = 'all';
        optAll.textContent = `All Chains (${currentChains.length})`;
        selectEl.appendChild(optAll);

        currentChains.forEach((c) => {
          const opt = document.createElement('option');
          opt.value = c.id;
          opt.textContent = `${c.chain_type.toUpperCase()} (Score: ${c.composite_score})`;
          selectEl.appendChild(opt);
        });

        selectEl.onchange = () => {
          renderSelectedChain(selectEl.value);
        };
      }
    }

    renderSelectedChain(currentChains.length > 0 ? 'all' : '');
    setupToolbar();
  }

  function renderSelectedChain(chainChoice) {
    const container = document.getElementById('cy');
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
            'color': '#EDF2EE',
            'font-size': '11px',
            'font-family': 'sans-serif',
            'text-valign': 'center',
            'text-halign': 'center',
            'background-color': 'data(color)',
            'width': 'data(size)',
            'height': 'data(size)',
            'border-width': 2,
            'border-color': 'rgba(255, 255, 255, 0.25)',
            'text-wrap': 'wrap',
            'text-max-width': '90px',
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#A8E6C0',
            'border-width': 4,
            'shadow-blur': 15,
            'shadow-color': '#A8E6C0',
          },
        },
        {
          selector: 'edge',
          style: {
            'width': 2.5,
            'line-color': '#79BD99',
            'target-arrow-color': '#79BD99',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'opacity': 0.85,
            'label': 'data(label)',
            'font-size': '9px',
            'color': '#9BAAA1',
            'text-rotation': 'autorotate',
            'text-background-opacity': 0.8,
            'text-background-color': '#101513',
            'text-background-padding': '2px',
          },
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 40,
        spacingFactor: 1.3,
      },
    });

    cy.on('tap', 'node', function (evt) {
      const nodeData = evt.target.data();
      displayNodeDetails(nodeData);
    });

    // Display primary chain narrative
    if (targetChains.length > 0) {
      displayChainNarrative(targetChains[0]);
    }
  }

  function buildCytoscapeElements(chains, findings) {
    const nodes = [];
    const edges = [];
    const seenNodes = new Set();
    const findingsById = {};
    findings.forEach((f) => {
      findingsById[f.id] = f;
    });

    chains.forEach((chain) => {
      const fIds = chain.finding_ids || [];

      // Create Entry Node (Trigger)
      const triggerId = `trig-${chain.id}`;
      if (!seenNodes.has(triggerId)) {
        nodes.push({
          data: {
            id: triggerId,
            label: 'Trigger / Entry',
            type: 'trigger',
            color: '#2ECC71',
            size: 48,
            chain: chain,
          },
        });
        seenNodes.add(triggerId);
      }

      let prevNodeId = triggerId;

      fIds.forEach((fid, idx) => {
        const finding = findingsById[fid] || { title: fid, rule_id: fid };
        const nodeId = `fnode-${fid}`;

        if (!seenNodes.has(nodeId)) {
          let nodeColor = '#FFA94D';
          let nodeType = 'misconfiguration';

          if (finding.rule_id === 'R005' || finding.rule_id === 'persist-credentials') {
            nodeColor = '#FF5C5C';
            nodeType = 'credential';
          } else if (idx === fIds.length - 1) {
            nodeColor = '#E04848';
            nodeType = 'privilege';
          }

          nodes.push({
            data: {
              id: nodeId,
              label: finding.title || finding.rule_id,
              type: nodeType,
              color: nodeColor,
              size: 44,
              finding: finding,
              chain: chain,
            },
          });
          seenNodes.add(nodeId);
        }

        edges.push({
          data: {
            id: `edge-${prevNodeId}-${nodeId}`,
            source: prevNodeId,
            target: nodeId,
            label: idx === 0 ? 'executes' : 'escalates',
          },
        });

        prevNodeId = nodeId;
      });

      // Impact Node
      const impactId = `imp-${chain.id}`;
      if (!seenNodes.has(impactId)) {
        nodes.push({
          data: {
            id: impactId,
            label: 'Supply-Chain Impact',
            type: 'impact',
            color: '#A8E6C0',
            size: 52,
            chain: chain,
          },
        });
        seenNodes.add(impactId);
      }

      edges.push({
        data: {
          id: `edge-${prevNodeId}-${impactId}`,
          source: prevNodeId,
          target: impactId,
          label: 'compromises',
        },
      });
    });

    return [...nodes, ...edges];
  }

  function displayChainNarrative(chain) {
    const sidebar = document.getElementById('graph-details-sidebar');
    if (!sidebar) return;

    while (sidebar.firstChild) sidebar.removeChild(sidebar.firstChild);

    const titleH3 = document.createElement('h3');
    titleH3.textContent = chain.chain_type ? chain.chain_type.toUpperCase() : 'Attack Chain';

    const scoreDiv = document.createElement('div');
    scoreDiv.className = 'chain-score-badge';
    scoreDiv.textContent = `Risk Score: ${chain.composite_score || 0} / 100`;

    const descH4 = document.createElement('h4');
    descH4.textContent = 'Attack Narrative:';
    descH4.style.marginTop = '0.5rem';

    const narrativeP = document.createElement('p');
    narrativeP.style.lineHeight = '1.6';
    narrativeP.textContent =
      chain.narrative ||
      'This correlated chain connects multiple misconfigurations to achieve privilege escalation.';

    const linkBtn = document.createElement('button');
    linkBtn.className = 'btn btn-primary btn-sm';
    linkBtn.style.marginTop = '1rem';
    linkBtn.textContent = 'Remediate Primary Finding';
    linkBtn.addEventListener('click', () => {
      const targetFid = chain.finding_ids && chain.finding_ids.length > 0 ? chain.finding_ids[0] : '';
      window.router.navigate(
        `remediation?scanId=${encodeURIComponent(currentScan.id)}&findingId=${encodeURIComponent(targetFid)}`
      );
    });

    sidebar.appendChild(titleH3);
    sidebar.appendChild(scoreDiv);
    sidebar.appendChild(descH4);
    sidebar.appendChild(narrativeP);
    sidebar.appendChild(linkBtn);
  }

  function displayNodeDetails(nodeData) {
    const sidebar = document.getElementById('graph-details-sidebar');
    if (!sidebar) return;

    while (sidebar.firstChild) sidebar.removeChild(sidebar.firstChild);

    const titleH3 = document.createElement('h3');
    titleH3.textContent = nodeData.label || 'Node Details';

    const typeBadge = document.createElement('span');
    typeBadge.className = 'badge badge-high';
    typeBadge.textContent = nodeData.type || 'NODE';
    typeBadge.style.alignSelf = 'flex-start';

    sidebar.appendChild(titleH3);
    sidebar.appendChild(typeBadge);

    if (nodeData.finding) {
      const f = nodeData.finding;
      const fileP = document.createElement('p');
      fileP.className = 'mono';
      fileP.textContent = `Location: ${f.file_path || 'workflow.yml'}:${f.line_number || 1}`;

      const fixBtn = document.createElement('button');
      fixBtn.className = 'btn btn-primary btn-sm';
      fixBtn.style.marginTop = '1rem';
      fixBtn.textContent = 'View Unified YAML Fix';
      fixBtn.addEventListener('click', () => {
        window.router.navigate(
          `remediation?scanId=${encodeURIComponent(currentScan.id)}&findingId=${encodeURIComponent(f.id)}`
        );
      });

      sidebar.appendChild(fileP);
      sidebar.appendChild(fixBtn);
    } else if (nodeData.chain) {
      const narP = document.createElement('p');
      narP.textContent = nodeData.chain.narrative || '';
      sidebar.appendChild(narP);
    }
  }

  function setupToolbar() {
    const btnZoomIn = document.getElementById('graph-btn-zoom-in');
    const btnZoomOut = document.getElementById('graph-btn-zoom-out');
    const btnFit = document.getElementById('graph-btn-fit');

    if (btnZoomIn) {
      btnZoomIn.onclick = () => {
        if (cy) cy.zoom(cy.zoom() * 1.25);
      };
    }
    if (btnZoomOut) {
      btnZoomOut.onclick = () => {
        if (cy) cy.zoom(cy.zoom() * 0.8);
      };
    }
    if (btnFit) {
      btnFit.onclick = () => {
        if (cy) cy.fit(null, 40);
      };
    }
  }

  function showEmptyGraph(msg) {
    const container = document.getElementById('cy');
    if (container) {
      while (container.firstChild) container.removeChild(container.firstChild);
      const div = document.createElement('div');
      div.style.padding = '3rem';
      div.style.textAlign = 'center';
      div.style.color = '#9BAAA1';
      div.textContent = msg;
      container.appendChild(div);
    }
  }

  return {
    init: init,
  };
})();
