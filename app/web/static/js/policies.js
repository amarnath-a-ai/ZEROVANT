/**
 * ZEROVANT — Screen 08: Security Policies & Rule Catalogue
 */

window.PoliciesModule = (function () {
  let allRules = [];
  let allChains = [];

  async function init() {
    const rulesRes = await window.api.getRules();
    const chainsRes = await window.api.getChains();

    if (rulesRes.ok) {
      allRules = rulesRes.data.rules || [];
      renderRulesList(allRules);
    }

    if (chainsRes.ok) {
      allChains = chainsRes.data.chains || [];
      renderChainsList(allChains);
    }

    setupCatalogueFilters();
  }

  function setupCatalogueFilters() {
    const searchInput = document.getElementById('rules-search-input');
    const tierSelect = document.getElementById('rules-tier-filter');

    const filterHandler = () => {
      const q = searchInput ? searchInput.value.toLowerCase().trim() : '';
      const tier = tierSelect ? tierSelect.value : 'all';

      const filtered = allRules.filter((r) => {
        const matchesQuery =
          !q ||
          (r.id && r.id.toLowerCase().includes(q)) ||
          (r.title && r.title.toLowerCase().includes(q)) ||
          (r.description && r.description.toLowerCase().includes(q));

        const matchesTier = tier === 'all' || (r.tier && r.tier.toLowerCase() === tier.toLowerCase());

        return matchesQuery && matchesTier;
      });

      renderRulesList(filtered);
    };

    if (searchInput) searchInput.oninput = filterHandler;
    if (tierSelect) tierSelect.onchange = filterHandler;
  }

  function renderRulesList(rules) {
    const container = document.getElementById('rules-catalogue-container');
    if (!container) return;

    while (container.firstChild) container.removeChild(container.firstChild);

    if (rules.length === 0) {
      const p = document.createElement('p');
      p.className = 'text-muted';
      p.textContent = 'No static security rules matching search criteria.';
      container.appendChild(p);
      return;
    }

    rules.forEach((r) => {
      const card = document.createElement('div');
      card.className = 'glass-card policy-item-card';

      const infoDiv = document.createElement('div');
      infoDiv.className = 'policy-info';

      const headerDiv = document.createElement('div');
      headerDiv.className = 'flex items-center gap-2';

      const codeSpan = document.createElement('span');
      codeSpan.className = 'mono';
      codeSpan.style.color = '#A8E6C0';
      codeSpan.textContent = r.id;

      const titleSpan = document.createElement('span');
      titleSpan.className = 'policy-title';
      titleSpan.textContent = r.title || r.name;

      const tierBadge = document.createElement('span');
      tierBadge.className = 'badge badge-info';
      tierBadge.textContent = r.tier ? r.tier.toUpperCase() : 'CORE';

      const sevBadge = document.createElement('span');
      const s = (r.severity || 'MEDIUM').toUpperCase();
      sevBadge.className = `badge badge-${s.toLowerCase()}`;
      sevBadge.textContent = s;

      headerDiv.appendChild(codeSpan);
      headerDiv.appendChild(titleSpan);
      headerDiv.appendChild(tierBadge);
      headerDiv.appendChild(sevBadge);

      const descP = document.createElement('p');
      descP.className = 'policy-desc';
      descP.textContent = r.description;

      infoDiv.appendChild(headerDiv);
      infoDiv.appendChild(descP);

      // Policy Enforcement Switch
      const toggleLabel = document.createElement('label');
      toggleLabel.className = 'toggle-switch';
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.checked = true; // Enabled by default
      const slider = document.createElement('span');
      slider.className = 'slider';
      toggleLabel.appendChild(input);
      toggleLabel.appendChild(slider);

      input.onchange = () => {
        window.showToast(`Policy for ${r.id} ${input.checked ? 'enabled' : 'disabled'}.`, 'success');
      };

      card.appendChild(infoDiv);
      card.appendChild(toggleLabel);

      container.appendChild(card);
    });
  }

  function renderChainsList(chains) {
    const container = document.getElementById('chains-catalogue-container');
    if (!container) return;

    while (container.firstChild) container.removeChild(container.firstChild);

    chains.forEach((c) => {
      const card = document.createElement('div');
      card.className = 'glass-card policy-item-card';

      const infoDiv = document.createElement('div');
      infoDiv.className = 'policy-info';

      const titleSpan = document.createElement('span');
      titleSpan.className = 'policy-title';
      titleSpan.textContent = c.name;

      const typeBadge = document.createElement('span');
      typeBadge.className = 'badge badge-high';
      typeBadge.textContent = c.chain_type.toUpperCase();

      const headerDiv = document.createElement('div');
      headerDiv.className = 'flex items-center gap-2';
      headerDiv.appendChild(typeBadge);
      headerDiv.appendChild(titleSpan);

      const descP = document.createElement('p');
      descP.className = 'policy-desc';
      descP.textContent = c.narrative_template || '';

      const reqP = document.createElement('p');
      reqP.className = 'mono';
      reqP.style.fontSize = '0.78rem';
      reqP.style.color = '#79BD99';
      reqP.textContent = `Required Rules: [${(c.required_rules || []).join(', ')}] | Scope: ${c.scope || 'same_job'}`;

      infoDiv.appendChild(headerDiv);
      infoDiv.appendChild(descP);
      infoDiv.appendChild(reqP);

      card.appendChild(infoDiv);
      container.appendChild(card);
    });
  }

  return {
    init: init,
  };
})();
