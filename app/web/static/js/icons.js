/**
 * ZEROVANT Iconography System
 * Clean, consistent Lucide SVG icons & custom geometric cyber defense brand mark.
 * Replaces all emojis with strict line-art SVGs (24x24 viewBox, stroke-width 2).
 */

const ICONS = {
  // Brand & Shield Icons
  "shield": `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>`,
  "shield-alert": `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>`,
  "shield-check": `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>`,
  
  // Navigation & Screens
  "layout-dashboard": `<rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/>`,
  "radar": `<path d="M19.07 4.93A10 10 0 0 0 6.99 3.34"/><path d="M4 6h.01"/><path d="M2.29 9.62A10 10 0 1 0 21.31 8.35"/><path d="M16.24 7.76A6 6 0 1 0 8.23 16.24"/><path d="M12 18h.01"/><path d="M17.99 11.66A6 6 0 0 1 15.77 16.24"/><circle cx="12" cy="12" r="2"/><path d="m13.41 10.59 5.66-5.66"/>`,
  "scan": `<path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/>`,
  "folder-git-2": `<path d="M9 20H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H20a2 2 0 0 1 2 2v3"/><circle cx="13" cy="13" r="2"/><path d="M13 15v5"/><circle cx="18" cy="18" r="2"/><path d="M15 18h1"/>`,
  "network": `<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/>`,
  "trending-up": `<polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/>`,
  "wrench": `<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>`,
  "file-check-2": `<path d="M4 22h14a2 2 0 0 0 2-2V7l-5-5H6a2 2 0 0 0-2 2v4"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="m3 15 2 2 4-4"/>`,
  "git-compare-arrows": `<circle cx="5" cy="6" r="3"/><path d="M12 6h5a2 2 0 0 1 2 2v7"/><path d="m15 9-3-3 3-3"/><circle cx="19" cy="18" r="3"/><path d="M12 18H7a2 2 0 0 1-2-2V9"/><path d="m9 15 3 3-3 3"/>`,
  "settings": `<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>`,

  // Core Actions & Indicators
  "search": `<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>`,
  "bell": `<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>`,
  "sun": `<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>`,
  "moon": `<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>`,
  "arrow-right": `<path d="M5 12h14"/><path d="m12 5 7 7-7 7"/>`,
  "copy": `<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>`,
  "check": `<polyline points="20 6 9 17 4 12"/>`,
  "play": `<polygon points="6 3 20 12 6 21 6 3"/>`,
  "filter": `<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>`,
  "external-link": `<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>`,
  "code-2": `<path d="m18 16 4-4-4-4"/><path d="m6 8-4 4 4 4"/><path d="m14.5 4-5 16"/>`,
  "workflow": `<rect x="3" y="3" width="6" height="6" rx="1"/><rect x="15" y="3" width="6" height="6" rx="1"/><rect x="9" y="15" width="6" height="6" rx="1"/><path d="M6 9v3a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V9"/><path d="M12 13v2"/>`,
  "terminal": `<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>`,
  "sparkles": `<path d="m12 3-1.9 5.8a2 2 0 0 1-1.3 1.3L3 12l5.8 1.9a2 2 0 0 1 1.3 1.3L12 21l1.9-5.8a2 2 0 0 1 1.3-1.3L21 12l-5.8-1.9a2 2 0 0 1-1.3-1.3Z"/>`,
  "alert-triangle": `<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>`,
  "info": `<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>`,
  "git-branch": `<line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/>`,
  "git-commit": `<circle cx="12" cy="12" r="3"/><line x1="3" y1="12" x2="9" y2="12"/><line x1="15" y1="12" x2="21" y2="12"/>`,
  "layers": `<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>`,
  "lock": `<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>`,
  "key": `<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>`,
  "cpu": `<rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/>`,
  "chevron-down": `<polyline points="6 9 12 15 18 9"/>`,
  "chevron-right": `<polyline points="9 18 15 12 9 6"/>`,
  "refresh-cw": `<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>`,
  "sliders": `<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>`,
  
  // Platform Providers
  "github": `<path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/><path d="M9 18c-4.51 2-5-2-7-2"/>`,
  "gitlab": `<path d="m22 13.29-1.32-4.06a.78.78 0 0 0-.3-.39.8.8 0 0 0-.5 0 .8.8 0 0 0-.38.29.83.83 0 0 0-.15.46l-1.63 5h-11.4L4.69 9.59a.83.83 0 0 0-.15-.46.8.8 0 0 0-.38-.29.8.8 0 0 0-.5 0 .78.78 0 0 0-.3.39L2 13.29a.8.8 0 0 0 .29.89l9.46 6.88a.8.8 0 0 0 .94 0l9.46-6.88a.8.8 0 0 0 .29-.89z"/><path d="M2 13.29 12 21.06 22 13.29"/>`,
  "bitbucket": `<path d="m3 3 2.3 14.5a2 2 0 0 0 2 1.5h9.4a2 2 0 0 0 2-1.5L21 3H3zm10.7 10h-3.4L9.2 8h5.6l-1.1 5z"/>`
};

/**
 * Render a Lucide SVG icon string.
 * @param {string} name - Name of the icon in ICONS map.
 * @param {object} options - Sizing, classes, and overrides.
 * @returns {string} - Complete SVG HTML markup.
 */
export function renderIcon(name, options = {}) {
  const size = options.size || 18;
  const className = options.className ? `lucide lucide-${name} ${options.className}` : `lucide lucide-${name}`;
  const strokeWidth = options.strokeWidth || 2;
  const path = ICONS[name] || ICONS["shield"];

  return `<svg class="${className}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${strokeWidth}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${path}</svg>`;
}

/**
 * Custom Minimal Geometric ZEROVANT Brand Mark.
 * Clean, faceted cyber defense emblem with stylized pipeline flow.
 * @param {object} options - Size and class.
 * @returns {string} - Geometric SVG mark.
 */
export function renderBrandMark(options = {}) {
  const size = options.size || 28;
  const className = options.className || "zerovant-brand-svg";

  return `<svg class="${className}" width="${size}" height="${size}" viewBox="0 0 36 36" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="ZEROVANT Emblem">
    <defs>
      <linearGradient id="zv-grad-emerald" x1="4" y1="4" x2="32" y2="32" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stop-color="#9BE5B5"/>
        <stop offset="100%" stop-color="#326B4C"/>
      </linearGradient>
      <linearGradient id="zv-grad-stroke" x1="4" y1="4" x2="32" y2="32" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.8"/>
        <stop offset="100%" stop-color="#9BE5B5" stop-opacity="0.2"/>
      </linearGradient>
    </defs>
    <!-- Faceted Cyber Shield Outer Boundary -->
    <path d="M18 3L31 8V18C31 26 25 31.5 18 34C11 31.5 5 26 5 18V8L18 3Z" stroke="url(#zv-grad-stroke)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
    <!-- Stylized Pipeline 'Z' & Nodes -->
    <path d="M11 12H25L13 23H25" stroke="url(#zv-grad-emerald)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="11" cy="12" r="2" fill="#9BE5B5"/>
    <circle cx="25" cy="23" r="2" fill="#9BE5B5"/>
  </svg>`;
}

/**
 * Scans the DOM and replaces any <i data-lucide="..."> with the actual SVG.
 * @param {HTMLElement|Document} root
 */
export function hydrateIcons(root = document) {
  const elements = root.querySelectorAll("[data-lucide]");
  elements.forEach((el) => {
    const iconName = el.getAttribute("data-lucide");
    const size = parseInt(el.getAttribute("data-size"), 10) || 18;
    const strokeWidth = parseFloat(el.getAttribute("data-stroke")) || 2;
    const extraClass = el.getAttribute("data-class") || "";
    
    el.innerHTML = renderIcon(iconName, { size, strokeWidth, className: extraClass });
    el.removeAttribute("data-lucide");
  });

  const brandElements = root.querySelectorAll("[data-brand-mark]");
  brandElements.forEach((el) => {
    const size = parseInt(el.getAttribute("data-size"), 10) || 28;
    el.innerHTML = renderBrandMark({ size });
    el.removeAttribute("data-brand-mark");
  });
}
