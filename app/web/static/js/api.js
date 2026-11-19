/**
 * ZEROVANT — Central API Client & Escaping Utilities
 */

// Global audited HTML escape helper for XSS protection
export function escapeHTML(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export class ApiClient {
  constructor(baseUrl = '/api') {
    this.baseUrl = baseUrl;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...options.headers,
    };

    try {
      const response = await fetch(url, { ...options, headers });
      const data = await response.json().catch(() => null);

      if (!response.ok) {
        const errorMsg = data?.error?.message || `HTTP ${response.status} Error`;
        const errorCode = data?.error?.code || 'UNKNOWN_ERROR';
        return { ok: false, status: response.status, code: errorCode, message: errorMsg, data };
      }

      return { ok: true, status: response.status, data };
    } catch (err) {
      return {
        ok: false,
        status: 0,
        code: 'NETWORK_ERROR',
        message: err.message || 'Network communication failed',
        data: null,
      };
    }
  }

  // API Endpoints
  async getHealth() {
    return this.request('/health');
  }

  async getStats() {
    return this.request('/stats');
  }

  async getRules(category = '', tier = '') {
    const params = new URLSearchParams();
    if (category) params.set('category', category);
    if (tier) params.set('tier', tier);
    const query = params.toString() ? `?${params.toString()}` : '';
    return this.request(`/rules${query}`);
  }

  async getChains() {
    return this.request('/chains');
  }

  async triggerScan(payload) {
    return this.request('/scan', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async getScan(scanId) {
    return this.request(`/scans/${encodeURIComponent(scanId)}`);
  }

  async getRepos(limit = 50, offset = 0) {
    return this.request(`/repos?limit=${limit}&offset=${offset}`);
  }

  async getRepoHistory(repoId, limit = 50) {
    return this.request(`/repos/${encodeURIComponent(repoId)}/history?limit=${limit}`);
  }

  async compareScans(repoId, scanA, scanB) {
    return this.request(
      `/repos/${encodeURIComponent(repoId)}/compare?a=${encodeURIComponent(scanA)}&b=${encodeURIComponent(scanB)}`
    );
  }
}

// Export singleton instance
export const api = new ApiClient();
window.api = api;
window.escapeHTML = escapeHTML;
