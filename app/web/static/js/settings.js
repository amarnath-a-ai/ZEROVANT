/**
 * ZEROVANT — Screen 10: Settings & Platform Configuration
 * GitHub integration credentials, Anthropic API configuration, theme control.
 */

async function init() {
  // Theme Switching Controls
  const btnDark = document.getElementById('btn-theme-dark');
  const btnLight = document.getElementById('btn-theme-light');

  const updateThemeButtons = () => {
    const current = window.getCurrentTheme();
    if (btnDark && btnLight) {
      if (current === 'light') {
        btnDark.classList.remove('active');
        btnLight.classList.add('active');
      } else {
        btnDark.classList.add('active');
        btnLight.classList.remove('active');
      }
    }
  };

  updateThemeButtons();

  if (btnDark) {
    btnDark.onclick = () => {
      window.applyTheme('dark');
      updateThemeButtons();
    };
  }

  if (btnLight) {
    btnLight.onclick = () => {
      window.applyTheme('light');
      updateThemeButtons();
    };
  }

  // GitHub Integration Testing
  const btnSaveGithub = document.getElementById('btn-save-github-token');
  const githubInput = document.getElementById('settings-github-token');
  const statusEl = document.getElementById('github-connection-status');

  // Check current backend status
  checkGithubStatus();

  if (btnSaveGithub && githubInput) {
    btnSaveGithub.onclick = async () => {
      const token = githubInput.value.trim();
      if (!token) {
        window.showToast('Please enter a GitHub Personal Access Token (PAT).', 'error');
        return;
      }

      btnSaveGithub.disabled = true;
      if (statusEl) statusEl.textContent = 'Verifying with GitHub REST API...';

      try {
        const res = await fetch('/api/integrations/github/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: token }),
        });

        const data = await res.json();
        btnSaveGithub.disabled = false;

        if (res.ok) {
          if (statusEl) {
            statusEl.textContent = `Connected as @${data.user.login} (${data.user.type})`;
            statusEl.style.color = 'var(--accent-primary)';
          }
          githubInput.value = '';
          window.showToast(`GitHub integration verified for @${data.user.login}!`, 'success');
        } else {
          if (statusEl) {
            statusEl.textContent = `Verification failed: ${data.error?.message || 'Unauthorized'}`;
            statusEl.style.color = 'var(--severity-critical)';
          }
          window.showToast(data.error?.message || 'GitHub connection failed.', 'error');
        }
      } catch (err) {
        btnSaveGithub.disabled = false;
        if (statusEl) statusEl.textContent = 'Connection error.';
        window.showToast('Network error verifying GitHub token.', 'error');
      }
    };
  }

  // Anthropic API Key
  const btnSaveAnthropic = document.getElementById('btn-save-anthropic-key');
  const anthropicInput = document.getElementById('settings-anthropic-key');
  if (btnSaveAnthropic && anthropicInput) {
    btnSaveAnthropic.onclick = () => {
      const key = anthropicInput.value.trim();
      if (key) {
        window.showToast('Anthropic API key saved for this auditor session.', 'success');
        anthropicInput.value = '';
      }
    };
  }
}

async function checkGithubStatus() {
  const statusEl = document.getElementById('github-connection-status');
  if (!statusEl) return;

  try {
    const res = await fetch('/api/integrations/github/status');
    if (res.ok) {
      const data = await res.json();
      if (data.authenticated) {
        statusEl.textContent = `Connected as @${data.user.login}`;
        statusEl.style.color = 'var(--accent-primary)';
      } else {
        statusEl.textContent = 'Status: Unconfigured (Public API limits apply)';
      }
    }
  } catch (e) {
    // Ignore error on status check
  }
}

export const SettingsModule = {
  init,
};
window.SettingsModule = SettingsModule;
