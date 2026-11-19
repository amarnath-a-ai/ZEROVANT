/**
 * ZEROVANT — Client-Side Hash Router
 */

class Router {
  constructor() {
    this.routes = {};
    this.currentRoute = null;
    this.defaultRoute = 'landing';

    window.addEventListener('hashchange', () => this.handleHashChange());
  }

  register(route, enterCallback) {
    this.routes[route] = enterCallback;
  }

  navigate(route) {
    window.location.hash = route;
  }

  handleHashChange() {
    let hash = window.location.hash.replace(/^#\/?/, '').trim();
    if (!hash) hash = this.defaultRoute;

    // Parse query params if any (e.g. #findings?scanId=...)
    const [path, queryString] = hash.split('?');
    const params = new URLSearchParams(queryString || '');

    this.currentRoute = path;
    this.renderRoute(path, params);
  }

  renderRoute(path, params) {
    const isLanding = path === 'landing';
    const landingEl = document.getElementById('view-landing');
    const workspaceEl = document.getElementById('view-workspace');

    if (isLanding) {
      if (landingEl) landingEl.classList.remove('hidden');
      if (workspaceEl) workspaceEl.classList.add('hidden');
      window.scrollTo(0, 0);
      return;
    }

    // Inside Workspace
    if (landingEl) landingEl.classList.add('hidden');
    if (workspaceEl) workspaceEl.classList.remove('hidden');

    // Hide all screen sections
    document.querySelectorAll('.app-screen').forEach((el) => {
      el.classList.add('hidden');
    });

    // Show target screen section
    const targetScreen = document.getElementById(`screen-${path}`);
    if (targetScreen) {
      targetScreen.classList.remove('hidden');
    }

    // Update active sidebar nav link
    document.querySelectorAll('.sidebar-link').forEach((link) => {
      const target = link.getAttribute('data-route');
      if (target === path) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    // Execute route callback if registered
    if (this.routes[path]) {
      this.routes[path](params);
    }

    window.scrollTo(0, 0);
  }

  init() {
    this.handleHashChange();
  }
}

window.router = new Router();
