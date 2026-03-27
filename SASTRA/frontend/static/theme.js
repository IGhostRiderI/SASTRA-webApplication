(() => {
  const THEME_KEY = 'sastra-theme';
  const root = document.documentElement;
  const mediaQuery = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  const SUN_ICON = `
    <svg class="theme-toggle-icon theme-toggle-icon-sun" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="4.2" stroke="currentColor" stroke-width="2"></circle>
      <path d="M12 2.8V5.2M12 18.8V21.2M21.2 12H18.8M5.2 12H2.8M18.5 5.5L16.8 7.2M7.2 16.8L5.5 18.5M18.5 18.5L16.8 16.8M7.2 7.2L5.5 5.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"></path>
    </svg>
  `;
  const MOON_ICON = `
    <svg class="theme-toggle-icon theme-toggle-icon-moon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M21 14.4A8.8 8.8 0 1 1 9.6 3a7.1 7.1 0 1 0 11.4 11.4z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
    </svg>
  `;

  function getSavedTheme() {
    try {
      const value = localStorage.getItem(THEME_KEY);
      return value === 'dark' || value === 'light' ? value : null;
    } catch (_error) {
      return null;
    }
  }

  function getActiveTheme() {
    const saved = getSavedTheme();
    if (saved) return saved;
    return mediaQuery && mediaQuery.matches ? 'dark' : 'light';
  }

  function applyTheme(theme) {
    root.setAttribute('data-theme', theme);
    root.style.colorScheme = theme;
    const btn = document.getElementById('theme-toggle');
    if (btn) {
      const nextMode = theme === 'dark' ? 'light' : 'dark';
      btn.setAttribute('aria-label', `Switch to ${nextMode} mode`);
      btn.setAttribute('title', `Switch to ${nextMode} mode`);
      btn.setAttribute('aria-pressed', String(theme === 'dark'));
    }
  }

  function persistTheme(theme) {
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch (_error) {
      // Ignore localStorage failures.
    }
  }

  function toggleTheme() {
    const nextTheme = getActiveTheme() === 'dark' ? 'light' : 'dark';
    persistTheme(nextTheme);
    applyTheme(nextTheme);
  }

  function getToggleMountPoint() {
    const navRight = document.querySelector('.nav-right');
    if (navRight) return { container: navRight, isFloating: false };

    const navActions = document.querySelector('.nav-actions');
    if (navActions) return { container: navActions, isFloating: false };

    return { container: document.body, isFloating: true };
  }

  function ensureToggleButton() {
    if (document.getElementById('theme-toggle-slot')) return;

    const { container, isFloating } = getToggleMountPoint();
    const slot = document.createElement('div');
    slot.id = 'theme-toggle-slot';
    slot.className = `theme-toggle-slot${isFloating ? ' theme-toggle-floating' : ''}`;

    const button = document.createElement('button');
    button.id = 'theme-toggle';
    button.type = 'button';
    button.className = 'theme-toggle-btn';
    button.innerHTML = `${SUN_ICON}${MOON_ICON}<span class="theme-toggle-thumb" aria-hidden="true"></span>`;
    button.addEventListener('click', toggleTheme);
    const logoutButton = !isFloating ? container.querySelector('.btn-logout') : null;
    if (logoutButton && logoutButton.parentElement === container) {
      container.insertBefore(slot, logoutButton);
    } else {
      container.appendChild(slot);
    }
    slot.appendChild(button);
    applyTheme(getActiveTheme());
  }

  function initTheme() {
    applyTheme(getActiveTheme());
    ensureToggleButton();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTheme, { once: true });
  } else {
    initTheme();
  }

  if (mediaQuery && typeof mediaQuery.addEventListener === 'function') {
    mediaQuery.addEventListener('change', (event) => {
      if (getSavedTheme()) return;
      applyTheme(event.matches ? 'dark' : 'light');
    });
  }
})();
