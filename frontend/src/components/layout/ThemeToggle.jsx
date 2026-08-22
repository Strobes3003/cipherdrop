import { useEffect, useState } from 'react';

const THEME_KEY = 'cipherdrop-theme';

function initialTheme() {
  try {
    const saved = window.localStorage.getItem(THEME_KEY);
    if (saved === 'light' || saved === 'dark') return saved;
  } catch {
    // Theme preference is optional; continue with the secure default.
  }
  return 'dark';
}

export default function ThemeToggle() {
  const [theme, setTheme] = useState(initialTheme);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch {
      // A blocked preference should not affect the application.
    }
  }, [theme]);

  const isLight = theme === 'light';

  return (
    <button
      className="theme-toggle"
      type="button"
      onClick={() => setTheme(isLight ? 'dark' : 'light')}
      aria-label={`Switch to ${isLight ? 'dark' : 'light'} theme`}
      aria-pressed={isLight}
      title={`Switch to ${isLight ? 'dark' : 'light'} theme`}
    >
      <span className="material-symbols-outlined" aria-hidden="true">{isLight ? 'dark_mode' : 'light_mode'}</span>
    </button>
  );
}
