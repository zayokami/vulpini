import { create } from 'zustand';

export type Theme = 'light' | 'dark' | 'system';

const STORAGE_KEY = 'vulpini.theme';

function resolve(theme: Theme): 'light' | 'dark' {
  if (theme !== 'system') return theme;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function apply(theme: Theme) {
  document.documentElement.dataset.theme = resolve(theme);
}

interface ThemeState {
  theme: Theme;
  setTheme: (theme: Theme) => void;
}

export const useTheme = create<ThemeState>((set) => ({
  theme: (localStorage.getItem(STORAGE_KEY) as Theme) || 'system',
  setTheme: (theme) => {
    localStorage.setItem(STORAGE_KEY, theme);
    apply(theme);
    set({ theme });
  },
}));

// Follow OS changes while in "system" mode.
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  apply(useTheme.getState().theme);
});
