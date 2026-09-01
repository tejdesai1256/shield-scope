(function () {
    const PRIMARY_STORAGE_KEY = "website-security-scanner-theme";
    const LEGACY_STORAGE_KEYS = ["theme", "jobjockey-theme"];
    const THEMES = ["dark", "light"];
    const prefersLight = window.matchMedia("(prefers-color-scheme: light)");

    function getStoredTheme() {
        let storedTheme = localStorage.getItem(PRIMARY_STORAGE_KEY);
        if (THEMES.includes(storedTheme)) return storedTheme;

        for (const legacyKey of LEGACY_STORAGE_KEYS) {
            storedTheme = localStorage.getItem(legacyKey);
            if (THEMES.includes(storedTheme)) return storedTheme;
        }

        return null;
    }

    function getPreferredTheme() {
        return getStoredTheme() || (prefersLight.matches ? "light" : "dark");
    }

    function updateToggleButton(button, theme) {
        const isLight = theme === "light";

        button.setAttribute("aria-label", `Switch to ${isLight ? "dark" : "light"} mode`);
        button.setAttribute("aria-pressed", String(isLight));
        button.setAttribute("title", `Switch to ${isLight ? "dark" : "light"} mode`);
        button.innerHTML = `<i class="fas ${isLight ? "fa-sun" : "fa-moon"}" aria-hidden="true"></i>`;
    }

    function applyTheme(theme, persist) {
        const nextTheme = THEMES.includes(theme) ? theme : "dark";

        document.documentElement.setAttribute("data-theme", nextTheme);
        document.documentElement.style.colorScheme = nextTheme;

        if (document.body) {
            document.body.classList.toggle("light-mode", nextTheme === "light");
            document.body.classList.toggle("dark-mode", nextTheme === "dark");
        }

        document.querySelectorAll("[data-theme-toggle]").forEach(button => {
            updateToggleButton(button, nextTheme);
        });

        if (persist) {
            localStorage.setItem(PRIMARY_STORAGE_KEY, nextTheme);
            LEGACY_STORAGE_KEYS.forEach(key => localStorage.setItem(key, nextTheme));
        }

        return nextTheme;
    }

    function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute("data-theme") || getPreferredTheme();
        return applyTheme(currentTheme === "light" ? "dark" : "light", true);
    }

    function initThemeControls() {
        applyTheme(getPreferredTheme(), false);

        document.querySelectorAll("[data-theme-toggle]").forEach(button => {
            button.addEventListener("click", toggleTheme);
        });
    }

    applyTheme(getPreferredTheme(), false);

    document.addEventListener("DOMContentLoaded", initThemeControls);

    prefersLight.addEventListener("change", () => {
        if (!getStoredTheme()) {
            applyTheme(getPreferredTheme(), false);
        }
    });

    const ThemeManager = {
        apply: applyTheme,
        toggle: toggleTheme,
        get: () => document.documentElement.getAttribute("data-theme") || getPreferredTheme()
    };

    window.SecurityScannerTheme = ThemeManager;
    window.ShieldScopeTheme = ThemeManager;
    window.JobJockeyTheme = ThemeManager; // Backward compatibility
})();

