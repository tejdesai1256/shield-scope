// Helper to determine the backend API base URL dynamically based on environment
window.getBackendBaseUrl = function() {
    if (window.API_BASE_URL) {
        return window.API_BASE_URL.replace(/\/$/, '');
    }

    const origin = window.location.origin || '';
    const hostname = window.location.hostname || '';
    const protocol = window.location.protocol || '';

    // Local development environment check
    if (
        hostname === 'localhost' ||
        hostname === '127.0.0.1' ||
        protocol === 'file:' ||
        origin.includes('8000') ||
        origin.includes('127.0.0.1') ||
        origin.includes('localhost')
    ) {
        return 'http://127.0.0.1:8000';
    }

    // Deployed on Render where backend & frontend are hosted on the exact same origin
    if (origin.includes('onrender.com') && origin.includes('website-security-scanner')) {
        return origin.replace(/\/$/, '');
    }

    // Deployed on Netlify, Vercel, GitHub Pages, or external frontend domain
    // Connects to live backend API hosted on Render
    return 'https://website-security-scanner-2-1.onrender.com';
};

// Real Authentication System for ShieldScope
class AuthSystem {
    constructor() {
        this.backendBase = window.getBackendBaseUrl();
        this.apiBase = `${this.backendBase}/api/auth`;
        this.currentUser = this.getCachedUser();
    }

    getToken() {
        return localStorage.getItem('access_token') || localStorage.getItem('token');
    }

    setToken(token) {
        if (token) {
            localStorage.setItem('access_token', token);
            localStorage.setItem('token', token);
        } else {
            localStorage.removeItem('access_token');
            localStorage.removeItem('token');
        }
    }

    getCachedUser() {
        const stored = localStorage.getItem('currentUser') || localStorage.getItem('user');
        if (stored) {
            try {
                return JSON.parse(stored);
            } catch (e) {
                return null;
            }
        }
        return null;
    }

    saveCurrentUser(user) {
        if (!user) {
            this.currentUser = null;
            localStorage.removeItem('currentUser');
            localStorage.removeItem('user');
            return;
        }

        // Normalize property names for UI compatibility
        const normalized = {
            id: user.id,
            email: user.email,
            name: user.full_name || user.name || user.email.split('@')[0],
            full_name: user.full_name || user.name,
            scansRemaining: user.scans_remaining ?? user.scansRemaining ?? 100,
            scans_remaining: user.scans_remaining ?? user.scansRemaining ?? 100,
            createdAt: user.created_at || user.createdAt || new Date().toISOString()
        };

        this.currentUser = normalized;
        localStorage.setItem('currentUser', JSON.stringify(normalized));
        localStorage.setItem('user', JSON.stringify(normalized));
    }

    clearSession() {
        this.currentUser = null;
        localStorage.removeItem('currentUser');
        localStorage.removeItem('user');
        localStorage.removeItem('access_token');
        localStorage.removeItem('token');
        localStorage.removeItem('users');
    }

    // Validate email
    validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    // Validate password — matches backend rules (8+ chars, upper, lower, digit, special)
    validatePassword(password) {
        return {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /\d/.test(password),
            special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
        };
    }

    // Centralised authenticated fetch. Handles 401 globally by clearing session and redirecting to login.
    async fetchWithAuth(url, options = {}) {
        const token = this.getToken();
        if (!token) {
            this.handleSessionExpired();
            return null;
        }

        const headers = options.headers ? { ...options.headers } : {};
        headers['Authorization'] = `Bearer ${token}`;
        if (!headers['Content-Type'] && options.body) {
            headers['Content-Type'] = 'application/json';
        }

        try {
            const response = await fetch(url, { ...options, headers });

            if (response.status === 401) {
                this.handleSessionExpired();
                return null;
            }

            return response;
        } catch (err) {
            console.error('fetchWithAuth network error:', err);
            throw err;
        }
    }

    handleSessionExpired() {
        this.clearSession();
        // Only redirect if we are not already on a public page
        const currentPage = window.location.pathname.split('/').pop() || 'index.html';
        const publicPages = ['index.html', 'login.html', 'signup.html', 'features.html', 'about.html', ''];
        if (!publicPages.includes(currentPage)) {
            alert('Your session has expired. Please log in again.');
            window.location.href = 'login.html';
        }
    }

    // Register User via Backend API
    async register(email, password, confirmPassword, name) {
        const errors = [];

        email = (email || '').trim().toLowerCase();
        password = (password || '').trim();
        confirmPassword = (confirmPassword || '').trim();
        name = (name || '').trim();

        if (!email || !password || !confirmPassword || !name) {
            errors.push('All fields are required.');
        }

        if (!this.validateEmail(email)) {
            errors.push('Invalid email address format.');
        }

        if (password !== confirmPassword) {
            errors.push('Passwords do not match.');
        }

        const pwdCheck = this.validatePassword(password);
        if (!pwdCheck.length) errors.push('Password must be at least 8 characters long.');
        if (!pwdCheck.uppercase) errors.push('Password must contain at least one uppercase letter.');
        if (!pwdCheck.lowercase) errors.push('Password must contain at least one lowercase letter.');
        if (!pwdCheck.number) errors.push('Password must contain at least one number.');
        if (!pwdCheck.special) errors.push('Password must contain at least one special character.');

        if (errors.length > 0) {
            return { success: false, errors };
        }

        try {
            const response = await fetch(`${this.apiBase}/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: email,
                    password: password,
                    full_name: name
                })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                return {
                    success: false,
                    errors: [data.detail || data.message || 'Registration failed. Please try again.']
                };
            }

            if (data.access_token) {
                this.setToken(data.access_token);
            }

            if (data.user) {
                this.saveCurrentUser(data.user);
            }

            return {
                success: true,
                message: 'Registration successful!',
                user: this.currentUser
            };

        } catch (err) {
            console.error('Registration API error:', err);
            return {
                success: false,
                errors: [`Could not connect to backend server (${this.backendBase}). Make sure the backend API is running and reachable.`]
            };
        }
    }

    // Login User via Backend API
    async login(email, password) {
        const errors = [];

        email = (email || '').trim().toLowerCase();
        password = (password || '').trim();

        if (!email || !password) {
            errors.push('Email and password are required.');
        }

        if (!this.validateEmail(email)) {
            errors.push('Invalid email address format.');
        }

        if (errors.length > 0) {
            return { success: false, errors };
        }

        try {
            const response = await fetch(`${this.apiBase}/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: email,
                    password: password
                })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                return {
                    success: false,
                    errors: [data.detail || data.message || 'Invalid email or password.']
                };
            }

            if (data.access_token) {
                this.setToken(data.access_token);
            }

            if (data.user) {
                this.saveCurrentUser(data.user);
            }

            return {
                success: true,
                message: 'Login successful!',
                user: this.currentUser
            };

        } catch (err) {
            console.error('Login API error:', err);
            return {
                success: false,
                errors: [`Could not connect to backend server (${this.backendBase}). Make sure the backend API is running and reachable.`]
            };
        }
    }

    // Fetch logged in user profile from Backend API
    async fetchCurrentUser() {
        const token = this.getToken();
        if (!token) {
            this.clearSession();
            return null;
        }

        try {
            const response = await fetch(`${this.apiBase}/me`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.status === 401) {
                this.clearSession();
                return null;
            }

            if (!response.ok) {
                this.clearSession();
                return null;
            }

            const data = await response.json();

            if (data.success && data.user) {
                this.saveCurrentUser(data.user);
                return this.currentUser;
            } else {
                this.clearSession();
                return null;
            }
        } catch (err) {
            console.warn('Backend unavailable, using cached session:', err);
            return this.currentUser;
        }
    }

    // Synchronous current user getter
    getCurrentUser() {
        return this.currentUser || this.getCachedUser();
    }

    isLoggedInLocally() {
        return !!this.getToken() && !!this.getCurrentUser();
    }

    async logout() {
        const token = this.getToken();
        this.clearSession(); // Wipes localStorage synchronously FIRST
        try {
            if (token) {
                await fetch(`${this.apiBase}/logout`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
            }
        } catch (e) {
            // Ignore network errors during logout
        }
    }
}

// Global auth instance
const auth = new AuthSystem();