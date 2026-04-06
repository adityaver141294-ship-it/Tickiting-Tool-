/* ============================================================
   app.js — Shared Data & Utility Layer (localStorage-based)
   ============================================================ */

const App = (() => {

  // ---- Keys ----
  const KEYS = {
    users: 'tt_users',
    tickets: 'tt_tickets',
    session: 'tt_session',
    counter: 'tt_counter',
  };

  // ---- Default seed data ----
  const DEFAULT_ADMIN = {
    id: 'admin_001',
    name: 'System Admin',
    email: 'admin@tickettool.com',
    password: 'admin123',
    role: 'admin',
    department: 'IT',
    createdAt: new Date().toISOString(),
    active: true,
  };

  const TECH_ADMIN = {
    id: 'admin_002',
    name: 'Tech User',
    email: 'tech@tickettool.com',
    password: 'admin123',
    role: 'admin',
    department: 'IT',
    createdAt: new Date().toISOString(),
    active: true,
  };

  // ---- Local Caches for synchronous HTML rendering ----
  let _usersCache = [];
  let _ticketsCache = [];

  const isCapacitor = window.location.protocol === 'capacitor:' || (window.location.hostname === 'localhost' && !window.location.port);
  const API_BASE = isCapacitor ? 'https://api.svmastt.com' : '';

  // ---- Init ----
  async function init() {
    try {
      const uRes = await fetch(API_BASE + '/api/users', { headers: Session.getAuthHeader() });
      if (uRes.ok) _usersCache = await uRes.json();

      const tRes = await fetch(API_BASE + '/api/tickets', { headers: Session.getAuthHeader() });
      if (tRes.ok) _ticketsCache = await tRes.json();
    } catch (err) {
      console.warn("Failed to fetch starting backend data. Is the server running?", err);
    }
  }

  async function syncCache() {
    await init();
  }

  // ---- Users API ----
  const Users = {
    getAll() { return _usersCache; },
    getById(id) { return this.getAll().find(u => u.id === id) || null; },
    getByEmail(email) { return this.getAll().find(u => u.email.toLowerCase() === email.toLowerCase()) || null; },
    getByUsername(username) { return this.getAll().find(u => u.name.toLowerCase() === username.toLowerCase()) || null; },
    getNonAdmins() { return this.getAll().filter(u => u.role !== 'admin'); },

    async add(data) {
      try {
        const res = await fetch(API_BASE + '/api/users', {
          method: 'POST', 
          headers: { ...Session.getAuthHeader(), 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        const resData = await res.json();
        if (!res.ok) return { ok: false, msg: resData.error || 'Operation failed' };
        await syncCache();
        return { ok: true, user: resData };
      } catch (err) { return { ok: false, msg: err.message }; }
    },

    async update(id, data) {
      try {
        const res = await fetch(API_BASE + `/api/users/${id}`, {
          method: 'PUT', 
          headers: { ...Session.getAuthHeader(), 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        if (res.ok) {
          await syncCache();
          return true;
        }
        return false;
      } catch (e) { return false; }
    },

    async delete(id) {
      try {
        const res = await fetch(API_BASE + `/api/users/${id}`, { 
          method: 'DELETE',
          headers: Session.getAuthHeader() 
        });
        if (res.ok) {
          await syncCache();
          return true;
        }
        return false;
      } catch (e) { return false; }
    },

    async toggleActive(id) {
      const user = this.getById(id);
      if (!user) return false;
      return await this.update(id, { active: !user.active });
    },

    async authenticate(username, password) {
      try {
        const res = await fetch(API_BASE + '/api/auth/login', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (!res.ok) return { ok: false, msg: data.error };
        // data.user contains the metadata, data.token contains the JWT
        Session.set(data.user, data.token);
        return { ok: true, user: data.user };
      } catch (err) {
        return { ok: false, msg: 'Server connection failed' };
      }
    },
  };

  // ---- Tickets API ----
  const Tickets = {
    getAll() { return _ticketsCache; },
    getById(id) { return this.getAll().find(t => t.id === id) || null; },
    getByUser(userId) { return this.getAll().filter(t => t.userId === userId); },

    async create(data, user) {
      try {
        const res = await fetch(API_BASE + '/api/tickets', {
          method: 'POST', 
          headers: { ...Session.getAuthHeader(), 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...data, user })
        });
        const ticket = await res.json();
        if (res.ok) {
          await syncCache();
          return ticket;
        }
        return null;
      } catch (e) { return null; }
    },

    async updateStatus(id, status) {
      try {
        const res = await fetch(API_BASE + `/api/tickets/${id}/status`, {
          method: 'PUT', 
          headers: { ...Session.getAuthHeader(), 'Content-Type': 'application/json' },
          body: JSON.stringify({ status })
        });
        if (res.ok) {
          await syncCache();
          return true;
        }
        return false;
      } catch (e) { return false; }
    },

    async addComment(id, comment, authorName, isWorkNote = false) {
      try {
        const res = await fetch(API_BASE + `/api/tickets/${id}/comments`, {
          method: 'POST', 
          headers: { ...Session.getAuthHeader(), 'Content-Type': 'application/json' },
          body: JSON.stringify({ by: authorName, text: comment, isWorkNote })
        });
        if (res.ok) {
          await syncCache();
          return true;
        }
        return false;
      } catch (e) { return false; }
    },

    async delete(id) {
      try {
        const res = await fetch(API_BASE + `/api/tickets/${id}`, { 
          method: 'DELETE',
          headers: Session.getAuthHeader() 
        });
        if (res.ok) {
          await syncCache();
          return true;
        }
        return false;
      } catch (e) { return false; }
    },

    stats() {
      const all = this.getAll();
      return {
        total: all.length,
        open: all.filter(t => t.status === 'open').length,
        inprogress: all.filter(t => t.status === 'inprogress').length,
        resolved: all.filter(t => t.status === 'resolved').length,
        closed: all.filter(t => t.status === 'closed').length,
      };
    },
  };

  // ---- Session ----
  const Session = {
    get() { return JSON.parse(sessionStorage.getItem(KEYS.session) || 'null'); },
    getToken() { return sessionStorage.getItem('tt_token') || ''; },
    getAuthHeader() { 
      const token = this.getToken();
      return token ? { 'Authorization': `Bearer ${token}` } : {};
    },
    set(user, token) { 
      sessionStorage.setItem(KEYS.session, JSON.stringify(user)); 
      if (token) sessionStorage.setItem('tt_token', token);
    },
    clear() { 
      sessionStorage.removeItem(KEYS.session); 
      sessionStorage.removeItem('tt_token');
    },
    isAdmin() { const s = this.get(); return s && s.role === 'admin'; },
    isUser() { const s = this.get(); return s && s.role === 'user'; },
  };

  // ---- Utils ----
  const Utils = {
    formatDate(iso) {
      if (!iso) return '—';
      const d = new Date(iso);
      return d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });
    },
    formatDateTime(iso) {
      if (!iso) return '—';
      const d = new Date(iso);
      return d.toLocaleString('en-IN', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
    },
    timeAgo(iso) {
      const diff = Date.now() - new Date(iso).getTime();
      const mins = Math.floor(diff / 60000);
      if (mins < 1) return 'Just now';
      if (mins < 60) return `${mins}m ago`;
      const hrs = Math.floor(mins / 60);
      if (hrs < 24) return `${hrs}h ago`;
      const days = Math.floor(hrs / 24);
      return `${days}d ago`;
    },
    initials(name) {
      return name.split(' ').map(w => w[0]).slice(0, 2).join('').toUpperCase();
    },
    escapeHtml(text) {
      const m = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
      return String(text || '').replace(/[&<>"']/g, c => m[c]);
    },
  };

  // ---- Toast ----
  function toast(msg, type = 'info') {
    const icons = { success: '✅', error: '❌', info: 'ℹ️', warning: '⚠️' };
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      container.className = 'toast-container';
      document.body.appendChild(container);
    }
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.innerHTML = `<span class="toast-icon">${icons[type]}</span><span class="toast-msg">${msg}</span>`;
    container.appendChild(el);
    setTimeout(() => {
      el.classList.add('removing');
      setTimeout(() => el.remove(), 300);
    }, 3500);
  }

  // ---- Modal helpers ----
  function openModal(id) { document.getElementById(id).classList.add('open'); }
  function closeModal(id) { document.getElementById(id).classList.remove('open'); }

  // ---- Navigation guard ----
  function requireRole(role) {
    const s = Session.get();
    if (!s) { window.location.href = 'index.html'; return false; }
    if (role && s.role !== role) {
      window.location.href = s.role === 'admin' ? 'admin.html' : 'user.html';
      return false;
    }
    return true;
  }

  return { init, Users, Tickets, Session, Utils, toast, openModal, closeModal, requireRole };
})();

// Initialize on load
App.init().then(() => {
  document.dispatchEvent(new Event('appReady'));
});
