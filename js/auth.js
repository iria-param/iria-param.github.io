/* ================================================
   PARAM MAKERSPACE — Auth Helpers
   ================================================ */

const Auth = {

  /* --- Sign Up --- */
  async signUp(email, password, meta = {}) {
    try {
      const { data, error } = await db.auth.signUp({
        email, password,
        options: { data: meta }
      });
      return { data, error };
    } catch (e) {
      return { data: null, error: { message: e.message } };
    }
  },

  /* --- Sign In --- */
  async signIn(email, password) {
    try {
      const { data, error } = await db.auth.signInWithPassword({ email, password });
      return { data, error };
    } catch (e) {
      return { data: null, error: { message: e.message } };
    }
  },

  /* --- Sign Out --- */
  async signOut() {
    try { await db.auth.signOut(); } catch (_) {}
    window.location.href = 'index.html';
  },

  /* --- Get current session user (safe — never throws) --- */
  async getUser() {
    try {
      const { data: { user }, error } = await db.auth.getUser();
      if (error) {
        /* Stale / rotated refresh token — wipe local session silently */
        const isTokenError = error.message &&
          (error.message.includes('Refresh Token') ||
           error.message.includes('refresh_token') ||
           error.message.includes('session_not_found') ||
           error.message.includes('Invalid JWT'));
        if (isTokenError) {
          try { await db.auth.signOut({ scope: 'local' }); } catch (_) {}
        }
        return null;
      }
      return user || null;
    } catch (e) {
      /* Network error or unexpected throw */
      return null;
    }
  },

  /* --- Get maker_profile for current user --- */
  async getProfile(userId) {
    try {
      const { data } = await db
        .from('maker_profiles')
        .select('*')
        .eq('user_id', userId)
        .single();
      return data;
    } catch (e) {
      return null;
    }
  },

  /* --- Guard: redirect to auth if not logged in --- */
  async requireAuth(redirect = 'auth.html') {
    try {
      const user = await this.getUser();
      if (!user) { window.location.href = redirect; return null; }
      return user;
    } catch (e) {
      window.location.href = redirect;
      return null;
    }
  },

  /* --- Guard: redirect to dashboard if already logged in --- */
  async redirectIfAuthed(redirect = 'dashboard.html') {
    try {
      const user = await this.getUser();
      if (user) window.location.href = redirect;
    } catch (e) {
      /* Not authed or error — stay on current page */
    }
  },

  /* --- Listen for auth state changes --- */
  onAuthChange(callback) {
    db.auth.onAuthStateChange((_event, session) => {
      callback(session ? session.user : null);
    });
  }
};
