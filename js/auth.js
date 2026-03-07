/* ================================================
   PARAM MAKERSPACE — Auth Helpers
   ================================================ */

const Auth = {

  /* --- Sign Up --- */
  async signUp(email, password, meta = {}) {
    const { data, error } = await db.auth.signUp({
      email, password,
      options: { data: meta }
    });
    return { data, error };
  },

  /* --- Sign In --- */
  async signIn(email, password) {
    const { data, error } = await db.auth.signInWithPassword({ email, password });
    return { data, error };
  },

  /* --- Sign Out --- */
  async signOut() {
    await db.auth.signOut();
    window.location.href = 'index.html';
  },

  /* --- Get current session user --- */
  async getUser() {
    const { data: { user } } = await db.auth.getUser();
    return user;
  },

  /* --- Get maker_profile for current user --- */
  async getProfile(userId) {
    const { data } = await db
      .from('maker_profiles')
      .select('*')
      .eq('user_id', userId)
      .single();
    return data;
  },

  /* --- Guard: redirect to auth if not logged in --- */
  async requireAuth(redirect = 'auth.html') {
    const user = await this.getUser();
    if (!user) { window.location.href = redirect; return null; }
    return user;
  },

  /* --- Guard: redirect to dashboard if already logged in --- */
  async redirectIfAuthed(redirect = 'dashboard.html') {
    const user = await this.getUser();
    if (user) window.location.href = redirect;
  },

  /* --- Listen for auth state changes --- */
  onAuthChange(callback) {
    db.auth.onAuthStateChange((_event, session) => {
      callback(session ? session.user : null);
    });
  }
};
