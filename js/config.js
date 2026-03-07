/* ================================================
   PARAM MAKERSPACE — Supabase Client
   ================================================ */

const SUPABASE_URL  = 'https://ytktlsdiborghdgtvdrt.supabase.co';
const SUPABASE_KEY  = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inl0a3Rsc2RpYm9yZ2hkZ3R2ZHJ0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI4NjQ0MTksImV4cCI6MjA4ODQ0MDQxOX0.edHk5uYQc0xbHgdYCPoF27EWTPh5-IgrSu9ImCbVcSM';

const db = supabase.createClient(SUPABASE_URL, SUPABASE_KEY);
