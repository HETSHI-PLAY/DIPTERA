/* Konfigurasi default untuk Diptera.
 *
 * File ini boleh kosong. Saat dijalankan lewat server.js / container,
 * window.DIPTERA_CONFIG diisi otomatis dari environment
 * (N8N_BASE_URL, DIPTERA_FORM_PATH, TENANT_OPTIONS, INITIAL_CASE_ID,
 * INITIAL_TICKETS) — lihat .env.example.
 *
 * Kalau perlu mengisi manual (mis. dibuka lewat file://):
 *   window.DIPTERA_CONFIG = { baseUrl: 'http://192.168.1.10:5678' };
 */
window.DIPTERA_CONFIG = window.DIPTERA_CONFIG || {};
