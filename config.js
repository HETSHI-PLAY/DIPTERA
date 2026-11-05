/* Konfigurasi default untuk Deeptera.
 *
 * File ini boleh kosong. Saat dijalankan lewat server.js / container,
 * window.DEEPTERA_CONFIG diisi otomatis dari environment
 * (N8N_BASE_URL, DEEPTERA_FORM_PATH, TENANT_OPTIONS, INITIAL_CASE_ID,
 * INITIAL_TICKETS) — lihat .env.example.
 *
 * Kalau perlu mengisi manual (mis. dibuka lewat file://):
 *   window.DEEPTERA_CONFIG = { baseUrl: 'http://192.168.1.10:5678' };
 */
window.DEEPTERA_CONFIG = window.DEEPTERA_CONFIG || {};
