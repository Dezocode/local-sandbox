declare namespace Cloudflare {
  interface Env {
    DB?: D1Database;
    BUCKET?: R2Bucket;
    APPLE_AUTH_TEAM_ID?: string;
    APPLE_AUTH_KEY_ID?: string;
    APPLE_AUTH_CLIENT_ID?: string;
    APPLE_AUTH_NATIVE_CLIENT_ID?: string;
    APPLE_AUTH_REDIRECT_URI?: string;
    APPLE_AUTH_PRIVATE_KEY_P8?: string;
    APPLE_AUTH_STORAGE_KEY?: string;
    ORIGIN_APP_ID?: string;
    ORIGIN_APP_PRIVATE_KEY_PKCS8?: string;
    ORIGIN_INSTALL_REDIRECT_URI?: string;
    ORIGIN_INSTALL_SCOPES?: string;
    ORIGIN_INSTALL_SUMMARY?: string;
  }
}
