#ifndef DOTTIE_GNOME_SETTINGS_H
#define DOTTIE_GNOME_SETTINGS_H

#include <gio/gio.h>

typedef struct DottieSettings DottieSettings;
typedef struct DottieSentinel DottieSentinel;

typedef enum {
    DOTTIE_SETTINGS_OPEN_ERROR_NONE = 0,
    DOTTIE_SETTINGS_OPEN_ERROR_SCHEMA_NOT_FOUND = 1,
    DOTTIE_SETTINGS_OPEN_ERROR_BACKEND_UNAVAILABLE = 2
} DottieSettingsOpenError;

typedef struct {
    gchar *effective_type;
    gchar *effective_text;
    gchar *default_type;
    gchar *default_text;
    gchar *user_type;
    gchar *user_text;
    gboolean user_present;
    gboolean writable;
} DottieRead;

typedef struct {
    gchar *variant_type;
    gchar *text;
    gchar *resolved_path;
    gboolean present;
    gboolean writable;
} DottieUserRead;

typedef enum {
    DOTTIE_SETTINGS_READ_ERROR_NONE = 0,
    DOTTIE_SETTINGS_READ_ERROR_KEY_NOT_FOUND = 1,
    DOTTIE_SETTINGS_READ_ERROR_READ_FAILED = 2
} DottieSettingsReadError;

DottieSettings *dottie_settings_open(const gchar *schema_dir, const gchar *schema_id, const gchar *path, gint backend_kind, const gchar *observed_keys, gboolean make_peer, gint *open_error, gchar **error_message);
void dottie_settings_close(DottieSettings *settings);
DottieRead *dottie_settings_read(DottieSettings *settings, const gchar *key, gchar **error_message);
void dottie_read_free(DottieRead *read_value);
DottieUserRead *dottie_settings_read_user(DottieSettings *settings, const gchar *key, gint *read_error, gchar **error_message);
void dottie_user_read_free(DottieUserRead *read_value);
gchar *dottie_settings_path(DottieSettings *settings);
gboolean dottie_settings_canonicalize(DottieSettings *settings, const gchar *key, const gchar *type, const gchar *text, gchar **canonical_type, gchar **canonical_text, gchar **error_message);
gboolean dottie_settings_set(DottieSettings *settings, const gchar *key, const gchar *type, const gchar *text, gchar **error_message);
gboolean dottie_settings_reset(DottieSettings *settings, const gchar *key, gchar **error_message);
void dottie_settings_sync(void);
gchar *dottie_settings_drain(DottieSettings *settings, gboolean *more_work, gchar **error_message);
gboolean dottie_settings_peer_set(DottieSettings *settings, const gchar *key, const gchar *type, const gchar *text, gchar **error_message);
gboolean dottie_settings_peer_reset(DottieSettings *settings, const gchar *key, gchar **error_message);
gboolean dottie_settings_queue_test_work(DottieSettings *settings, guint count, gchar **error_message);
gboolean dottie_test_settings_set_user_value(DottieSettings *settings, const gchar *key, const gchar *text, gchar **error_message);
gboolean dottie_test_variant_text_equal(const gchar *type, const gchar *first_text, const gchar *second_text, gchar **error_message);
DottieSentinel *dottie_sentinel_new(void);
gboolean dottie_sentinel_fired(DottieSentinel *sentinel);
void dottie_sentinel_free(DottieSentinel *sentinel);
void dottie_free(void *value);

#endif
