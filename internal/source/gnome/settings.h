#ifndef DOTTIE_GNOME_SETTINGS_H
#define DOTTIE_GNOME_SETTINGS_H

#include <gio/gio.h>

typedef struct DottieSettings DottieSettings;
typedef struct DottieSentinel DottieSentinel;

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

DottieSettings *dottie_settings_open(const gchar *schema_dir, const gchar *schema_id, const gchar *path, gint backend_kind, const gchar *observed_keys, gboolean make_peer, gchar **error_message);
void dottie_settings_close(DottieSettings *settings);
DottieRead *dottie_settings_read(DottieSettings *settings, const gchar *key, gchar **error_message);
void dottie_read_free(DottieRead *read_value);
gboolean dottie_settings_set(DottieSettings *settings, const gchar *key, const gchar *type, const gchar *text, gchar **error_message);
gboolean dottie_settings_reset(DottieSettings *settings, const gchar *key, gchar **error_message);
gchar *dottie_settings_drain(DottieSettings *settings, gboolean *more_work, gchar **error_message);
gboolean dottie_settings_peer_set(DottieSettings *settings, const gchar *key, const gchar *type, const gchar *text, gchar **error_message);
gboolean dottie_settings_peer_reset(DottieSettings *settings, const gchar *key, gchar **error_message);
gboolean dottie_settings_queue_test_work(DottieSettings *settings, guint count, gchar **error_message);
gboolean dottie_test_variant_text_equal(const gchar *type, const gchar *first_text, const gchar *second_text, gchar **error_message);
DottieSentinel *dottie_sentinel_new(void);
gboolean dottie_sentinel_fired(DottieSentinel *sentinel);
void dottie_sentinel_free(DottieSentinel *sentinel);
void dottie_free(void *value);

#endif
