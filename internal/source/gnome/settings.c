#define G_SETTINGS_ENABLE_BACKEND
#include <gio/gsettingsbackend.h>
#include "settings.h"

#include <stdarg.h>
#include <string.h>

#define DOTTIE_MAX_OBSERVED_KEYS 64
#define DOTTIE_MAX_FIELD_BYTES 4096
#define DOTTIE_MAX_VALUE_BYTES 65536
#define DOTTIE_DISPATCH_BUDGET 64
#define DOTTIE_MAX_TEST_WORK 10000

typedef struct {
    guint remaining;
} DottieWork;

struct DottieSettings {
    GSettingsSchema *schema;
    GSettingsBackend *backend;
    GSettings *settings;
    GSettings *peer;
    GMainContext *context;
    gulong changed_handler;
    gchar **keys;
    gboolean *dirty;
    guint key_count;
    GSource *test_work_source;
};

struct DottieSentinel {
    GSource *source;
    gint fired;
};

static void set_error(gchar **error_message, const gchar *format, ...) {
    va_list args;
    if (error_message == NULL) {
        return;
    }
    va_start(args, format);
    *error_message = g_strdup_vprintf(format, args);
    va_end(args);
}

static gboolean valid_path(const gchar *path) {
    gsize length;
    if (path == NULL) {
        return FALSE;
    }
    length = strlen(path);
    return length > 0 && path[0] == '/' && path[length - 1] == '/' && strstr(path, "//") == NULL;
}

static gint find_key(DottieSettings *settings, const gchar *key) {
    guint i;
    for (i = 0; i < settings->key_count; i++) {
        if (g_str_equal(settings->keys[i], key)) {
            return (gint)i;
        }
    }
    return -1;
}

static void changed_cb(GSettings *source, const gchar *key, gpointer user_data) {
    DottieSettings *settings = user_data;
    gint index = find_key(settings, key);
    (void)source;
    if (index >= 0) {
        settings->dirty[index] = TRUE;
    }
}

static gboolean valid_text_field(const gchar *value, gsize maximum) {
    return value != NULL && strlen(value) <= maximum && g_utf8_validate(value, -1, NULL);
}

static gboolean load_observed_keys(DottieSettings *settings, const gchar *list, gchar **error_message) {
    gchar **parts;
    guint i;
    guint count = 0;
    if (list == NULL || list[0] == '\0') {
        return TRUE;
    }
    parts = g_strsplit(list, "\n", DOTTIE_MAX_OBSERVED_KEYS + 1);
    for (i = 0; parts[i] != NULL; i++) {
        if (i >= DOTTIE_MAX_OBSERVED_KEYS) {
            set_error(error_message, "at most %u observed keys are allowed", DOTTIE_MAX_OBSERVED_KEYS);
            g_strfreev(parts);
            return FALSE;
        }
        if (parts[i][0] == '\0' || strlen(parts[i]) > DOTTIE_MAX_FIELD_BYTES || !g_settings_schema_has_key(settings->schema, parts[i])) {
            set_error(error_message, "invalid or unknown observed key: %s", parts[i]);
            g_strfreev(parts);
            return FALSE;
        }
        {
            guint j;
            for (j = 0; j < count; j++) {
                if (g_str_equal(settings->keys[j], parts[i])) {
                    set_error(error_message, "duplicate observed key: %s", parts[i]);
                    g_strfreev(parts);
                    return FALSE;
                }
            }
        }
        settings->keys[count] = g_strdup(parts[i]);
        count++;
    }
    settings->key_count = count;
    g_strfreev(parts);
    return TRUE;
}

static void release_settings(DottieSettings *settings) {
    guint i;
    if (settings == NULL) {
        return;
    }
    if (settings->test_work_source != NULL) {
        g_source_destroy(settings->test_work_source);
        g_source_unref(settings->test_work_source);
        settings->test_work_source = NULL;
    }
    if (settings->settings != NULL && settings->changed_handler != 0) {
        g_signal_handler_disconnect(settings->settings, settings->changed_handler);
        settings->changed_handler = 0;
    }
    if (settings->peer != NULL) {
        g_object_unref(settings->peer);
    }
    if (settings->settings != NULL) {
        g_object_unref(settings->settings);
    }
    if (settings->backend != NULL) {
        g_object_unref(settings->backend);
    }
    if (settings->schema != NULL) {
        g_settings_schema_unref(settings->schema);
    }
    if (settings->context != NULL) {
        g_main_context_unref(settings->context);
    }
    if (settings->keys != NULL) {
        for (i = 0; i < DOTTIE_MAX_OBSERVED_KEYS; i++) {
            g_free(settings->keys[i]);
        }
        g_free(settings->keys);
    }
    g_free(settings->dirty);
    g_free(settings);
}

DottieSettings *dottie_settings_open(const gchar *schema_dir, const gchar *schema_id, const gchar *path, gint backend_kind, const gchar *observed_keys, gboolean make_peer, gchar **error_message) {
    DottieSettings *settings = NULL;
    GSettingsSchemaSource *source = NULL;
    GSettingsSchema *schema = NULL;
    GError *error = NULL;
    const gchar *fixed_path;
    const gchar *resolved_path;
    gboolean pushed = FALSE;
    guint i;
    if (error_message != NULL) {
        *error_message = NULL;
    }
    if (!valid_text_field(schema_dir, DOTTIE_MAX_FIELD_BYTES) || !valid_text_field(schema_id, DOTTIE_MAX_FIELD_BYTES) || (path != NULL && !valid_text_field(path, DOTTIE_MAX_FIELD_BYTES))) {
        set_error(error_message, "schema directory, id, or path is invalid");
        return NULL;
    }
    if (backend_kind != 1 && backend_kind != 2) {
        set_error(error_message, "backend must be explicitly memory or null");
        return NULL;
    }
    if (observed_keys == NULL || strlen(observed_keys) > (DOTTIE_MAX_OBSERVED_KEYS * (DOTTIE_MAX_FIELD_BYTES + 1))) {
        set_error(error_message, "observed key set is invalid");
        return NULL;
    }
    settings = g_new0(DottieSettings, 1);
    settings->context = g_main_context_new();
    settings->keys = g_new0(gchar *, DOTTIE_MAX_OBSERVED_KEYS);
    settings->dirty = g_new0(gboolean, DOTTIE_MAX_OBSERVED_KEYS);
    g_main_context_push_thread_default(settings->context);
    pushed = TRUE;
    source = g_settings_schema_source_new_from_directory(schema_dir, NULL, FALSE, &error);
    if (source == NULL) {
        set_error(error_message, "load schema source: %s", error != NULL ? error->message : "unknown GIO error");
        g_clear_error(&error);
        goto fail;
    }
    schema = g_settings_schema_source_lookup(source, schema_id, FALSE);
    g_settings_schema_source_unref(source);
    source = NULL;
    if (schema == NULL) {
        set_error(error_message, "schema not found in supplied directory: %s", schema_id);
        goto fail;
    }
    settings->schema = schema;
    fixed_path = g_settings_schema_get_path(schema);
    if (fixed_path != NULL) {
        if (path != NULL && path[0] != '\0' && !g_str_equal(path, fixed_path)) {
            set_error(error_message, "supplied path conflicts with fixed schema path");
            goto fail;
        }
        resolved_path = fixed_path;
    } else {
        if (!valid_path(path)) {
            set_error(error_message, "relocatable schemas require a valid explicit path");
            goto fail;
        }
        resolved_path = path;
    }
    if (!load_observed_keys(settings, observed_keys, error_message)) {
        goto fail;
    }
    settings->backend = backend_kind == 1 ? g_memory_settings_backend_new() : g_null_settings_backend_new();
    if (settings->backend == NULL) {
        set_error(error_message, "create explicit isolated GSettings backend failed");
        goto fail;
    }
    settings->settings = g_settings_new_full(settings->schema, settings->backend, resolved_path);
    if (settings->settings == NULL) {
        set_error(error_message, "create GSettings handle failed");
        goto fail;
    }
    settings->changed_handler = g_signal_connect(settings->settings, "changed", G_CALLBACK(changed_cb), settings);
    for (i = 0; i < settings->key_count; i++) {
        GVariant *value = g_settings_get_value(settings->settings, settings->keys[i]);
        if (value == NULL) {
            set_error(error_message, "arm observation for key failed: %s", settings->keys[i]);
            goto fail;
        }
        g_variant_unref(value);
    }
    if (make_peer) {
        settings->peer = g_settings_new_full(settings->schema, settings->backend, resolved_path);
        if (settings->peer == NULL) {
            set_error(error_message, "create shared-backend peer failed");
            goto fail;
        }
    }
    g_main_context_pop_thread_default(settings->context);
    return settings;

fail:
    if (source != NULL) {
        g_settings_schema_source_unref(source);
    }
    if (schema != NULL && settings->schema == NULL) {
        g_settings_schema_unref(schema);
    }
    if (pushed) {
        g_main_context_pop_thread_default(settings->context);
    }
    release_settings(settings);
    return NULL;
}

void dottie_settings_close(DottieSettings *settings) {
    release_settings(settings);
}

static GSettingsSchemaKey *get_schema_key(DottieSettings *settings, const gchar *key, gchar **error_message) {
    GSettingsSchemaKey *schema_key;
    if (key == NULL || strlen(key) > DOTTIE_MAX_FIELD_BYTES || !g_settings_schema_has_key(settings->schema, key)) {
        set_error(error_message, "unknown schema key: %s", key != NULL ? key : "(null)");
        return NULL;
    }
    schema_key = g_settings_schema_get_key(settings->schema, key);
    if (schema_key == NULL) {
        set_error(error_message, "schema key lookup failed: %s", key);
    }
    return schema_key;
}

static gchar *variant_type_text(GVariant *value) {
    return g_strdup(g_variant_get_type_string(value));
}

static gchar *variant_print_text(GVariant *value) {
    return g_variant_print(value, TRUE);
}

DottieRead *dottie_settings_read(DottieSettings *settings, const gchar *key, gchar **error_message) {
    GSettingsSchemaKey *schema_key;
    GVariant *effective = NULL;
    GVariant *default_value = NULL;
    GVariant *user = NULL;
    DottieRead *result = NULL;
    if (error_message != NULL) {
        *error_message = NULL;
    }
    schema_key = get_schema_key(settings, key, error_message);
    if (schema_key == NULL) {
        return NULL;
    }
    effective = g_settings_get_value(settings->settings, key);
    default_value = g_settings_schema_key_get_default_value(schema_key);
    user = g_settings_get_user_value(settings->settings, key);
    if (effective == NULL || default_value == NULL) {
        set_error(error_message, "read effective or default value failed for key: %s", key);
        goto done;
    }
    result = g_new0(DottieRead, 1);
    result->effective_type = variant_type_text(effective);
    result->effective_text = variant_print_text(effective);
    result->default_type = variant_type_text(default_value);
    result->default_text = variant_print_text(default_value);
    result->user_present = user != NULL;
    result->writable = g_settings_is_writable(settings->settings, key);
    if (user != NULL) {
        result->user_type = variant_type_text(user);
        result->user_text = variant_print_text(user);
    }

done:
    if (effective != NULL) {
        g_variant_unref(effective);
    }
    if (default_value != NULL) {
        g_variant_unref(default_value);
    }
    if (user != NULL) {
        g_variant_unref(user);
    }
    g_settings_schema_key_unref(schema_key);
    if (result != NULL && (result->effective_type == NULL || result->effective_text == NULL || result->default_type == NULL || result->default_text == NULL || (result->user_present && (result->user_type == NULL || result->user_text == NULL)))) {
        dottie_read_free(result);
        set_error(error_message, "format value failed for key: %s", key);
        return NULL;
    }
    return result;
}

void dottie_read_free(DottieRead *read_value) {
    if (read_value == NULL) {
        return;
    }
    g_free(read_value->effective_type);
    g_free(read_value->effective_text);
    g_free(read_value->default_type);
    g_free(read_value->default_text);
    g_free(read_value->user_type);
    g_free(read_value->user_text);
    g_free(read_value);
}

static GVariant *parse_checked_value(GSettingsSchemaKey *schema_key, const gchar *key, const gchar *type, const gchar *text, gchar **error_message) {
    GVariantType *variant_type;
    GVariant *value;
    GError *error = NULL;
    const gchar *end = NULL;
    if (!valid_text_field(type, DOTTIE_MAX_FIELD_BYTES) || !valid_text_field(text, DOTTIE_MAX_VALUE_BYTES) || !g_variant_type_string_is_valid(type)) {
        set_error(error_message, "invalid or oversized GVariant type/text");
        return NULL;
    }
    variant_type = g_variant_type_new(type);
    if (!g_variant_type_equal(variant_type, g_settings_schema_key_get_value_type(schema_key))) {
        g_variant_type_free(variant_type);
        set_error(error_message, "GVariant type does not match schema key: %s", key);
        return NULL;
    }
    value = g_variant_parse(variant_type, text, NULL, &end, &error);
    g_variant_type_free(variant_type);
    if (value == NULL) {
        set_error(error_message, "parse GVariant for %s: %s", key, error != NULL ? error->message : "invalid value");
        g_clear_error(&error);
        return NULL;
    }
    while (end != NULL && *end != '\0' && g_ascii_isspace(*end)) {
        end++;
    }
    if (end == NULL || *end != '\0') {
        g_variant_unref(value);
        set_error(error_message, "trailing data after GVariant value for key: %s", key);
        return NULL;
    }
    if (!g_settings_schema_key_range_check(schema_key, value)) {
        g_variant_unref(value);
        set_error(error_message, "GVariant value is outside the schema range: %s", key);
        return NULL;
    }
    return value;
}

static gboolean set_on_settings(DottieSettings *owner, GSettings *target, const gchar *key, const gchar *type, const gchar *text, gchar **error_message) {
    GSettingsSchemaKey *schema_key = get_schema_key(owner, key, error_message);
    GVariant *value;
    gboolean accepted;
    if (schema_key == NULL) {
        return FALSE;
    }
    if (!g_settings_is_writable(target, key)) {
        set_error(error_message, "schema key is not writable: %s", key);
        g_settings_schema_key_unref(schema_key);
        return FALSE;
    }
    value = parse_checked_value(schema_key, key, type, text, error_message);
    g_settings_schema_key_unref(schema_key);
    if (value == NULL) {
        return FALSE;
    }
    accepted = g_settings_set_value(target, key, value);
    g_variant_unref(value);
    if (!accepted) {
        set_error(error_message, "GSettings rejected value for key: %s", key);
    }
    return accepted;
}

gboolean dottie_settings_set(DottieSettings *settings, const gchar *key, const gchar *type, const gchar *text, gchar **error_message) {
    if (error_message != NULL) {
        *error_message = NULL;
    }
    return set_on_settings(settings, settings->settings, key, type, text, error_message);
}

static gboolean reset_on_settings(DottieSettings *settings, GSettings *target, const gchar *key, gchar **error_message) {
    GSettingsSchemaKey *schema_key = get_schema_key(settings, key, error_message);
    if (schema_key == NULL) {
        return FALSE;
    }
    g_settings_schema_key_unref(schema_key);
    if (!g_settings_is_writable(target, key)) {
        set_error(error_message, "schema key is not writable: %s", key);
        return FALSE;
    }
    g_settings_reset(target, key);
    return TRUE;
}

gboolean dottie_settings_reset(DottieSettings *settings, const gchar *key, gchar **error_message) {
    if (error_message != NULL) {
        *error_message = NULL;
    }
    return reset_on_settings(settings, settings->settings, key, error_message);
}

gchar *dottie_settings_drain(DottieSettings *settings, gboolean *more_work, gchar **error_message) {
    GString *result = g_string_new(NULL);
    guint iterations = 0;
    guint i;
    gboolean more;
    if (error_message != NULL) {
        *error_message = NULL;
    }
    while (iterations < DOTTIE_DISPATCH_BUDGET && g_main_context_pending(settings->context)) {
        g_main_context_iteration(settings->context, FALSE);
        iterations++;
    }
    more = g_main_context_pending(settings->context);
    for (i = 0; i < settings->key_count; i++) {
        if (settings->dirty[i]) {
            if (result->len != 0) {
                g_string_append_c(result, '\n');
            }
            g_string_append(result, settings->keys[i]);
            settings->dirty[i] = FALSE;
        }
    }
    if (more_work != NULL) {
        *more_work = more;
    }
    return g_string_free(result, FALSE);
}

gboolean dottie_settings_peer_set(DottieSettings *settings, const gchar *key, const gchar *type, const gchar *text, gchar **error_message) {
    if (error_message != NULL) {
        *error_message = NULL;
    }
    if (settings->peer == NULL) {
        set_error(error_message, "shared-backend peer is not available");
        return FALSE;
    }
    return set_on_settings(settings, settings->peer, key, type, text, error_message);
}

gboolean dottie_settings_peer_reset(DottieSettings *settings, const gchar *key, gchar **error_message) {
    if (error_message != NULL) {
        *error_message = NULL;
    }
    if (settings->peer == NULL) {
        set_error(error_message, "shared-backend peer is not available");
        return FALSE;
    }
    return reset_on_settings(settings, settings->peer, key, error_message);
}

static gboolean work_cb(gpointer user_data) {
    DottieWork *work = user_data;
    if (work->remaining > 0) {
        work->remaining--;
    }
    return work->remaining > 0 ? G_SOURCE_CONTINUE : G_SOURCE_REMOVE;
}

gboolean dottie_settings_queue_test_work(DottieSettings *settings, guint count, gchar **error_message) {
    DottieWork *work;
    if (error_message != NULL) {
        *error_message = NULL;
    }
    if (settings->test_work_source != NULL || count == 0 || count > DOTTIE_MAX_TEST_WORK) {
        set_error(error_message, "test work count is invalid or a source is already pending");
        return FALSE;
    }
    work = g_new0(DottieWork, 1);
    work->remaining = count;
    settings->test_work_source = g_idle_source_new();
    g_source_set_callback(settings->test_work_source, work_cb, work, g_free);
    g_source_attach(settings->test_work_source, settings->context);
    return TRUE;
}

gboolean dottie_test_variant_text_equal(const gchar *type, const gchar *first_text, const gchar *second_text, gchar **error_message) {
    GVariantType *variant_type;
    GVariant *first;
    GVariant *second;
    GError *error = NULL;
    const gchar *end = NULL;
    gboolean equal;
    if (error_message != NULL) {
        *error_message = NULL;
    }
    if (!valid_text_field(type, DOTTIE_MAX_FIELD_BYTES) || !g_variant_type_string_is_valid(type) || !valid_text_field(first_text, DOTTIE_MAX_VALUE_BYTES) || !valid_text_field(second_text, DOTTIE_MAX_VALUE_BYTES)) {
        set_error(error_message, "invalid or oversized test GVariant text");
        return FALSE;
    }
    variant_type = g_variant_type_new(type);
    first = g_variant_parse(variant_type, first_text, NULL, &end, &error);
    if (first == NULL) {
        set_error(error_message, "parse first test GVariant: %s", error != NULL ? error->message : "invalid value");
        g_clear_error(&error);
        g_variant_type_free(variant_type);
        return FALSE;
    }
    while (end != NULL && *end != '\0' && g_ascii_isspace(*end)) {
        end++;
    }
    if (end == NULL || *end != '\0') {
        set_error(error_message, "trailing data in first test GVariant");
        g_variant_unref(first);
        g_variant_type_free(variant_type);
        return FALSE;
    }
    end = NULL;
    second = g_variant_parse(variant_type, second_text, NULL, &end, &error);
    if (second == NULL) {
        set_error(error_message, "parse second test GVariant: %s", error != NULL ? error->message : "invalid value");
        g_clear_error(&error);
        g_variant_unref(first);
        g_variant_type_free(variant_type);
        return FALSE;
    }
    while (end != NULL && *end != '\0' && g_ascii_isspace(*end)) {
        end++;
    }
    if (end == NULL || *end != '\0') {
        set_error(error_message, "trailing data in second test GVariant");
        g_variant_unref(second);
        g_variant_unref(first);
        g_variant_type_free(variant_type);
        return FALSE;
    }
    equal = g_variant_equal(first, second);
    g_variant_unref(second);
    g_variant_unref(first);
    g_variant_type_free(variant_type);
    return equal;
}

static gboolean sentinel_cb(gpointer user_data) {
    DottieSentinel *sentinel = user_data;
    g_atomic_int_inc(&sentinel->fired);
    return G_SOURCE_REMOVE;
}

DottieSentinel *dottie_sentinel_new(void) {
    DottieSentinel *sentinel = g_new0(DottieSentinel, 1);
    sentinel->source = g_idle_source_new();
    g_source_set_callback(sentinel->source, sentinel_cb, sentinel, NULL);
    g_source_attach(sentinel->source, g_main_context_default());
    return sentinel;
}

gboolean dottie_sentinel_fired(DottieSentinel *sentinel) {
    return sentinel != NULL && g_atomic_int_get(&sentinel->fired) != 0;
}

void dottie_sentinel_free(DottieSentinel *sentinel) {
    if (sentinel == NULL) {
        return;
    }
    g_source_destroy(sentinel->source);
    g_source_unref(sentinel->source);
    g_free(sentinel);
}

void dottie_free(void *value) {
    g_free(value);
}
