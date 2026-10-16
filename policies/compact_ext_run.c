// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#define MAX_SETTINGS 32
#define MAX_PINS 16

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
    running = 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-n node] [-i seconds] [-s name=value]... policy.bpf.o\n",
            prog);
}

static int parse_long(const char *arg, long long *val)
{
    char *end;

    errno = 0;
    *val = strtoll(arg, &end, 0);
    if (errno || end == arg || *end)
        return -1;
    return 0;
}

static struct bpf_map *section_map(struct bpf_object *obj, const char *sec)
{
    size_t len = strlen(sec);
    struct bpf_map *map;

    bpf_object__for_each_map(map, obj) {
        const char *name = bpf_map__name(map);
        size_t n = strlen(name);

        if (bpf_map__is_internal(map) && n >= len &&
            !strcmp(name + n - len, sec))
            return map;
    }
    return NULL;
}

static bool int_type(const struct btf_type *t, bool *is_signed)
{
    if (btf_is_int(t) && t->size <= 8) {
        *is_signed = btf_int_encoding(t) & BTF_INT_SIGNED;
        return true;
    }
    if (btf_is_enum(t) && t->size <= 8) {
        *is_signed = true;
        return true;
    }
    return false;
}

static long long get_int(const void *p, unsigned int size, bool is_signed)
{
    switch (size) {
    case 1:
        return is_signed ? *(const __s8 *)p : *(const __u8 *)p;
    case 2:
        return is_signed ? *(const __s16 *)p : *(const __u16 *)p;
    case 4:
        return is_signed ? *(const __s32 *)p : *(const __u32 *)p;
    default:
        return *(const __s64 *)p;
    }
}

static void set_int(void *p, unsigned int size, long long val)
{
    switch (size) {
    case 1:
        *(__u8 *)p = val;
        break;
    case 2:
        *(__u16 *)p = val;
        break;
    case 4:
        *(__u32 *)p = val;
        break;
    default:
        *(__u64 *)p = val;
    }
}

static void print_int(const char *name, int idx, const void *p,
                      unsigned int size, bool is_signed)
{
    long long val = get_int(p, size, is_signed);

    if (idx >= 0)
        printf("  %s[%d] = ", name, idx);
    else
        printf("  %s = ", name);
    if (is_signed)
        printf("%lld\n", val);
    else
        printf("%llu\n", (unsigned long long)val);
}

static int for_each_var(const struct btf *btf, const char *sec, void *data,
                        size_t data_size,
                        int (*fn)(const struct btf *btf, const char *name,
                                  const struct btf_type *t, void *p, void *arg),
                        void *arg)
{
    const struct btf_var_secinfo *vs;
    const struct btf_type *ds;
    int id, i, err;

    id = btf__find_by_name_kind(btf, sec, BTF_KIND_DATASEC);
    if (id < 0)
        return 0;
    ds = btf__type_by_id(btf, id);
    vs = btf_var_secinfos(ds);
    for (i = 0; i < btf_vlen(ds); i++, vs++) {
        const struct btf_type *var = btf__type_by_id(btf, vs->type);
        const struct btf_type *t;

        if (!btf_is_var(var) || btf_var(var)->linkage == BTF_VAR_STATIC)
            continue;
        if (vs->offset + vs->size > data_size)
            continue;
        t = btf__type_by_id(btf, btf__resolve_type(btf, var->type));
        err = fn(btf, btf__name_by_offset(btf, var->name_off), t,
                 (char *)data + vs->offset, arg);
        if (err)
            return err;
    }
    return 0;
}

static int print_var(const struct btf *btf, const char *name,
                     const struct btf_type *t, void *p, void *arg)
{
    bool is_signed;

    if (int_type(t, &is_signed)) {
        print_int(name, -1, p, t->size, is_signed);
    } else if (btf_is_array(t)) {
        const struct btf_array *arr = btf_array(t);
        const struct btf_type *et;
        __u32 i;

        et = btf__type_by_id(btf, btf__resolve_type(btf, arr->type));
        if (!int_type(et, &is_signed))
            return 0;
        for (i = 0; i < arr->nelems; i++)
            print_int(name, i, (char *)p + i * et->size, et->size, is_signed);
    }
    return 0;
}

static void print_section(struct bpf_object *obj, const char *sec,
                          const char *title)
{
    const struct btf *btf = bpf_object__btf(obj);
    struct bpf_map *map = section_map(obj, sec);
    __u32 key = 0;
    size_t size;
    void *data;

    if (!btf || !map)
        return;
    size = bpf_map__value_size(map);
    data = calloc(1, size);
    if (!data)
        return;
    if (bpf_map__lookup_elem(map, &key, sizeof(key), data, size, 0)) {
        fprintf(stderr, "Failed to read %s: %s\n", sec, strerror(errno));
    } else {
        printf("%s:\n", title);
        for_each_var(btf, sec, data, size, print_var, NULL);
    }
    free(data);
}

static void print_counters(struct bpf_object *obj)
{
    print_section(obj, ".bss", "counters");
    print_section(obj, ".data", "counters (.data)");
}

struct setting {
    const char *name;
    long long val;
    bool found;
};

static bool fits(const struct btf_type *t, bool is_signed, long long val)
{
    unsigned int bits = t->size * 8;

    if (btf_is_int(t) && (btf_int_encoding(t) & BTF_INT_BOOL))
        return val == 0 || val == 1;
    if (bits >= 64)
        return is_signed || val >= 0;
    if (is_signed)
        return val >= -(1LL << (bits - 1)) && val < (1LL << (bits - 1));
    return val >= 0 && val < (1LL << bits);
}

static int apply_setting(const struct btf *btf, const char *name,
                         const struct btf_type *t, void *p, void *arg)
{
    struct setting *s = arg;
    bool is_signed;

    if (strcmp(name, s->name))
        return 0;
    if (!int_type(t, &is_signed)) {
        fprintf(stderr, "%s is not an integer\n", name);
        return -EINVAL;
    }
    if (!fits(t, is_signed, s->val)) {
        fprintf(stderr, "%lld is out of range for %s\n", s->val, name);
        return -ERANGE;
    }
    set_int(p, t->size, s->val);
    s->found = true;
    return 0;
}

static int set_setting(struct bpf_object *obj, const char *arg)
{
    const struct btf *btf = bpf_object__btf(obj);
    struct bpf_map *map = section_map(obj, ".rodata");
    struct setting s = {};
    const char *eq = strchr(arg, '=');
    char name[128];
    size_t size;
    void *data;
    int err;

    if (!eq || eq == arg || eq - arg >= (long)sizeof(name) ||
        parse_long(eq + 1, &s.val)) {
        fprintf(stderr, "bad setting '%s', expected name=value\n", arg);
        return -EINVAL;
    }
    memcpy(name, arg, eq - arg);
    name[eq - arg] = '\0';
    s.name = name;

    data = map ? bpf_map__initial_value(map, &size) : NULL;
    if (!btf || !data) {
        fprintf(stderr, "the policy has no settings\n");
        return -ENOENT;
    }
    err = for_each_var(btf, ".rodata", data, size, apply_setting, &s);
    if (err)
        return err;
    if (!s.found) {
        fprintf(stderr, "the policy has no setting '%s'\n", name);
        return -ENOENT;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *settings[MAX_SETTINGS];
    struct bpf_map *pins[MAX_PINS];
    struct bpf_link *link = NULL;
    struct bpf_map *ops = NULL, *map;
    struct bpf_object *obj;
    int nr_settings = 0, nr_pins = 0, node_id = 0, interval = 0, opt, err, i;
    bool loaded = false;
    long long val;

    while ((opt = getopt(argc, argv, "n:i:s:h")) != -1) {
        switch (opt) {
        case 'n':
            if (parse_long(optarg, &val) || val < 0 || val > INT_MAX) {
                usage(argv[0]);
                return 1;
            }
            node_id = val;
            break;
        case 'i':
            if (parse_long(optarg, &val) || val < 0 || val > INT_MAX) {
                usage(argv[0]);
                return 1;
            }
            interval = val;
            break;
        case 's':
            if (nr_settings == MAX_SETTINGS) {
                fprintf(stderr, "too many settings\n");
                return 1;
            }
            settings[nr_settings++] = optarg;
            break;
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }
    if (optind != argc - 1) {
        usage(argv[0]);
        return 1;
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    obj = bpf_object__open_file(argv[optind], NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open %s: %s\n", argv[optind],
                strerror(errno));
        return 1;
    }
    for (i = 0; i < nr_settings; i++) {
        err = set_setting(obj, settings[i]);
        if (err)
            goto cleanup;
    }

    bpf_object__for_each_map(map, obj) {
        const char *path = bpf_map__pin_path(map);

        if (path && access(path, F_OK) && nr_pins < MAX_PINS)
            pins[nr_pins++] = map;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load %s: %s\n", argv[optind],
                strerror(-err));
        goto cleanup;
    }
    loaded = true;

    bpf_object__for_each_map(map, obj) {
        if (bpf_map__type(map) == BPF_MAP_TYPE_STRUCT_OPS) {
            ops = map;
            break;
        }
    }
    if (!ops) {
        fprintf(stderr, "%s has no struct_ops map\n", argv[optind]);
        err = -ENOENT;
        goto cleanup;
    }

    link = bpf_map__attach_compact_ext_ops(ops, node_id);
    if (!link) {
        err = -errno;
        fprintf(stderr, "Failed to attach %s to node %d: %s\n",
                bpf_map__name(ops), node_id, strerror(-err));
        goto cleanup;
    }

    printf("%s attached to node %d\n", bpf_map__name(ops), node_id);
    print_section(obj, ".rodata", "settings");
    printf("Press Ctrl-C to detach and exit.\n");

    for (i = 1; running; i++) {
        sleep(1);
        if (interval && running && i % interval == 0)
            print_counters(obj);
    }

    printf("\nDetaching...\n");
    bpf_link__destroy(link);
    print_counters(obj);

cleanup:
    for (i = 0; loaded && i < nr_pins; i++)
        bpf_map__unpin(pins[i], NULL);
    bpf_object__close(obj);
    return err ? 1 : 0;
}
