#define _POSIX_C_SOURCE 200809L

#include <Python.h>

#if PY_VERSION_HEX < 0x030C0000
#include "internal/pycore_gc.h"
#include "internal/pycore_interp.h"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "protocol.h"

#if PY_VERSION_HEX < 0x030A0000
#error "The native Agent requires CPython 3.10 or newer"
#endif

#if defined(Py_GIL_DISABLED) && Py_GIL_DISABLED
#error "Free-threaded CPython is not supported"
#endif

#define PYDUMP_EXPORT __attribute__((visibility("default")))

typedef struct {
    char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    uint8_t nonce[PYDUMP_NONCE_SIZE];
} session_args;

typedef struct {
    int fd;
    uint64_t values[PYDUMP_IO_BATCH];
    size_t count;
    enum pydump_frame_kind kind;
} address_stream;

static atomic_flag session_active = ATOMIC_FLAG_INIT;

static uint64_t
host_to_be64(uint64_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl((uint32_t)(value >> 32)))
           | ((uint64_t)htonl((uint32_t)value) << 32);
#else
    return value;
#endif
}

static int
send_all(int fd, const void *data, size_t length)
{
    const uint8_t *cursor = data;
    while (length > 0) {
        ssize_t sent = send(fd, cursor, length, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent <= 0) {
            return -1;
        }
        cursor += (size_t)sent;
        length -= (size_t)sent;
    }
    return 0;
}

static int
receive_all(int fd, void *data, size_t length)
{
    uint8_t *cursor = data;
    while (length > 0) {
        ssize_t received = recv(fd, cursor, length, 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return -1;
        }
        cursor += (size_t)received;
        length -= (size_t)received;
    }
    return 0;
}

static int
send_frame(int fd, enum pydump_frame_kind kind, const void *payload, uint32_t length)
{
    uint8_t header[12];
    uint16_t flags = 0;
    uint32_t network_length = htonl(length);
    memcpy(header, "PYDP", 4);
    header[4] = PYDUMP_PROTOCOL_VERSION;
    header[5] = (uint8_t)kind;
    memcpy(header + 6, &flags, sizeof(flags));
    memcpy(header + 8, &network_length, sizeof(network_length));
    if (send_all(fd, header, sizeof(header)) < 0) {
        return -1;
    }
    return length == 0 ? 0 : send_all(fd, payload, length);
}

static int
receive_frame(int fd, enum pydump_frame_kind *kind, uint8_t *payload, uint32_t *length)
{
    uint8_t header[12];
    uint16_t flags;
    uint32_t network_length;
    if (receive_all(fd, header, sizeof(header)) < 0) {
        return -1;
    }
    memcpy(&flags, header + 6, sizeof(flags));
    memcpy(&network_length, header + 8, sizeof(network_length));
    *length = ntohl(network_length);
    if (memcmp(header, "PYDP", 4) != 0 || header[4] != PYDUMP_PROTOCOL_VERSION || flags != 0
        || *length > PYDUMP_MAX_PAYLOAD) {
        return -1;
    }
    *kind = (enum pydump_frame_kind)header[5];
    return *length == 0 ? 0 : receive_all(fd, payload, *length);
}

static int
send_error(int fd, const char *message)
{
    size_t length = strlen(message);
    if (length > PYDUMP_MAX_PAYLOAD) {
        length = PYDUMP_MAX_PAYLOAD;
    }
    return send_frame(fd, PYDUMP_ERROR, message, (uint32_t)length);
}

static int
flush_addresses(address_stream *stream)
{
    if (stream->count == 0) {
        return 0;
    }
    uint64_t payload[PYDUMP_IO_BATCH];
    for (size_t index = 0; index < stream->count; index++) {
        payload[index] = host_to_be64(stream->values[index]);
    }
    int result = send_frame(
        stream->fd,
        stream->kind,
        payload,
        (uint32_t)(stream->count * sizeof(uint64_t))
    );
    stream->count = 0;
    return result;
}

static int
stream_address(address_stream *stream, PyObject *object)
{
    stream->values[stream->count++] = (uint64_t)(uintptr_t)object;
    if (stream->count == PYDUMP_IO_BATCH) {
        return flush_addresses(stream) == 0 ? 0 : -1;
    }
    return 0;
}

static int
visit_root(PyObject *object, void *argument)
{
    return stream_address((address_stream *)argument, object) == 0;
}

static int
visit_referent(PyObject *object, void *argument)
{
    return stream_address((address_stream *)argument, object);
}

static int
send_hello(int fd, const uint8_t nonce[PYDUMP_NONCE_SIZE])
{
    uint8_t payload[20] = {
        PY_MAJOR_VERSION,
        PY_MINOR_VERSION,
        sizeof(void *),
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        1,
#else
        0,
#endif
    };
    memcpy(payload + 4, nonce, PYDUMP_NONCE_SIZE);
    return send_frame(fd, PYDUMP_HELLO, payload, sizeof(payload));
}

static int
send_well_known(int fd)
{
    PyTypeObject *types[] = {
        &PyList_Type,
        &PyTuple_Type,
        &PyDict_Type,
        &PySet_Type,
        &PyUnicode_Type,
        &PyBytes_Type,
        &PyByteArray_Type,
        &PyLong_Type,
        &PyBool_Type,
        &PyFloat_Type,
        &PyBaseObject_Type,
        &PyType_Type,
        Py_TYPE(Py_None),
    };
    uint64_t payload[sizeof(types) / sizeof(types[0])];
    for (size_t index = 0; index < sizeof(types) / sizeof(types[0]); index++) {
        payload[index] = host_to_be64((uint64_t)(uintptr_t)types[index]);
    }
    return send_frame(fd, PYDUMP_WELL_KNOWN, payload, sizeof(payload));
}

static int
send_roots(int fd)
{
    address_stream stream = {.fd = fd, .count = 0, .kind = PYDUMP_ROOT_BATCH};
#if PY_VERSION_HEX >= 0x030C0000
    PyUnstable_GC_VisitObjects(visit_root, &stream);
#else
    PyThreadState *thread = PyGILState_GetThisThreadState();
    PyInterpreterState *interpreter = PyThreadState_GetInterpreter(thread);
    struct _gc_runtime_state *gc = &interpreter->gc;
    PyGC_Head *heads[] = {
        &gc->generations[0].head,
        &gc->generations[1].head,
        &gc->generations[2].head,
        &gc->permanent_generation.head,
    };
    for (size_t generation = 0; generation < sizeof(heads) / sizeof(heads[0]); generation++) {
        PyGC_Head *head = heads[generation];
        PyGC_Head *current = _PyGCHead_NEXT(head);
        while (current != head) {
            if (current == NULL || _PyGCHead_PREV(current) == NULL) {
                return -1;
            }
            if (!visit_root((PyObject *)(current + 1), &stream)) {
                return -1;
            }
            current = _PyGCHead_NEXT(current);
        }
    }
#endif
    if (flush_addresses(&stream) < 0) {
        return -1;
    }
    return send_frame(fd, PYDUMP_ROOTS_DONE, NULL, 0);
}

static uint32_t
shallow_size(PyObject *object)
{
    PyTypeObject *type = Py_TYPE(object);
    Py_ssize_t size = type->tp_basicsize;
    if (type->tp_itemsize > 0 && !PyLong_Check(object)) {
        Py_ssize_t variable_size = Py_SIZE(object);
        if (variable_size > 0) {
            size += variable_size * type->tp_itemsize;
        }
    }
    if (PyList_CheckExact(object)) {
        size = (Py_ssize_t)sizeof(PyListObject)
               + ((PyListObject *)object)->allocated * (Py_ssize_t)sizeof(PyObject *);
    }
    if (PySet_CheckExact(object)) {
        PySetObject *set = (PySetObject *)object;
        size = (Py_ssize_t)sizeof(PySetObject);
        if (set->table != set->smalltable) {
            size += (set->mask + 1) * (Py_ssize_t)sizeof(setentry);
        }
    }
    if (size < 0) {
        return 0;
    }
    return size > UINT32_MAX ? UINT32_MAX : (uint32_t)size;
}

static enum pydump_content_kind
content_kind(PyObject *object)
{
    if (PyDict_CheckExact(object)) {
        return PYDUMP_CONTENT_DICT;
    }
    if (PyList_CheckExact(object)) {
        return PYDUMP_CONTENT_LIST;
    }
    if (PySet_CheckExact(object)) {
        return PYDUMP_CONTENT_SET;
    }
    if (PyTuple_CheckExact(object)) {
        return PYDUMP_CONTENT_TUPLE;
    }
    return PYDUMP_CONTENT_NONE;
}

static int
send_object_begin(int fd, PyObject *object, enum pydump_content_kind kind)
{
    const char *type_name = Py_TYPE(object)->tp_name == NULL ? "<unknown>" : Py_TYPE(object)->tp_name;
    size_t name_length = strlen(type_name);
    if (name_length > UINT16_MAX) {
        name_length = UINT16_MAX;
    }
    uint8_t *payload = malloc(23 + name_length);
    if (payload == NULL) {
        return -1;
    }
    uint64_t address = host_to_be64((uint64_t)(uintptr_t)object);
    uint64_t type_address = host_to_be64((uint64_t)(uintptr_t)Py_TYPE(object));
    uint32_t size = htonl(shallow_size(object));
    uint16_t network_name_length = htons((uint16_t)name_length);
    memcpy(payload, &address, sizeof(address));
    memcpy(payload + 8, &type_address, sizeof(type_address));
    memcpy(payload + 16, &size, sizeof(size));
    payload[20] = (uint8_t)kind;
    memcpy(payload + 21, &network_name_length, sizeof(network_name_length));
    memcpy(payload + 23, type_name, name_length);
    int result = send_frame(fd, PYDUMP_OBJECT_BEGIN, payload, (uint32_t)(23 + name_length));
    free(payload);
    return result;
}

static int
send_sequence_content(int fd, PyObject *object, enum pydump_content_kind kind)
{
    address_stream stream = {.fd = fd, .count = 0, .kind = PYDUMP_SEQUENCE_CONTENT};
    if (kind == PYDUMP_CONTENT_LIST) {
        Py_ssize_t length = PyList_GET_SIZE(object);
        for (Py_ssize_t index = 0; index < length; index++) {
            if (stream_address(&stream, PyList_GET_ITEM(object, index)) < 0) {
                return -1;
            }
        }
    } else if (kind == PYDUMP_CONTENT_TUPLE) {
        Py_ssize_t length = PyTuple_GET_SIZE(object);
        for (Py_ssize_t index = 0; index < length; index++) {
            if (stream_address(&stream, PyTuple_GET_ITEM(object, index)) < 0) {
                return -1;
            }
        }
    } else if (kind == PYDUMP_CONTENT_SET) {
        PySetObject *set = (PySetObject *)object;
        for (Py_ssize_t index = 0; index <= set->mask; index++) {
            setentry *entry = &set->table[index];
            if (entry->key != NULL && entry->hash != -1 && stream_address(&stream, entry->key) < 0) {
                return -1;
            }
        }
    }
    return flush_addresses(&stream);
}

static int
send_dict_content(int fd, PyObject *object)
{
    address_stream stream = {.fd = fd, .count = 0, .kind = PYDUMP_DICT_CONTENT};
    Py_ssize_t position = 0;
    PyObject *key;
    PyObject *value;
    while (PyDict_Next(object, &position, &key, &value)) {
        if (stream_address(&stream, key) < 0 || stream_address(&stream, value) < 0) {
            return -1;
        }
    }
    return flush_addresses(&stream);
}

static int
send_referents(int fd, PyObject *object)
{
    address_stream stream = {.fd = fd, .count = 0, .kind = PYDUMP_REFERENTS};
    traverseproc traverse = Py_TYPE(object)->tp_traverse;
    if (traverse != NULL && PyObject_IS_GC(object)
        && traverse(object, visit_referent, &stream) != 0) {
        return -1;
    }
    return flush_addresses(&stream);
}

static int
send_object(int fd, PyObject *object)
{
    enum pydump_content_kind kind = content_kind(object);
    if (send_object_begin(fd, object, kind) < 0) {
        return -1;
    }
    if (kind == PYDUMP_CONTENT_DICT && send_dict_content(fd, object) < 0) {
        return -1;
    }
    if ((kind == PYDUMP_CONTENT_LIST || kind == PYDUMP_CONTENT_SET
         || kind == PYDUMP_CONTENT_TUPLE)
        && send_sequence_content(fd, object, kind) < 0) {
        return -1;
    }
    if (send_referents(fd, object) < 0) {
        return -1;
    }
    return send_frame(fd, PYDUMP_OBJECT_END, NULL, 0);
}

static int
handle_requests(int fd, uint8_t *payload)
{
    while (1) {
        enum pydump_frame_kind kind;
        uint32_t length;
        if (receive_frame(fd, &kind, payload, &length) < 0) {
            return -1;
        }
        if (kind == PYDUMP_FINISH && length == 0) {
            return send_frame(fd, PYDUMP_COMPLETE, NULL, 0);
        }
        if (kind != PYDUMP_REQUEST_OBJECTS || length % sizeof(uint64_t) != 0) {
            send_error(fd, "expected an object request batch");
            return -1;
        }
        for (uint32_t offset = 0; offset < length; offset += sizeof(uint64_t)) {
            uint64_t network_address;
            memcpy(&network_address, payload + offset, sizeof(network_address));
            uint64_t address = host_to_be64(network_address);
            if (send_object(fd, (PyObject *)(uintptr_t)address) < 0) {
                return -1;
            }
        }
        if (send_frame(fd, PYDUMP_BATCH_DONE, NULL, 0) < 0) {
            return -1;
        }
    }
}

static int
configure_socket(int fd)
{
    struct timeval timeout = {.tv_sec = 30, .tv_usec = 0};
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))
           | setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static int
connect_collector(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || configure_socket(fd) < 0) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void *
session_main(void *argument)
{
    session_args *args = argument;
    pthread_detach(pthread_self());
    int fd = connect_collector(args->socket_path);
    if (fd < 0) {
        goto done;
    }

    PyGILState_STATE gil = PyGILState_Ensure();
    int gc_was_enabled = PyGC_IsEnabled();
    if (gc_was_enabled) {
        PyGC_Disable();
    }
    enum pydump_frame_kind kind;
    uint8_t options[5];
    uint32_t options_length;
    if (send_hello(fd, args->nonce) < 0
        || receive_frame(fd, &kind, options, &options_length) < 0 || kind != PYDUMP_HELLO_ACK
        || options_length != sizeof(options)) {
        send_error(fd, "native agent session failed or timed out");
    } else {
        uint8_t *requested = malloc(PYDUMP_MAX_PAYLOAD);
        if (requested == NULL || send_well_known(fd) < 0 || send_roots(fd) < 0
            || handle_requests(fd, requested) < 0) {
            send_error(fd, "native agent session failed or timed out");
        }
        free(requested);
    }
    if (gc_was_enabled) {
        PyGC_Enable();
    }
    PyGILState_Release(gil);
    close(fd);

done:
    free(args);
    atomic_flag_clear(&session_active);
    return NULL;
}

static int
decode_nonce(const char *hex, uint8_t nonce[PYDUMP_NONCE_SIZE])
{
    if (strlen(hex) != PYDUMP_NONCE_SIZE * 2) {
        return -1;
    }
    for (size_t index = 0; index < PYDUMP_NONCE_SIZE; index++) {
        unsigned int byte;
        if (sscanf(hex + index * 2, "%2x", &byte) != 1) {
            return -1;
        }
        nonce[index] = (uint8_t)byte;
    }
    return 0;
}

PYDUMP_EXPORT int
pydump_start(const char *socket_path, const char *nonce_hex)
{
    if (socket_path == NULL || nonce_hex == NULL
        || strlen(socket_path) >= sizeof(((session_args *)0)->socket_path)) {
        return 2;
    }
    if (atomic_flag_test_and_set(&session_active)) {
        return 3;
    }

    session_args *args = calloc(1, sizeof(*args));
    if (args == NULL) {
        atomic_flag_clear(&session_active);
        return 4;
    }
    memcpy(args->socket_path, socket_path, strlen(socket_path) + 1);
    if (decode_nonce(nonce_hex, args->nonce) < 0) {
        free(args);
        atomic_flag_clear(&session_active);
        return 5;
    }

    pthread_t thread;
    int result = pthread_create(&thread, NULL, session_main, args);
    if (result != 0) {
        free(args);
        atomic_flag_clear(&session_active);
    }
    return result;
}
