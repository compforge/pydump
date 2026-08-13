#include <Python.h>
#include <frameobject.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "object_facts.h"

#if PY_VERSION_HEX < 0x030A0000
#error "Object facts require CPython 3.10 or newer"
#endif

/* These are exported CPython-private functions. The Agent is already built
   for one exact CPython minor, so using them does not widen the ABI boundary. */
PyAPI_FUNC(Py_ssize_t) _PyDict_SizeOf(PyDictObject *);
PyAPI_FUNC(size_t) _PySys_GetSizeOf(PyObject *);

static size_t
preheader_size(PyObject *object)
{
#if PY_VERSION_HEX < 0x030B0000
    return PyObject_IS_GC(object) ? 2 * sizeof(uintptr_t) : 0;
#else
#if PY_VERSION_HEX >= 0x030D0000
    if (Py_IS_TYPE(object, &PyType_Type)
        && !PyType_HasFeature((PyTypeObject *)object, Py_TPFLAGS_HEAPTYPE)) {
        return 0;
    }
#endif
    size_t size = PyType_HasFeature(Py_TYPE(object), Py_TPFLAGS_HAVE_GC)
                      ? 2 * sizeof(uintptr_t)
                      : 0;
#if PY_VERSION_HEX < 0x030C0000
    if (PyType_HasFeature(Py_TYPE(object), Py_TPFLAGS_MANAGED_DICT)) {
#else
    if (PyType_HasFeature(Py_TYPE(object), Py_TPFLAGS_PREHEADER)) {
#endif
        size += 2 * sizeof(PyObject *);
    }
    return size;
#endif
}

static size_t
unicode_size(PyObject *object)
{
    PyASCIIObject *ascii = (PyASCIIObject *)object;
    PyCompactUnicodeObject *compact = (PyCompactUnicodeObject *)object;
    PyUnicodeObject *unicode = (PyUnicodeObject *)object;
    size_t length = (size_t)PyUnicode_GET_LENGTH(object);
    size_t size;
    void *data;

    if (PyUnicode_IS_COMPACT_ASCII(object)) {
        size = sizeof(PyASCIIObject) + length + 1;
        data = ascii + 1;
    } else if (PyUnicode_IS_COMPACT(object)) {
        size = sizeof(PyCompactUnicodeObject)
               + (length + 1) * (size_t)PyUnicode_KIND(object);
        data = compact + 1;
    } else {
        size = sizeof(PyUnicodeObject);
        data = unicode->data.any;
        if (data != NULL) {
            size += (length + 1) * (size_t)PyUnicode_KIND(object);
        }
    }

#if PY_VERSION_HEX < 0x030C0000
    if (ascii->wstr != NULL && ascii->wstr != data) {
        size_t wstr_length = PyUnicode_IS_COMPACT_ASCII(object)
                                 ? length
                                 : (size_t)compact->wstr_length;
        size += (wstr_length + 1) * sizeof(wchar_t);
    }
#endif
    if (!PyUnicode_IS_COMPACT_ASCII(object) && compact->utf8 != NULL
        && compact->utf8 != data) {
        size += (size_t)compact->utf8_length + 1;
    }
    return size;
}

static size_t
type_fallback_size(PyTypeObject *type)
{
    return PyType_HasFeature(type, Py_TPFLAGS_HEAPTYPE) ? sizeof(PyHeapTypeObject)
                                                        : sizeof(PyTypeObject);
}

static int
dict_defines_sizeof(PyObject *dict)
{
    Py_ssize_t position = 0;
    PyObject *key;
    PyObject *value;
    while (PyDict_Next(dict, &position, &key, &value)) {
        (void)value;
        if (PyUnicode_CheckExact(key) && PyUnicode_GET_LENGTH(key) == 10
            && PyUnicode_KIND(key) == PyUnicode_1BYTE_KIND
            && memcmp(PyUnicode_1BYTE_DATA(key), "__sizeof__", 10) == 0) {
            return 1;
        }
    }
    return 0;
}

static int
type_uses_builtin_sizeof(PyTypeObject *metaclass)
{
    PyObject *mro = metaclass->tp_mro;
    if (mro == NULL || !PyTuple_CheckExact(mro)) {
        return 0;
    }
    Py_ssize_t length = PyTuple_GET_SIZE(mro);
    for (Py_ssize_t index = 0; index < length; index++) {
        PyTypeObject *base = (PyTypeObject *)PyTuple_GET_ITEM(mro, index);
        if (base == &PyType_Type) {
            return 1;
        }
        if (base->tp_dict != NULL && dict_defines_sizeof(base->tp_dict)) {
            return 0;
        }
    }
    return 0;
}

static size_t
known_object_size(PyObject *object)
{
    PyTypeObject *type = Py_TYPE(object);
    if (PyDict_CheckExact(object)) {
        return (size_t)_PyDict_SizeOf((PyDictObject *)object);
    }
    if (PyList_CheckExact(object)) {
        PyListObject *list = (PyListObject *)object;
        return sizeof(PyListObject) + (size_t)list->allocated * sizeof(PyObject *);
    }
    if (PyAnySet_CheckExact(object)) {
        PySetObject *set = (PySetObject *)object;
        size_t size = sizeof(PySetObject);
        if (set->table != set->smalltable) {
            size += ((size_t)set->mask + 1) * sizeof(setentry);
        }
        return size;
    }
    if (PyUnicode_CheckExact(object)) {
        return unicode_size(object);
    }
    if (PyLong_CheckExact(object) || PyBool_Check(object)) {
        return _PySys_GetSizeOf(object);
    }
    if (PyByteArray_CheckExact(object)) {
        return sizeof(PyByteArrayObject)
               + (size_t)((PyByteArrayObject *)object)->ob_alloc * sizeof(char);
    }
    if (PyTuple_CheckExact(object) || PyBytes_CheckExact(object)) {
        return (size_t)type->tp_basicsize
               + (size_t)Py_SIZE(object) * (size_t)type->tp_itemsize;
    }
    if (PyGen_CheckExact(object) || PyCoro_CheckExact(object)
        || PyAsyncGen_CheckExact(object)) {
        return _PySys_GetSizeOf(object);
    }
    if (PyCode_Check(object)) {
        return _PySys_GetSizeOf(object);
    }
    if (PyFrame_Check(object)) {
        return _PySys_GetSizeOf(object);
    }
    if (PyType_Check(object)) {
        return type_fallback_size((PyTypeObject *)object);
    }

    /* Unknown extension and application types may repurpose ob_size or
       override __sizeof__. Their fixed allocation is the safe lower bound. */
    return type->tp_basicsize > 0 ? (size_t)type->tp_basicsize : 0;
}

const char *
pydump_type_name(PyObject *object)
{
    PyTypeObject *type = Py_TYPE(object);
    return type->tp_name == NULL ? "<unknown>" : _PyType_Name(type);
}

uint32_t
pydump_shallow_size(PyObject *object)
{
    if (PyType_Check(object) && type_uses_builtin_sizeof(Py_TYPE(object))) {
        size_t size = _PySys_GetSizeOf(object);
        return size > UINT32_MAX ? UINT32_MAX : (uint32_t)size;
    }
    size_t size = known_object_size(object);
    if (PyLong_CheckExact(object) || PyBool_Check(object) || PyGen_CheckExact(object)
        || PyCoro_CheckExact(object) || PyAsyncGen_CheckExact(object)
        || PyCode_Check(object) || PyFrame_Check(object)) {
        return size > UINT32_MAX ? UINT32_MAX : (uint32_t)size;
    }
    size += preheader_size(object);
    return size > UINT32_MAX ? UINT32_MAX : (uint32_t)size;
}
