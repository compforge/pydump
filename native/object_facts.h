#ifndef PYDUMP_OBJECT_FACTS_H
#define PYDUMP_OBJECT_FACTS_H

#include <Python.h>
#include <stdint.h>

const char *pydump_type_name(PyObject *object);
uint32_t pydump_shallow_size(PyObject *object);

#endif
