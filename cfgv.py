from __future__ import absolute_import
from __future__ import unicode_literals

import collections
import contextlib
import io
import os.path
import re
import sys

import six


class ValidationError(ValueError):
    def __init__(self, error_msg, ctx=None):
        super(ValidationError, self).__init__(error_msg)
        self.error_msg = error_msg
        self.ctx = ctx

    def __str__(self):
        out = '\n'
        err = self
        while err.ctx is not None:
            out += '==> {}\n'.format(err.ctx)
            err = err.error_msg
        out += '=====> {}'.format(err.error_msg)
        return out


MISSING = collections.namedtuple('Missing', ())()
type(MISSING).__repr__ = lambda self: 'MISSING'


@contextlib.contextmanager
def validate_context(msg):
    try:
        yield
    except ValidationError as e:
        _, _, tb = sys.exc_info()
        six.reraise(ValidationError, ValidationError(e, ctx=msg), tb)


@contextlib.contextmanager
def reraise_as(tp):
    try:
        yield
    except ValidationError as e:
        _, _, tb = sys.exc_info()
        six.reraise(tp, tp(e), tb)


def _dct_noop(self, dct):
    pass


def _check_optional(self, dct):
    if self.key not in dct:
        return
    with validate_context('At key: {}'.format(self.key)):
        self.check_fn(dct[self.key])


def _apply_default_optional(self, dct):
    dct.setdefault(self.key, self.default)


def _remove_default_optional(self, dct):
    if dct.get(self.key, MISSING) == self.default:
        del dct[self.key]


def _require_key(self, dct):
    if self.key not in dct:
        raise ValidationError('Missing required key: {}'.format(self.key))


def _check_required(self, dct):
    _require_key(self, dct)
    _check_optional(self, dct)


@property
def _check_fn_recurse(self):
    def check_fn(val):
        validate(val, self.schema)
    return check_fn


def _apply_default_required_recurse(self, dct):
    dct[self.key] = apply_defaults(dct[self.key], self.schema)


def _remove_default_required_recurse(self, dct):
    dct[self.key] = remove_defaults(dct[self.key], self.schema)


def _apply_default_optional_recurse(self, dct):
    if self.key not in dct:
        _apply_default_optional(self, dct)
    _apply_default_required_recurse(self, dct)


def _remove_default_optional_recurse(self, dct):
    if self.key in dct:
        _remove_default_required_recurse(self, dct)
        _remove_default_optional(self, dct)


def _check_conditional(self, dct):
    if dct.get(self.condition_key, MISSING) == self.condition_value:
        _check_required(self, dct)
    elif self.condition_key in dct and self.ensure_absent and self.key in dct:
        if hasattr(self.condition_value, 'describe_opposite'):
            explanation = self.condition_value.describe_opposite()
        else:
            explanation = 'is not {!r}'.format(self.condition_value)
        raise ValidationError(
            'Expected {key} to be absent when {cond_key} {explanation}, '
            'found {key}: {val!r}'.format(
                key=self.key,
                val=dct[self.key],
                cond_key=self.condition_key,
                explanation=explanation,
            ),
        )


Required = collections.namedtuple('Required', ('key', 'check_fn'))
Required.check = _check_required
Required.apply_default = _dct_noop
Required.remove_default = _dct_noop
RequiredRecurse = collections.namedtuple('RequiredRecurse', ('key', 'schema'))
RequiredRecurse.check = _check_required
RequiredRecurse.check_fn = _check_fn_recurse
RequiredRecurse.apply_default = _apply_default_required_recurse
RequiredRecurse.remove_default = _remove_default_required_recurse
Optional = collections.namedtuple('Optional', ('key', 'check_fn', 'default'))
Optional.check = _check_optional
Optional.apply_default = _apply_default_optional
Optional.remove_default = _remove_default_optional
OptionalRecurse = collections.namedtuple(
    'OptionalRecurse', ('key', 'schema', 'default'),
)
OptionalRecurse.check = _check_optional
OptionalRecurse.check_fn = _check_fn_recurse
OptionalRecurse.apply_default = _apply_default_optional_recurse
OptionalRecurse.remove_default = _remove_default_optional_recurse
OptionalNoDefault = collections.namedtuple(
    'OptionalNoDefault', ('key', 'check_fn'),
)
OptionalNoDefault.check = _check_optional
OptionalNoDefault.apply_default = _dct_noop
OptionalNoDefault.remove_default = _dct_noop
Conditional = collections.namedtuple(
    'Conditional',
    ('key', 'check_fn', 'condition_key', 'condition_value', 'ensure_absent'),
)
Conditional.__new__.__defaults__ = (False,)
Conditional.check = _check_conditional
Conditional.apply_default = _dct_noop
Conditional.remove_default = _dct_noop
ConditionalRecurse = collections.namedtuple(
    'ConditionalRecurse',
    ('key', 'schema', 'condition_key', 'condition_value', 'ensure_absent'),
)
ConditionalRecurse.__new__.__defaults__ = (False,)
ConditionalRecurse.check = _check_conditional
ConditionalRecurse.check_fn = _check_fn_recurse
ConditionalRecurse.apply_default = _dct_noop
ConditionalRecurse.remove_default = _dct_noop


class Map(collections.namedtuple('Map', ('object_name', 'id_key', 'items'))):
    __slots__ = ()

    def __new__(cls, object_name, id_key, *items):
        return super(Map, cls).__new__(cls, object_name, id_key, items)

    def check(self, v):
        if not isinstance(v, dict):
            raise ValidationError('Expected a {} map but got a {}'.format(
                self.object_name, type(v).__name__,
            ))
        if self.id_key is None:
            context = 'At {}()'.format(self.object_name)
        else:
            context = 'At {}({}={!r})'.format(
                self.object_name, self.id_key, v.get(self.id_key, MISSING),
            )
        with validate_context(context):
            for item in self.items:
                item.check(v)

    def apply_defaults(self, v):
        ret = v.copy()
        for item in self.items:
            item.apply_default(ret)
        return ret

    def remove_defaults(self, v):
        ret = v.copy()
        for item in self.items:
            item.remove_default(ret)
        return ret


class Array(collections.namedtuple('Array', ('of', 'allow_empty'))):
    __slots__ = ()

    def __new__(cls, of, allow_empty=True):
        return super(Array, cls).__new__(cls, of=of, allow_empty=allow_empty)

    def check(self, v):
        check_array(check_any)(v)
        if not self.allow_empty and not v:
            raise ValidationError(
                "Expected at least 1 '{}'".format(self.of.object_name),
            )
        for val in v:
            validate(val, self.of)

    def apply_defaults(self, v):
        return [apply_defaults(val, self.of) for val in v]

    def remove_defaults(self, v):
        return [remove_defaults(val, self.of) for val in v]


class Not(collections.namedtuple('Not', ('val',))):
    __slots__ = ()

    def describe_opposite(self):
        return 'is {!r}'.format(self.val)

    def __eq__(self, other):
        return other is not MISSING and other != self.val


class NotIn(collections.namedtuple('NotIn', ('values',))):
    __slots__ = ()

    def __new__(cls, *values):
        return super(NotIn, cls).__new__(cls, values=values)

    def describe_opposite(self):
        return 'is any of {!r}'.format(self.values)

    def __eq__(self, other):
        return other is not MISSING and other not in self.values


class In(collections.namedtuple('In', ('values',))):
    __slots__ = ()

    def __new__(cls, *values):
        return super(In, cls).__new__(cls, values=values)

    def describe_opposite(self):
        return 'is not any of {!r}'.format(self.values)

    def __eq__(self, other):
        return other is not MISSING and other in self.values


def check_any(_):
    pass


def check_type(tp, typename=None):
    def check_type_fn(v):
        if not isinstance(v, tp):
            raise ValidationError(
                'Expected {} got {}'.format(
                    typename or tp.__name__, type(v).__name__,
                ),
            )
    return check_type_fn


check_bool = check_type(bool)
check_bytes = check_type(bytes, typename='bytes')
check_int = check_type(int)
check_string = check_type(six.string_types, typename='string')
check_text = check_type(six.text_type, typename='text')


def check_one_of(possible):
    def check_one_of_fn(v):
        if v not in possible:
            raise ValidationError('Expected one of {} but got: {!r}'.format(
                ', '.join(str(x) for x in sorted(possible)), v,
            ))
    return check_one_of_fn


def check_regex(v):
    try:
        re.compile(v)
    except re.error:
        raise ValidationError('{!r} is not a valid python regex'.format(v))


def check_array(inner_check):
    def check_array_fn(v):
        if not isinstance(v, (list, tuple)):
            raise ValidationError(
                'Expected array but got {!r}'.format(type(v).__name__),
            )

        for i, val in enumerate(v):
            with validate_context('At index {}'.format(i)):
                inner_check(val)
    return check_array_fn


def check_and(*fns):
    def check(v):
        for fn in fns:
            fn(v)
    return check


def validate(v, schema):
    schema.check(v)
    return v


def apply_defaults(v, schema):
    return schema.apply_defaults(v)


def remove_defaults(v, schema):
    return schema.remove_defaults(v)


def load_from_filename(
        filename,
        schema,
        load_strategy,
        exc_tp=ValidationError,
):
    with reraise_as(exc_tp):
        if not os.path.exists(filename):
            raise ValidationError('{} does not exist'.format(filename))

        with io.open(filename) as f:
            contents = f.read()

        with validate_context('File {}'.format(filename)):
            try:
                data = load_strategy(contents)
            except Exception as e:
                raise ValidationError(str(e))

            validate(data, schema)
            return apply_defaults(data, schema)
