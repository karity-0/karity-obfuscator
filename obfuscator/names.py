"""Shared Lua identifier allocation. Generated names are temporary until emit."""
from __future__ import annotations

import random
import re
import string
from contextvars import ContextVar

RENAME_OPTIONS = ContextVar('rename_options', default={})

KEYWORDS = frozenset('and break do else elseif end false for function goto if in local nil not or repeat return then true until while'.split())


class NameAllocator:
    def __init__(self, reserved=(), *, seed=None, readable=False):
        self.used = set(reserved) | KEYWORDS | {'_ENV', 'self'}
        self.first = string.ascii_letters
        self.rest = self.first + string.digits
        if seed is not None:
            rng = random.Random(seed)
            self.first = ''.join(rng.sample(self.first, len(self.first)))
            self.rest = ''.join(rng.sample(self.rest, len(self.rest)))
        self.readable = readable
        self.counter = 0

    @classmethod
    def for_source(cls, source, **options):
        # Conservatively reserve even identifiers in comments/strings for helpers.
        return cls(re.findall(r'[A-Za-z_][A-Za-z_0-9]*', source), **options)

    def allocate(self, hint='local'):
        while True:
            index = self.counter
            self.counter += 1
            if self.readable:
                safe_hint = re.sub(r'[^A-Za-z_0-9]', '_', hint)
                name = f'_{safe_hint}_{index}'
            else:
                name = self.first[index % len(self.first)]
                index //= len(self.first)
                while index:
                    index -= 1
                    name += self.rest[index % len(self.rest)]
                    index //= len(self.rest)
            if name not in self.used:
                self.used.add(name)
                return name

    @staticmethod
    def symbolic(prefix, index):
        """Internal template symbols; never use as final emitted local names."""
        return f'{prefix}{index}'
