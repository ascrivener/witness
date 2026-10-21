#!/usr/bin/env python3
"""Make a solver's delta: the part of a full lean4export export that isn't in the statement
environment, renumbered to continue the environment's indices.

    lean_delta.py ENV FULL > DELTA

ENV is the poster's export (the statement and its dependencies). FULL is the solver's export of
their theorem, which repeats ENV's items. The checker reads ENV followed by DELTA as one export.

Every name (`in`), level (`il`) and expression (`ie`) item is defined by its content plus
references to earlier items, so identical content means the same item. FULL's items are mapped
onto ENV's by content. Items that aren't in ENV get the next free index, and declarations already
in ENV are dropped.

A FULL declaration with an ENV name but different content (a redefinition) is kept. The checker
then rejects the duplicate name, which is the point.
"""

import json
import sys

INDEX_KEYS = ("in", "il", "ie")

# Which index space each field refers to.
NAME_FIELDS = {"pre", "name", "levelParams", "all", "induct", "ctor", "typeName", "param"}
EXPR_FIELDS = {"type", "value", "body", "fn", "arg", "struct", "rhs", "expr"}
LEVEL_FIELDS = {"us", "succ", "max", "imax", "sort"}


def space(field):
    if field in NAME_FIELDS:
        return "in"
    if field in EXPR_FIELDS:
        return "ie"
    if field in LEVEL_FIELDS:
        return "il"
    return None


def remap(value, field, maps):
    """Rewrite the references in `value` (found under `field`) through `maps`."""
    if isinstance(value, dict):
        return {k: remap(v, k, maps) for k, v in value.items()}
    if isinstance(value, list):
        return [remap(v, field, maps) for v in value]
    if isinstance(value, int) and not isinstance(value, bool):
        # `ctors` is a list of names in an inductive type, but a list of objects at the top of an
        # inductive block; objects are handled above, so an int here is a name.
        s = "in" if field == "ctors" else space(field)
        return maps[s][value] if s else value
    return value


def index_key(line):
    keys = [k for k in INDEX_KEYS if k in line]
    return keys[0] if keys else None


def canonical(line):
    return json.dumps({k: v for k, v in line.items() if k not in INDEX_KEYS}, sort_keys=True)


def read(path):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def main(env_path, full_path):
    # Index 0 is predefined for names (anonymous) and levels (zero).
    env_items = {"in": {}, "il": {}, "ie": {}}
    env_decls = set()
    next_index = {"in": 1, "il": 1, "ie": 0}
    for line in read(env_path):
        if "meta" in line:
            continue
        k = index_key(line)
        if k:
            env_items[k][canonical(line)] = line[k]
            next_index[k] = max(next_index[k], line[k] + 1)
        else:
            env_decls.add(canonical(line))

    maps = {"in": {0: 0}, "il": {0: 0}, "ie": {}}
    out = []
    for line in read(full_path):
        if "meta" in line:
            continue
        k = index_key(line)
        body = {f: remap(v, f, maps) for f, v in line.items() if f not in INDEX_KEYS}
        key = json.dumps(body, sort_keys=True)
        if k:
            if key in env_items[k]:
                maps[k][line[k]] = env_items[k][key]
            else:
                maps[k][line[k]] = next_index[k]
                out.append({**body, k: next_index[k]})
                next_index[k] += 1
        elif key not in env_decls:
            out.append(body)

    for line in out:
        sys.stdout.write(json.dumps(line, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
