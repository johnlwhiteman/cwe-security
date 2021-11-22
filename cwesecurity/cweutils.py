import json
import os
import pprint
import sys

def ex(msg, dontExit=False):
    print(f"[Exception]: {msg}")
    if not dontExit:
        sys.exit(1)

def exists(*paths, verbose=False, exit=False):
    _paths = toList(paths)
    notExists = False
    for _path in _paths:
        if not os.path.exists(_path):
            out("Can't find {_path}", verbose=verbose)
            if exit:
                sys.exit(1)
            notExists = True
            break
    return not notExists

def isNumber(token):
    try:
        float(token)
    except ValueError:
        return False
    return True

def out(msg, asText=False, verbose=None, sort=False, indent=1):
    if verbose or verbose is None:
        if asText:
            print(msg)
        else:
            pprint.pprint(msg, sort_dicts=sort, indent=indent)

def read(*paths, verbose=False):
    results = [r for r in readG(toList(paths))]
    if len(results) < 2:
        return results[0]
    return results

def readG(*paths, verbose=False):
    _paths = toList(paths)
    try:
        for _path in _paths:
            out(f"Reading {_path}", asText=True, verbose=verbose)
            with open(_path) as fd:
                yield json.load(fd)
    except (OSError, IOError) as e:
        ex("Can't read {_paths}: {e}")

def rm(*paths):
    _paths = toList(paths)
    try:
        [os.remove(_path) for _path in _paths]
    except OSError:
        pass

def toLinuxPath(path):
    return path.replace(os.path.sep, "/")

def toList(args):
    _args = []
    for _ in list(args):
        if isinstance(_, list):
            _args.extend(_)
        elif isinstance(_, set):
            _args.extend(_, list(set))
        else:
            _args.append(_)
    return _args

def tout(msg, verbose=None):
    out(msg, asText=False, verbose=verbose)

def write(path, content, sortKeys=False, verbose=False):
    out(f"Writing {path}", asText=True, verbose=verbose)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fd:
            json.dump(content, fd, indent=2, sort_keys=sortKeys)
    except (OSError, IOError) as e:
        ex(f"Can't write to {path}: {e}")
