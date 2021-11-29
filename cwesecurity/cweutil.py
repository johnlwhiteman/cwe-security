import json
import os
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent))

def ex(msg, dontExit=False):
    print(f"[Exception]: {msg}")
    if not dontExit:
        sys.exit(1)

def exists(*paths, exit=False):
    _paths = toList(paths)
    notExists = False
    for _path in _paths:
        if not os.path.exists(_path):
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

def read(*paths):
    _paths = toList(paths)
    try:
        for _path in _paths:
            with open(_path) as fd:
                return json.load(fd)
    except (OSError, IOError) as e:
        ex("Can't read {_paths}: {e}")

def rm(*paths):
    _paths = toList(paths)
    try:
        [os.remove(_path) for _path in _paths]
    except OSError:
        pass

def toList(args):
    if not args or len(args) < 1 or args[0] is None:
        return None
    _args = []
    for _ in list(args):
        if isinstance(_, list):
            _args.extend(_)
        elif isinstance(_, set):
            _args.extend(_, list(set))
        else:
            _args.append(_)
    return [str(_) for _ in list(set(_args))]

def write(path, content, sortKeys=False):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fd:
            json.dump(content, fd, indent=2, sort_keys=sortKeys)
    except (OSError, IOError) as e:
        ex(f"Can't write to {path}: {e}")

if __name__ == "__main__":
    pass