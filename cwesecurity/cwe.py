import glob
import json
import os
import pprint
import re
import requests
import sys
import tempfile
import types
import xmltodict
import zipfile
from bs4 import BeautifulSoup
from types import SimpleNamespace

DOWNLOADS_URL = "https://cwe.mitre.org/data/downloads.html"
ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

class Cwe():

    def __init__(self):
        self.index = None
        self.dataDir = f"{os.path.dirname(__file__)}{os.sep}data"
        self.jsonPath = f"{self.dataDir}{os.sep}cwe.json"
        self.xmlPath = f"{self.dataDir}{os.sep}cwe.xml"
        self.indexPath = f"{self.dataDir}{os.sep}index.json"
        self.cwesDir = f"{self.dataDir}{os.sep}cwes"
        self.catsDir = f"{self.dataDir}{os.sep}categories"
        self.refsDir = f"{self.dataDir}{os.sep}references"
        self.viewsDir = f"{self.dataDir}{os.sep}views"

    def checkForUpdates(self):
        lVersion = self.getLocalVersion()
        if not lVersion:
            return True
        oVersion = self.getOnlineVersion()
        return lVersion != oVersion

    def delete(self):
        paths = glob.glob(f"{self.dataDir}{os.sep}*.json")
        _rm(paths, self.xmlPath)

    def _download(self):
        tmpZipPath = f"{tempfile.gettempdir()}{os.sep}cwe.zip"
        try:
            r = requests.get(ZIP_URL, stream=True)
            try:
                _rm(tmpZipPath, self.jsonPath, self.xmlPath)
                with open(tmpZipPath, mode="wb") as fd:
                    fd.write(r.content)
            except (OSError, IOError) as e:
                _ex("Unable to locally save the online CWE content\n{e}")
        except requests.exceptions.RequestException as e:
            _ex("Unable to download the online CWE content:\n{e}")
        try:
            with zipfile.ZipFile(tmpZipPath, mode="r") as fd:
                fd.extractall(self.dataDir)
                tmpXmlPath = glob.glob(f"{self.dataDir}/cwec_v*.xml")[0]
                os.rename(tmpXmlPath, self.xmlPath)
                _rm(tmpZipPath)
        except (IOError, zipfile.BadZipfile) as e:
            _ex(f"Unable to extract downloaded CWE content:\n{e}")
        try:
            with open(self.xmlPath, encoding="utf-8") as fd1:
                xmlData = xmltodict.parse(fd1.read(), encoding="utf-8")
                with open(self.jsonPath, mode="w", encoding="utf-8") as fd2:
                    json.dump(xmlData, fd2, indent=2, sort_keys=False)
        except (OSError, IOError, Exception) as e:
            _ex(f"Unable to extract downloaded CWE content:\n{e}")

    def __get(self, group, gid, asObject=False):
        if not self.index:
            self.loadIndex()
        _gid = gid if group == "refs" else _cleanIds([gid])[0]
        r = None
        try:
            r = self.index.get(group, _gid)
        except Exception as e:
            _ex(e)
        if asObject and r:
            return _toObject(r)
        return r

    def __gets(self, group, gids, asObject=False):
        if not self.index:
            self.loadIndex()
        try:
            if len(gids) and gids[0]:
                _gids = _cleanIds(gids)
            else:
                _gids = self.index.getIds(group)
        except Exception as e:
            _ex(e)
        for _gid in _gids:
            yield self.__get(group, _gid, asObject)

    def getCategory(self, gid, asObject=False):
        return self.__get("cats", gid, asObject)

    def getCategories(self, *gids, asObject=False):
        return self.__gets("cats", gids, asObject)

    def getCwe(self, gid, asObject=False):
        return self.__get("cwes", gid, asObject)

    def getCwes(self, *gids, asObject=False):
        return self.__gets("cwes", gids, asObject)

    def getLocalVersion(self):
        if not _exists(self.jsonPath):
            return None
        content = _read(self.jsonPath)
        try:
            version = content["Weakness_Catalog"]["@Version"]
            if _isNumber(version):
                return float(version)
        except KeyError:
            pass
        return None

    def getOnlineVersion(self):
        response = requests.get(DOWNLOADS_URL)
        soup = BeautifulSoup(response.text, "html.parser")
        results = soup.find_all("h2", class_="header")
        if len(results) > 0:
            for result in results:
                if re.search("CWE List Version", result.text, re.IGNORECASE):
                    version = result.text.split()[-1]
                    if _isNumber(version):
                        return float(version)
        return None

    def getReference(self, gid, asObject=False):
        return self.__get("refs", gid, asObject)

    def getReferences(self, *gids, asObject=False):
        return self.__gets("refs", gids, asObject)

    def getView(self, gid, asObject=False):
        return self.__get("views", gid, asObject)

    def getViews(self, *gids, asObject=False):
        return self.__gets("views", gids, asObject)

    def isInstalled(self):
        if not _exists(self.jsonPath, self.xmlPath, self.indexPath):
            return False
        results = _read(self.indexPath)
        for key in ["cwes", "cats", "views", "refs"]:
            if not _exists([i for i in results[key].values()]):
                return False
        return True

    def load(self):
        self.loadIndex()

    def loadIndex(self):
        self.index = _Index(self.indexPath)
        self.index.read()
        return self.index

    def loadJson(self):
        return _read(self.jsonPath)

    def update(self):
        def _update(data, dataDir, index, key="ID"):
            for d in data:
                d = _clean(d)
                path = f"{dataDir}{os.sep}{d[key]}.json"
                index[d[key]] = path
                _write(path, d, sortKeys=False)
        self._download()
        self.index = _Index(self.indexPath)
        results = _read(self.jsonPath)
        _update(results["Weakness_Catalog"]["Weaknesses"]["Weakness"],
                self.cwesDir, self.index.cwes)
        _update(results["Weakness_Catalog"]["Categories"]["Category"],
                self.catsDir, self.index.cats)
        _update(results["Weakness_Catalog"]["Views"]["View"],
                self.viewsDir, self.index.views)
        _update(results["Weakness_Catalog"]["External_References"]["External_Reference"],
                self.refsDir, self.index.refs, "Reference_ID")
        self.index.sort().save()

class _Index():
    def __init__(self, path):
        self.path = path
        self.cwes = {}
        self.cats = {}
        self.views = {}
        self.refs = {}

    def get(self, group, gid):
        print(group, gid)
        try:
            path = getattr(self, group)[gid]
            if _exists(path):
                return _read(path)
            else:
                raise Exception(f"({group}) Missing group id {gid}")
        except KeyError:
            raise Exception(f"({group}) Unknown group id {gid}")

    def getIds(self, group):
        try:
            return list(getattr(self, group).keys())
        except Exception as e:
            raise Exception(f"({group}) Unknown group")

    def read(self):
        r = _read(self.path)
        [setattr(self, key, r[key]) \
                 for key in ["cwes", "cats", "views", "refs"]]

    def save(self):
        _write(
            self.path,
            {
                "cwes": self.cwes,
                "cats": self.cats,
                "views": self.views,
                "refs": self.refs
            },
        )

    def sort(self):
        self.cwes = {k:self.cwes[k] for k in sorted(self.cwes, key=int)}
        self.cats = {k:self.cats[k] for k in sorted(self.cats, key=int)}
        self.views = {k:self.views[k] for k in sorted(self.views, key=int)}
        self.refs = {k:self.refs[k] for k in sorted(self.refs, key=str)}
        return self

def _clean(c):
    sC = json.dumps(c)
    for t in re.findall(r'"@\w+":', sC):
        sC = re.sub(t, t.replace("@", ""), sC)
    return json.loads(sC)

def _cleanIds(ids):
    _ids = list(map(lambda i: re.sub("[^0-9]", "",
                str(i)), _toList(ids)))
    return _ids

def _ex(msg, dontExit=False):
    print(f"[Exception]: {msg}")
    if not dontExit:
        sys.exit(1)

def _exists(*paths, exit=False):
    _paths = _toList(paths)
    notExists = False
    for _path in _paths:
        if not os.path.exists(_path):
            if exit:
                sys.exit(1)
            notExists = True
            break
    return not notExists

def _isNumber(token):
    try:
        float(token)
    except ValueError:
        return False
    return True

def _out(msg, asText=False, sort=False, indent=1):
    if asText:
        print(msg)
    else:
        pprint.pprint(msg, sort_dicts=sort, indent=indent)

def _read(*paths):
    results = [r for r in _readG(_toList(paths))]
    if len(results) < 2:
        return results[0]
    return results

def _readG(*paths):
    _paths = _toList(paths)
    try:
        for _path in _paths:
            with open(_path) as fd:
                yield json.load(fd)
    except (OSError, IOError) as e:
        _ex("Can't read {_paths}: {e}")

def _rm(*paths):
    _paths = _toList(paths)
    try:
        [os.remove(_path) for _path in _paths]
    except OSError:
        pass

def _toList(args):
    _args = []
    for _ in list(args):
        if isinstance(_, list):
            _args.extend(_)
        elif isinstance(_, set):
            _args.extend(_, list(set))
        else:
            _args.append(_)
    return _args

def _toObject(data):
    _data = data
    if isinstance(_data, dict):
        _data = json.dumps(_data)
    return json.loads(_data, object_hook=lambda d: SimpleNamespace(**d))

def _write(path, content, sortKeys=False):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fd:
            json.dump(content, fd, indent=2, sort_keys=sortKeys)
    except (OSError, IOError) as e:
        _ex(f"Can't write to {path}: {e}")

if __name__ == "__main__":
    pass