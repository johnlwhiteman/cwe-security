import glob
import json
import os
import pathlib
import re
import requests
import sys
import tempfile
import xmltodict
import zipfile
from bs4 import BeautifulSoup
from pprint import pprint as p

sys.path.append(str(pathlib.Path(__file__).resolve().parent))
import cweutil

DOWNLOADS_URL = "https://cwe.mitre.org/data/downloads.html"
ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

class Cwe():

    def __init__(self):
        self.db = None
        self.dataDir = f"{os.path.dirname(__file__)}{os.sep}data"
        self.jsonPath = f"{self.dataDir}{os.sep}cwe.json"
        self.xmlPath = f"{self.dataDir}{os.sep}cwe.xml"
        self.dbPath = f"{self.dataDir}{os.sep}db.json"
        self.viewDir = f"{self.dataDir}{os.sep}view"
        self.catDir = f"{self.dataDir}{os.sep}cat"
        self.cweDir = f"{self.dataDir}{os.sep}cwe"

    def createDb(self):
        self.db = {}
        cweutil.rm(self.dbPath)
        results = self.loadJson()
        self.__createDbKey(results["Weakness_Catalog"]["Views"]["View"], "view")
        self.__createDbKey(results["Weakness_Catalog"]["Categories"]["Category"], "cat")
        self.__createDbKey(results["Weakness_Catalog"]["Weaknesses"]["Weakness"], "cwe")
        self.__createDbView()
        self.__createDbCat()
        self.__createDbCwe()
        cweutil.write(self.dbPath, self.db)

    def __createDbKey(self, data, key):
        def cleanDbKeys(data):
            _data = json.dumps(data)
            for t in re.findall(r'"@\w+":', _data):
                _data = re.sub(t, t.replace("@", ""), _data)
            return json.loads(_data)
        ids = {}
        for d in data:
            d = cleanDbKeys(d)
            _id = d["ID"]
            path = f"{self.dataDir}{os.sep}{key}{os.sep}{_id}.json"
            url = f"https://cwe.mitre.org/data/{_id}.html"
            self.db[_id] = {
                "id": _id,
                "key": key,
                "status": d["Status"],
                "path": path,
                "url": url,
                "hasMem": {
                    "view": [],
                    "cat": [],
                    "cwe": [],
                },
                "memOf": {
                    "view": [],
                    "cat": [],
                    "cwe": []
                }
            }
            cweutil.write(path, d, sortKeys =False)

    def __createDbCat(self):
        for cat in self.getCat():
            try:
                catId = cat["ID"]
                self.db[catId]["status"] = cat["Status"]
                nodes = cat["Relationships"]["Has_Member"]
                if isinstance(nodes, dict):
                    nodes = [nodes]
                for node in nodes:
                    key = self.getKey(node["CWE_ID"])
                    self.db[catId]["hasMem"][key].append(node["CWE_ID"])
                    self.db[catId]["memOf"]["view"].append(node["View_ID"])
                    self.db[node["CWE_ID"]]["memOf"][key].append(catId)
                    self.db[node["CWE_ID"]]["memOf"]["view"].append(node["View_ID"])
            except Exception as e:
                pass
            self.normalizeDb()

    def __createDbCwe(self):
        for cwe in self.getCwe():
            try:
                cweId = cwe["ID"]
                self.db[cweId]["status"] = cwe["Status"]
            except Exception as e:
                pass
        self.normalizeDb()

    def __createDbView(self):
        for view in self.getView():
            try:
                viewId = view["ID"]
                nodes = view["Members"]["Has_Member"]
                if isinstance(nodes, dict):
                    nodes = [nodes]
                for node in nodes:
                    key = self.getKey(node["CWE_ID"])
                    self.db[viewId]["hasMem"][key].append(node["CWE_ID"])
                    self.db[node["CWE_ID"]]["memOf"]["view"].append(viewId)
            except Exception as e:
                pass
        self.normalizeDb()

    def deleteDb(self):
        for key in ["view", "cat", "cwe"]:
            [cweutil.rm(path) for path in glob.glob(f"{self.dataDir}{os.sep}{key}{os.sep}*.json")]
        for key in ["json", "xml"]:
            [cweutil.rm(path) for path in glob.glob(f"{self.dataDir}{os.sep}*.{key}")]

    def download(self):
        tmpZipPath = f"{tempfile.gettempdir()}{os.sep}cwe.zip"
        cweutil.rm(tmpZipPath, self.jsonPath, self.xmlPath)
        try:
            r = requests.get(ZIP_URL, stream=True)
            try:
                with open(tmpZipPath, mode="wb") as fd:
                    fd.write(r.content)
            except (OSError, IOError) as e:
                cweutil.ex("Unable to locally save the online CWE content\n{e}")
        except requests.exceptions.RequestException as e:
            cweutil.ex("Unable to download the online CWE content:\n{e}")
        try:
            with zipfile.ZipFile(tmpZipPath, mode="r") as fd:
                fd.extractall(self.dataDir)
                tmpXmlPath = glob.glob(f"{self.dataDir}/cwec_v*.xml")[0]
                os.rename(tmpXmlPath, self.xmlPath)
                cweutil.rm(tmpZipPath)
        except (IOError, zipfile.BadZipfile) as e:
            cweutil.ex(f"Unable to extract downloaded CWE content:\n{e}")
        try:
            with open(self.xmlPath, encoding="utf-8") as fd1:
                xmlData = xmltodict.parse(fd1.read(), encoding="utf-8")
                with open(self.jsonPath, mode="w", encoding="utf-8") as fd2:
                    json.dump(xmlData, fd2, indent=2, sort_keys=False)
        except (OSError, IOError, Exception) as e:
            cweutil.ex(f"Unable to extract downloaded CWE content:\n{e}")

    def __get(self, ids, key):
        nodes = self.getDb(key)

        if not ids:
            for node in nodes:
                yield cweutil.read(node["path"])
        else:
            for node in nodes:
                if node["id"] in ids and node["key"] in key:
                    yield cweutil.read(node["path"])

    def getCat(self, *ids):
        return self.__get(cweutil.toList(ids), "cat")

    def getCwe(self, *ids):
        return self.__get(cweutil.toList(ids), "cwe")

    def getDb(self, *keys):
        if not self.db:
            self.loadDb()
        _keys = cweutil.toList(keys)
        if not _keys:
            for k, v in self.db.items():
                yield v
        else:
            for k, v in self.db.items():
                if v["key"] in _keys:
                    yield v

    def getKey(self, keyId):
        try:
            return self.db[keyId]["key"]
        except:
            return None

    def getLocalVersion(self):
        if not cweutil.exists(self.jsonPath):
            return None
        content = cweutil.read(self.jsonPath)
        try:
            version = content["Weakness_Catalog"]["@Version"]
            if cweutil.isNumber(version):
                return float(version)
        except KeyError:
            pass
        return None

    def getRemoteVersion(self):
        response = requests.get(DOWNLOADS_URL)
        soup = BeautifulSoup(response.text, "html.parser")
        results = soup.find_all("h2", class_="header")
        if len(results) > 0:
            for result in results:
                if re.search("CWE List Version", result.text, re.IGNORECASE):
                    version = result.text.split()[-1]
                    if cweutil.isNumber(version):
                        return float(version)
        return None

    def getView(self, *ids):
        return self.__get(cweutil.toList(ids), "view")

    def hasUpdate(self):
        lVersion = self.getLocalVersion()
        if not lVersion:
            return True
        rVersion = self.getRemoteVersion()
        return lVersion != rVersion

    def isInstalled(self):
        if not cweutil.exists(self.dbPath, self.jsonPath, self.xmlPath):
            return False
        paths = [v["path"] for v in cweutil.read(self.dbPath).values()]
        return cweutil.exists(paths)

    def loadDb(self):
        self.db = cweutil.read(self.dbPath)
        return  self.db

    def loadJson(self):
        return cweutil.read(self.jsonPath)

    def normalizeDb(self):
        for _id in self.db.keys():
            for x in ["hasMem", "memOf"]:
                for y in ["view", "cat", "cwe"]:
                    self.db[_id][x][y] = sorted(list(set(self.db[_id][x][y])), key=int)
        self.db = {k:v for k, v in sorted(self.db.items(), key=lambda item: int(item[0]))}

    def update(self):
        self.deleteDb()
        self.download()
        self.createDb()

if __name__ == "__main__":
    pass
