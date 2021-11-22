import glob
import json
import os
import re
import requests
import sys
import tempfile
import xmltodict
import zipfile
from bs4 import BeautifulSoup
import cweutils as cu

DOWNLOADS_URL = "https://cwe.mitre.org/data/downloads.html"
ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

class Cwe():

    def __init__(self):
        self.dataDir = cu.toLinuxPath(f"{os.path.dirname(__file__)}{os.sep}data")
        self.jsonPath = cu.toLinuxPath(f"{self.dataDir}{os.sep}cwe.json")
        self.xmlPath = cu.toLinuxPath(f"{self.dataDir}{os.sep}cwe.xml")
        self.indexPath = cu.toLinuxPath(f"{self.dataDir}{os.sep}index.json")
        self.catsPath = cu.toLinuxPath(f"{self.dataDir}{os.sep}cats.json")
        self.refsPath = cu.toLinuxPath(f"{self.dataDir}{os.sep}refs.json")
        self.viewsPath = cu.toLinuxPath(f"{self.dataDir}{os.sep}views.json")
        self.index = None

    def checkForUpdates(self):
        if not self.isInstalled():
            return True
        lVersion = self.getLocalVersion()
        if not lVersion:
            return True
        oVersion = self.getOnlineVersion()
        return lVersion != oVersion

    def delete(self):
        paths = glob.glob(f"{self.dataDir}{os.sep}*.json")
        cu.rm(paths, self.xmlPath)

    def __download(self):
        tmpZipPath = f"{tempfile.gettempdir()}{os.sep}cwe.zip"

        # Download
        try:
            r = requests.get(ZIP_URL, stream=True)
            try:
                cu.rm(tmpZipPath, self.jsonPath, self.xmlPath)
                with open(tmpZipPath, mode="wb") as fd:
                    fd.write(r.content)
            except (OSError, IOError) as e:
                cu.ex("Unable to locally save the online CWE content\n{e}")
        except requests.exceptions.RequestException as e:
            cu.ex("Unable to download the online CWE content:\n{e}")

        # Extract
        try:
            with zipfile.ZipFile(tmpZipPath, mode="r") as fd:
                fd.extractall(self.dataDir)
                tmpXmlPath = glob.glob(f"{self.dataDir}/cwec_v*.xml")[0]
                os.rename(tmpXmlPath, self.xmlPath)
                cu.rm(tmpZipPath)
        except (IOError, zipfile.BadZipfile) as e:
            cu.ex(f"Unable to extract downloaded CWE content:\n{e}")

        # Convert/Copy XML to JSON
        try:
            with open(self.xmlPath, encoding="utf-8") as fd1:
                xmlData = xmltodict.parse(fd1.read(), encoding="utf-8")
                with open(self.jsonPath, mode="w", encoding="utf-8") as fd2:
                    json.dump(xmlData, fd2, indent=2, sort_keys=False)
        except (OSError, IOError, Exception) as e:
            cu.ex(f"Unable to extract downloaded CWE content:\n{e}")

    def getCwe(self, cweId, verbose=False):
        if not self.index:
            self.loadIndex()
        cweId = re.sub("[^0-9]", "", str(cweId))
        try:
            path = self.index[cweId]
        except KeyError as e:
            cu.tout(f"[Error]: Can't find CWE with Id {cweId}", verbose)
            return None
        return cu.read(path)

    def getLocalVersion(self):
        if not cu.exists(self.jsonPath):
            return None
        content = cu.read(self.jsonPath)
        try:
            version = content["Weakness_Catalog"]["@Version"]
            if cu.isNumber(version):
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
                    if cu.isNumber(version):
                        return float(version)
        return None

    def isInstalled(self):
        if not cu.exists(self.jsonPath, self.xmlPath, self.indexPath,
                         self.catsPath, self.refsPath, self.viewsPath):
            return False
        return cu.exists([p for p in cu.read(self.indexPath).values()])

    def loadCategories(self):
        return cu.read(self.catsPath)

    def loadIndex(self):
        self.index = cu.read(self.indexPath)
        return self.index

    def loadJson(self):
        return cu.read(self.jsonPath)

    def loadReferences(self):
        return cu.read(self.refsPath)

    def loadViews(self):
        return cu.read(self.viewsPath)

    def process(self):
        if self.data:
            self.load()

    def showCwe(self, cweId):
        cwe = self.getCwe(cweId)
        if not cwe:
            cu.tout(f"Can't find {cweId}")
        cu.out(cwe)

    def update(self):
        def clean(c):
            sC = json.dumps(c)
            for t in re.findall(r'"@\w+":', sC):
                sC = re.sub(t, t.replace("@", ""), sC)
            return json.loads(sC)
        self.__download()
        index = {}
        content = cu.read(self.jsonPath)
        for cwe in content["Weakness_Catalog"]["Weaknesses"]["Weakness"]:
            cwe = clean(cwe)
            path = cu.toLinuxPath(f"{self.dataDir}{os.sep}{cwe['ID']}.json")
            cu.write(path, cwe, sortKeys=True, verbose=False)
            index[cwe["ID"]] = path
        cu.write(self.indexPath, index, sortKeys=True)
        cu.write(self.catsPath, clean(content["Weakness_Catalog"]["Categories"]["Category"]))
        cu.write(self.refsPath, clean(content["Weakness_Catalog"]["External_References"]["External_Reference"]))
        cu.write(self.viewsPath, clean(content["Weakness_Catalog"]["Views"]["View"]))

if __name__ == "__main__":
    c = Cwe()
    #c.delete()
    if c.checkForUpdates():
        print("Retrieving latest online CWE content")
        c.update()
    cwe = c.getCwe(1312)
    cu.out(cwe)
    sys.exit()