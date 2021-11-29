import sys
from pprint import pprint as p
import cwesecurity

def main():
    cwe = cwesecurity.Cwe()
    print("Deleting existing local cwe database if exist")
    cwe.deleteDb()
    if cwe.hasUpdate() or not cwe.isInstalled():
        print("Updating CWEs")
        cwe.update()
    else:
        cwe.loadDb()
    print("Getting a couple of views")
    for _view in cwe.getView(699, 1000):
        p(_view)
    print("Getting some categories")
    for _cat in cwe.getCat([16, 17]):
        p(_cat)
    print("Getting a cwe")
    for _cwe in cwe.getCwe("92"):
        p(_cwe)
    return 0

if __name__ == "__main__":
    sys.exit(main())