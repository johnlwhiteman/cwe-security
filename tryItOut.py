import pandas as pd
import sys
import xlsxwriter
from pprint import pprint as p
import cwesecurity

SANS_TOP_25_CWES = [
    "CWE-20",
    "CWE-22",
    "CWE-77",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-119",
    "CWE-125",
    "CWE-190",
    "CWE-200",
    "CWE-276",
    "CWE-287",
    "CWE-306",
    "CWE-352",
    "CWE-416",
    "CWE-434",
    "CWE-476",
    "CWE-502",
    "CWE-522",
    "CWE-611",
    "CWE-732",
    "CWE-787",
    "CWE-798",
    "CWE-862",
    "CWE-918"
]

STATUSES = ["Deprecated", "Draft", "Incomplete", "Obsolete", "Stable"]
REPORT_PATH = "report.xlsx"

def buildCatSheet(wb, cwe):
    ws = wb.add_worksheet("All Categories")
    ws.set_column(0, 0, 9)
    ws.set_column(1, 1, 85)
    ws.set_column(2, 2, 13)
    ws.set_column(3, 3, 100)
    ws.set_column(4, 4, 45)
    fmtBold = wb.add_format({"bold": True})
    row = 0
    keys = ["Cat ID", "Cat Name", "Status", "CWE IDs", "Url"]
    for col, val in enumerate(keys):
        ws.write(row, col, val, fmtBold)
    for _ in cwe.getCats():
        meta = cwe.db[_["ID"]]
        data = _
        if meta["status"] in ["Deprecated", "Obsolete"]:
            continue
        row += 1
        ws.write(row, 0, data["ID"])
        ws.write(row, 1, data["Name"])
        ws.write(row, 2, meta["status"])
        ws.write(row, 3, ",".join(meta["hasMem"]["cwe"]))
        ws.write(row, 4, meta["url"])
    ws.ignore_errors({"number_stored_as_text": f"A1:E{row + 1}"})
    ws.autofilter(f"A1:E{row + 1}")

def buildCweSheet(wb, cwe):
    ws = wb.add_worksheet("All CWEs")
    ws.set_column(0, 0, 9)
    ws.set_column(1, 1, 85)
    ws.set_column(2, 2, 13)
    ws.set_column(3, 3, 79)
    ws.set_column(4, 4, 45)
    fmtBold = wb.add_format({"bold": True})
    row = 0
    keys = ["CWE ID", "CWE Name", "Status", "Cat IDs", "Url"]
    for col, val in enumerate(keys):
        ws.write(row, col, val, fmtBold)
    for _ in cwe.getCwes():
        meta = cwe.db[_["ID"]]
        data = _
        if meta["status"] in ["Deprecated", "Obsolete"]:
            continue
        row += 1
        ws.write(row, 0, data["ID"])
        ws.write(row, 1, data["Name"])
        ws.write(row, 2, meta["status"])
        ws.write(row, 3, ",".join(meta["memOf"]["cat"]))
        ws.write(row, 4, meta["url"])
    ws.ignore_errors({"number_stored_as_text": f"A1:E{row + 1}"})
    ws.autofilter(f"A1:E{row + 1}")

def buildSansTop25Sheet(wb, cwe):
    ws = wb.add_worksheet("SANS Top 25 CWEs")
    ws.set_column(0, 0, 9)
    ws.set_column(1, 1, 85)
    ws.set_column(2, 2, 13)
    ws.set_column(3, 3, 80)
    ws.set_column(4, 4, 45)
    fmtBold = wb.add_format({"bold": True})
    row = 0
    keys = ["CWE Id", "CWE Name", "Status", "Category IDs", "Url"]
    for col, val in enumerate(keys):
        ws.write(row, col, val, fmtBold)
    for _ in cwe.gets(SANS_TOP_25_CWES):
        meta = _["meta"]
        data = _["data"]
        if meta["status"] in ["Deprecated", "Obsolete"]:
            continue
        row += 1
        ws.write(row, 0, data["ID"])
        ws.write(row, 1, data["Name"])
        ws.write(row, 2, meta["status"])
        ws.write(row, 3, ",".join(meta["memOf"]["cat"]))
        ws.write(row, 4, meta["url"])
    ws.ignore_errors({"number_stored_as_text": f"A1:E{row + 1}"})
    ws.autofilter(f"A1:E{row + 1}")

def main():
    cwe = cwesecurity.Cwe()
    if cwe.hasUpdate() or not cwe.isInstalled():
        print("- Updating local CWE database")
        cwe.update()
    else:
        cwe.loadDb()
    print(f"- Creating report: {REPORT_PATH}")
    wb = xlsxwriter.Workbook(REPORT_PATH)
    print(f"- Building SANS Top 25 worksheet")
    buildSansTop25Sheet(wb, cwe)
    print(f"- Building all categories worksheet")
    buildCatSheet(wb, cwe)
    print(f"- Building all CWEs worksheet")
    buildCweSheet(wb, cwe)
    wb.close()
    print("- Script completed")
    return 0

if __name__ == "__main__":
    sys.exit(main())