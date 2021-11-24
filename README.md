# CWE-Security

CWE™ is a community-developed list of software and hardware weakness types. It serves as a common language, a measuring stick for security tools, and as a baseline for weakness identification, mitigation, and prevention efforts.

This project provides an automated interface to access the latest CWEs. Teams are encouraged to map their vulnerabilities to CWEs to promote consistency.

# Use Cases

### Search for CWEs
```
from cwesecurity.cwe import Cwe

cwe = Cwe()

# Single input only
print(cwe.getCwe(123))

# Multiple inputs that support many types
for c in cwe.getCwes(112, "cwe-113", ["114", 115]):
    print(c)

# No input returns all records
for r in cwe.getCwes():
    print(r)
```

### Search for categories
```
from cwesecurity.cwe import Cwe

cwe = Cwe()

# Single input only
print(cwe.getCategory(123))

# Multiple inputs that support many types
for c in cwe.getCategories(112, "cwe-113", ["114", 115]):
    print(c)

# No input returns all records
for r in cwe.getCategories():
    print(r)
```

### Search for views
```
from cwesecurity.cwe import Cwe

cwe = Cwe()

# Single input only
print(cwe.getView(884))

# Multiple inputs that support many types
for r in cwe.getViews(604, "660", ["1154", 1350]):
    print(r)

# No input returns all records
for r in cwe.getViews():
    print(r)
```

### Search for references
```
from cwesecurity.cwe import Cwe

cwe = Cwe()

# Single input only
print(cwe.getReference("REF-14"))

# Multiple inputs that support many types
for r in cwe.getRefences("REF-23", "REF-24", ["REF-42, "REF-43"]):
    print(r)

# No input returns all records
for r in cwe.getReferences():
    print(r)
```

# References

* [CWE Homepage](https://cwe.mitre.org/)