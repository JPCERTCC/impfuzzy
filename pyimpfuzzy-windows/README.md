# pyimpfuzzy-windows
  Python module comparing the impfuzzy for Windows  
  pyimpfuzzy-windows is python module which calculate and compare the impfuzzy(import fuzzy hashing)  
  This module is pyimpfuzzy for Windows version. For Linux and Mac OS users, please use [pyimpfuzzy](https://github.com/JPCERTCC/impfuzzy/tree/master/pyimpfuzzy).  

  More details are described in the following documents:   
  https://www.jpcert.or.jp/magazine/acreport-impfuzzy.html (Japanese)   
  http://blog.jpcert.or.jp/2016/05/classifying-mal-a988.html (English)

## Requirements
  pyimpfuzzy-windows requires the following modules:

  * pefile 1.2.10-139 or later

## Installation

```bash
$ pip install pyimpfuzzy-windows
```
or
```bash
$ python setup.py install
```

## Usage
  * get_impfuzzy - return the impfuzzy hash for a given file
  * get_impfuzzy_data - return the impfuzzy hash for a buffer
  * hash_compare - return the match between 2 hashes

### Example Usage

```python
import pyimpfuzzy
import sys

hash1 = pyimpfuzzy.get_impfuzzy(sys.argv[1])
hash2 = pyimpfuzzy.get_impfuzzy(sys.argv[2])
print("ImpFuzzy1: %s" % hash1)
print("ImpFuzzy2: %s" % hash2)
print("Compare: %i" % pyimpfuzzy.hash_compare(hash1, hash2))
```

## Notes
  This module includes [fuzzy.dll version 2.14.1](https://github.com/ssdeep-project/ssdeep/releases/tag/release-2.14.1).
