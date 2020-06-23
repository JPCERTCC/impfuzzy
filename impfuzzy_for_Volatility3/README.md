# impfuzzy for Volatility3
  Volatility3 plugin for comparing the impfuzzy, imphash and ssdeep.  
  This plugin can be used to scan malware in memory image.  
  Imphash see [FireEye Blog](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html)

  More details are described in the following documents:   
  * https://blogs.jpcert.or.jp/ja/2016/11/impfuzzy_volatility.html (Japanese)   
  * https://blogs.jpcert.or.jp/en/2016/12/a-new-tool-to-d-d6bc.html (English)

## Functions

  * pehash.ImpFuzzy - compare or print the impfuzzy
  * pehash.ImpHash - search or print the imphash
  * pehash.Ssdeep - compare or print the ssdeep

## Requirements
  This plugin requires the following modules:

  * pefile https://github.com/erocarrera/pefile
  * pyimpfuzzy https://github.com/JPCERTCC/impfuzzy/tree/master/pyimpfuzzy
  * python-ssdeep https://github.com/DinoTools/python-ssdeep

## How to Use

### Download Volatility3 and impfuzzy for Volatility3
  ```shell
  $ git clone https://github.com/volatilityfoundation/volatility3.git
  $ git clone https://github.com/JPCERTCC/impfuzzy.git
  ```

### Install requirements
  ```shell
  $ pip3 install pefile yara-python capstone pyimpfuzzy ssdeep
  ```

### Run
  ```shell
  $ cd volatility3
  $ python3 vol.py -f [memorydata] --plugin-dirs ../impfuzzy/impfuzzy_for_Volatility3 [ pehash.ImpHash | pehash.ImpFuzzy | pehash.Ssdeep ]
  ```

  Use -h to see help message.

### Example Usage
#### Printing The Impfuzzy Hash of Process and Dll Module
```
$ python3 vol.py -f [memorydata] --plugin-dirs ../impfuzzy/impfuzzy_for_Volatility3 pehash.ImpFuzzy --pid [PID]
```
#### Searching The Impfuzzy Hash from PE Files
```
$ python3 vol.py -f [memorydata] --plugin-dirs ../impfuzzy/impfuzzy_for_Volatility3 pehash.ImpFuzzy --exefile [PE file]
```
#### Searching The Impfuzzy Hash from Hash List
```
$ python3 vol.py -f [memorydata] --plugin-dirs ../impfuzzy/impfuzzy_for_Volatility3 pehash.ImpFuzzy --impfuzzylist [Hash List File]
```
#### Printing The Imphash
```
$ python3 vol.py -f [memorydata] --plugin-dirs ../impfuzzy/impfuzzy_for_Volatility3 pehash.ImpHash --pid [PID]
```
#### Searching The Imphash from Hash List
```
$ python3 vol.py -f [memorydata] --plugin-dirs ../impfuzzy/impfuzzy_for_Volatility3 pehash.ImpHash --imphashlist [Hash List]
```
#### Printing The ssdeep
```
$ python3 vol.py -f [memorydata] --plugin-dirs ../impfuzzy/impfuzzy_for_Volatility3 pehash.Ssdeep --pid [PID]
```
