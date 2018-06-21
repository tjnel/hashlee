# hashlee

## Purpose
The goal of hashlee is to extract indicators from text and search for references on osint

## Installing

Running hashlee is easy just install requirements and point to a indicator, file or directory

### Prerequisites
No prerequisites needed

## Usage

#### Options 
```
usage: hashlee.py [-h] [-v] [-d] [-s] p_input

This script will extract and cross reference indicators with OSINT sources

positional arguments:
  p_input        file or directory to run hashlee against

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  increase output verbosity
  -d, --debug    output logging
  -s, --save     save output to a file
```

#### Simple usage against single file
```
python hashlee.py google.com
```

#### Run against directory with debug data
```
python hashlee.py directory/ -d
```

#### Run against a file in verbose mode
```
python hashlee.py directory/ -v
```

## Usage Video

[https://youtu.be/](https://youtu.be/)

## Built With

* [Python3](https://github.com/python/cpython)

## Authors

* **TJ Nel** - *Initial work* - [TJNel](https://github.com/tjnel)

See also the list of [contributors](https://github.com/tjnel/hashlee/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Hat tip to [URL Void](http://www.urlvoid.com) for their reputation service
* Hat tip to [Zero Fusion](http://0spam.fusionzero.com) for their reputation service
