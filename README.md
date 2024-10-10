# server-scripts

## block_country.py

uses ipset and ip(6)tables to block incoming traffic from country ip ranges

example:
```sh
# block countries
./block_country.py --ban RU CN
# unblock countries
./block_country.py --unban RU CN
```
