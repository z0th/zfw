## zfw: z0th's Firewall ##

An IPTables firewall written in bash, for linux systems.

**FEATURES:**
Sources config file for various settings.
  * configurable interfaces and IP addresses.
  * configurable public and private ports.
  * configurable trusted networks
  * configurable default policy

Some "extra" features that you can enable:
  * basic brute force mitigation
  * blacklist files
  * torrent mitigation protection
  * FTP connection tracking (so ftp will work properly)

**NOTE:** This firewall is written for _my_ general use, so some defaults are set up for my preferences in the .conf file. Feel free to use the code, report bugs, and submit suggestions!

**TODO**
  * add conditional for loading of ipt modules to deal with kernel built-in vs. installed ipt source.
  * clear out the .conf file for general use.
  * add variable to state first\_port:last\_port for torrent RST protection, add some comments about rtorrentrc file.