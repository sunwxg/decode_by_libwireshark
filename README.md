# Decode by libwireshark
Use libwireshark to decode pcap file and print out as XML format or Text format like tshark.

#Dependencies
* libwireshark library (version 2.4.4)

* libglib2.0

# Install
- openSUSE
```
zypper in wireshark
zypper in glib2 glib2-devel
zypper in libwiretap7 libwsutil8 libwireshark9

make source
make

./myshark -f file.pcap -t text
```
