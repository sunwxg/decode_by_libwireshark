# Decode by libwireshark
Use libwireshark to decode pcap file and print out as XML format or Text format like tshark.

#Dependencies
* libwireshark library (version 1.12.8)

* libglib2.0

# Install
- ubuntu
```
apt-get install libglib2.0-dev

git clone https://github.com/sunwxg/decode_by_libwireshark.git

cd decode_by_libwireshark
cat libs/libwireshark.{00,01,02,03} > libs/libwireshark.so
chmod 775 libs/libwireshark.so

make

./myshark -f file.pcap -t text
```

# Debug
Debug program to see how wireshark dissect packet.
- Download wireshark source code(version 1.12.8) from www.wireshark.org
- Uncompress source code and compile. Following [wireshark guide](https://www.wireshark.org/docs/wsug_html/#ChBuildInstallUnixBuild)
- Export SRC_WIRESHARK as wireshark source code path
```
export SRC_WIRESHARK=<wireshark source code path>
```
- Make file
```
make debug
```
- Using GDB
```
libtool --mode=execute gdb ./myshark
```

