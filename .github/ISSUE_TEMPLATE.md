This is an example of bug report. Try to adapt it to your case. When
putting code snippets (logs, commands), put them between triple backquotes:

````
```
# lldpcli -vv
[output of lldpcli -vv]
```
````

# Bug description

## Steps to reproduce the problem

 1. Compile `lldpd` with `./configure --localstatedir=/var --with-snmp && make`.

 2. Install with `sudo make install`.

 3. Run `lldpd`.
 
 4. Wait for a LLDPDU from the remote switch (vendor Pisco, release 19.1(478)KHT47.3).
 
## Expected outcome

`lldpd` should accept the LLDPDU and it should be available in the
output of `lldpcli show neighbors details`.

## Current outcome

After executing the above steps, `lldpd` crashed. Here is the end of
the output of `lldpd -ddddd` before the crash:

```
2016-11-10T11:06:40 [ DBG/lldp] receive LLDP PDU on eno1
2016-11-10T11:06:40 [ DBG/alloc] allocate a new management address (family: 1)
2016-11-10T11:06:40 [ DBG/decode] search for the same MSAP
2016-11-10T11:06:40 [ DBG/decode] MSAP is unknown, search for the chassis
2016-11-10T11:06:40 [ DBG/decode] unknown chassis, add it to the list
```

# Additional information

 - Output of `lldpd -vv`:
 
```
lldpd x.y.z
  Built on ...
  
Additional LLDP features: ...
Additional protocols: ...
```

 - Output of `ps -fp $(pgrep -d, -x lldpd)`:
 
```
UID        PID  PPID  C STIME TTY          TIME CMD
root      2265     1  0 nov.05 ?       00:00:00 lldpd: monitor.
_lldpd    2285  2265  0 nov.05 ?       00:00:00 lldpd: connected to gs108t.
```

 - Output of `uname -sro`:
 
```
Linux 4.8.0-1-amd64 GNU/Linux
```

 - Output of `tcpdump -pni eth0 -vv -X ether host 01:80:c2:00:00:0e`:
 
```
16:47:37.595387 LLDP, length 219
        Chassis ID TLV (1), length 7
          Subtype MAC address (4): 54:ee:75:0f:31:7e
          0x0000:  0454 ee75 0f31 7e
[...]
        0x00b0:  1600 080f 656e 7830 3035 3062 3636 6563  ....enx0050b66ec
        0x00c0:  6236 65fe 0900 120f 0301 0000 0000 fe09  b6e.............
        0x00d0:  0012 0f01 03ec c100 1e00 00              ...........
```
