This is an example of bug report. Try to adapt it to your case.

# Bug description

## Steps to reproduce the problem

 1. Compile `lldpd` with `./configure --localstatedir=/var --with-snmp && make`.

 2. Install with `sudo make install`.

 3. Run `lldpd`.
 
 4. Wait for a LLDPDU from the remote switch (vendor Pisco, release 19.1(478)KHT47.3).
 
## Expected outcome

`lldpd` should accept the LLDPDU and it should be available in the
output of `lldpcli show neighbors`.

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
