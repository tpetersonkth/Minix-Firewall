# Minix Firewall
This repository contains an extension to the Minix operating system which includes a firewall in the TCP/IP stack. For more information, see the [Report.pdf](https://github.com/tpetersonkth/Minix-Firewall/blob/master/Report.pdf) file in the root directory.
## Contributors
* Davis Freimanis (davisf@kth.se)
* Thomas Peterson (thpeter@kth.se)
* Emelie Eriksson (emee@kth.se)
* Marcus Lignercrona (mlig@kth.se)

# Setup
Compile the code using releasetools and then run Minix using the command that releasetools generates for you. Add the flags for network access inside Minix.
```bash
./releasetools/x86_hdimage.sh
qemu -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::xxxx-:yyyy
```

xxxx corresponding the the port on the local machine and yyyy corresponding to the port on vm. For example with xxxx = 5555 and yyyy = 22.

When you boot Minix, run the commands below to enable internet access.
```bash
netconf
service network restart
```

You should now have the IP address *10.0.2.15* when you run `ifconfig`.

Dropped packets are logged to a logfile located in `/var/log/fwdec`. Debuging output is also available to stdout by setting the `FWDEC_DEBUG` flag to 1 in `fwdec/fwdec.h`. After running some commands that generate traffic run:

```bash
cat /var/log/fwdec
```

# Testing
Testing instructions can be found in the file `test.md`.
