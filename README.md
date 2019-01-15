# DD2497 Group 7
## Members
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
These tests require recompilation between each test. The test code can be found in the file /minix/servers/fwdec/fwdec.c in the function loadConfiguration(). First the rules are defined and then we set the linked list rules to the rules that will be active. For every test comment and uncomment the rules that will be used for that test. 

## Test 1 - DNS
The first set of rules allows packets to and from the DNS server with the port 53. This test can be demonstrated with the `dig` command:
```bash
dig google.com
```

## Test 2 - Ping a Webpage
This test will add two more rules to the list. Allow packets with source IP or destination IP set to 130.237.28.40 (kth.se). We can now test the rules by using the ping command and exploring the log file. 
```bash
ping google.com
cat /var/log/fwdec
```
In the output we will see something like this:
```bash
[Packet Dropped|Not in whitelist]Proto:1 srcIp:10.0.2.15 srcPort:128 dstIp:216.58.207.238 dstPort:2938
```
We can now do the same thing but with kth.se
```bash
ping kth.se
cat /var/log/fwdec
```
We will not see a new entry in the log because kth.se is in the whitelist

## Test 3 - UDP and TCP
To test UDP and TCP connections we will use a tool called `netcat` on our host machine to generate UDP and TCP packets to the MINIX system. To do this we must forward some ports from the host machine to MINIX. We use the following flags for qemu to forward 2 TCP ports and 1 UDP port. Port 5555 will be forwarded to port 23 on the MINIX system for TCP packets:

```bash
qemu -device e1000,netdev=net0 -netdev user,id=net0,
hostfwd=tcp::5555-:23,
hostfwd=tcp::5556-:24,
hostfwd=udp::5557-:25
```

We have 2 rules to allow TCP traffic on port 23 and to allow UDP traffic on port 25. If we now run the command
```bash
nc -u localhost 5557
Test message
```

Then this will generate and send a UDP packet to MINIX on port 25 because we forwarded port 5557 on our host machine to port 25 in MINIX. We will receive the packet normally and nothing will be logged.

We will get the same result when sending a TCP message on port 23

```bash
nc localhost 5555
Test message
```

However running the same command for port 24, we will drop the packet in minix and log it to the log file

```bash
nc localhost 5556
Test message
```

The output in the log file will be:

```bash
[Packet Dropped|Not in whitelist]Proto:6 srcIp:10.0.2.2 srcPort:2124 dstIp:10.0.2.15 dstPort:24
```
