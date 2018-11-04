# DD2497 Group 7
## Members
* Davis Freimanis (davisf@kth.se)
* Thomas Peterson (thpeter@kth.se)
* Emelie Eriksson (emee@kth.se)
* Marcus Lignercrona (mlig@kth.se)
# Documentation
## Adding a driver
To add a driver, the following files need to be modified:
### minix/drivers/[DRIVERNAME]
Add driver source code in this directory and modify the makefiles accordingly
### distrib/sets/lists/minix-base/mi
Modify flist to include the new driver

### minix/include/minix/dmap.h
Add a major number for our device(Any non-used number should do)
### minix/commands/MAKEDEV/MAKEDEV.sh
Map the device file /dev/[DRIVERNAME] to the major number
### etc/usr/rc
Add instructions to the bootloader to start the driver and map it to /dev/[DRIVERNAME]
