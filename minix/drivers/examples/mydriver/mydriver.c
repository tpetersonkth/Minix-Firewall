#include <stdio.h>
#include <stdlib.h>
#include <minix/syslib.h>
#include "mydriver.h"
 
int main(int argc, char **argv)
{
    sef_startup();
 
    printf(HELLO_MESSAGE);
    return EXIT_SUCCESS;
}
