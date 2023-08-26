# libsecureid

A small C library to Work with Microsofts Secure Identfier.

##Dependcies

- Linux
- GCC/Clang
- C99
- Cmake

###Optional
- Doxygen (for documentation)

##Build

1. cd libsecureid
2. mkdir build
3. cd build
4. cmake ../
5. make || ninja
6.  make install || ninja install

##Usage Example

```C

#include "secureid.h"

#define MYSID "S-1-5-21-3686201514-2077471124-1704617262-1104"

int main(int argc, char *argv[]){
    struct SID *sid;
    initSID(&sid);
    parseSID(sid,MYSID,strlen(MYSID));

    char test[512];

    printSID(sid,test,512);

    printf("%s\n",test);

    printf("%s\n",MYSID);

    destroySID(sid);
}

```
