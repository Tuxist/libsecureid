# libsecureid

A small C library to Work with Microsofts Secure Identfier.
(___)
##Dependcies
1. Linux
2. GCC/Clang
3. C99
4. Cmake

(___)
##Build
cd libsecureid
mkdir build
cd build
cmake ../
make | ninja
make install | ninja install

(___)
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
