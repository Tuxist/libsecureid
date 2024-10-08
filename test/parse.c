/*******************************************************************************
 * Copyright (c) 2023, Jan Koester jan.koester@gmx.net
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 * Neither the name of the <organization> nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#include "stdio.h"
#include "string.h"

#include "secureid.h"

int main(int argc, char *argv[]){
    int read=0;

    if(argc!=2){
        printf("no file path argument append !");
        return -1;
    }

    FILE *list;
    list=fopen(argv[1],"r");

    if(list==0){
        printf("cannot open file !");
        return -1;
    }

    int failed=0;

    while(read==0){
        char line[512],out[512];
        int spos=0,written=0;;
        for(spos=fgetc(list); spos!='\n'; spos=fgetc(list)){
            if(written > 511){
                printf("line too long aborting");
                failed=-1;
            }
            if(feof(list)){
                read=-1;
                break;
            }
            line[written++]=spos;
        }

        if(written==0)
            return 0;

        line[written]='\0';

        struct SID *sid;
        initSID(&sid);

        int ret=parseSID(sid,line,written);

        if(ret>=0){
            printSID(sid,out,512);

        }
        destroySID(sid);
        if(ret>=0 && strcmp(line,out)==0){
            printf("Success: %s \n",out);
            continue;
        }
        printf("Failed: %s != %s \n",line,out);
        failed = -1;
    }
    return failed;
}
