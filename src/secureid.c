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

#include "assert.h"
#include "stdio.h"

#include "sys/mman.h"

#include "secureid.h"

Authority NullAccount     ={0,0,0,0,0,0};
Authority World           ={0,0,0,0,0,1};
Authority Local           ={0,0,0,0,0,2};
Authority Creator         ={0,0,0,0,0,3};
Authority NonUnique       ={0,0,0,0,0,4};
Authority NT              ={0,0,0,0,0,5};
Authority ResourceManager ={0,0,0,0,0,6};
Authority MandatoryLevel  ={0,0,0,0,1,6};

__attribute__((visibility("hidden"))) uint32_t string2uint32_t(const char* str,int size){
    uint32_t res = 0;
    for (int i = 0; i < size; ++i)
        res = res * 10 + str[i] - '0';
    return res;
};

#if defined(__LP64__) && !defined(__x86_64__)
   __attribute__((visibility("hidden"))) static uintptr_t next_mem_pos_;
#endif

__attribute__((visibility("hidden"))) uint32_t map32(uint32_t size){
#ifdef X86_64
    return mmap(0,size,PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT, -1, 0);
#endif

#if defined(__LP64__) && !defined(__x86_64__)
  // MAP_32BIT only available on x86_64.
  void* actual = MAP_FAILED;
  std::string strerr;
  if (low_4gb && expected == nullptr) {
    flags |= MAP_FIXED;

    for (uintptr_t ptr = next_mem_pos; ptr < 4 * GB; ptr += kPageSize) {
      uintptr_t tail_ptr;

      // Check pages are free.
      bool safe = true;
      for (tail_ptr = ptr; tail_ptr < ptr + page_aligned_byte_count; tail_ptr += kPageSize) {
        if (msync(reinterpret_cast<void*>(tail_ptr), kPageSize, 0) == 0) {
          safe = false;
          break;
        } else {
          DCHECK_EQ(errno, ENOMEM);
        }
      }

      next_mem_pos_ = tail_ptr;  // update early, as we break out when we found and mapped a region

      if (safe == true) {
        actual = mmap(reinterpret_cast<void*>(ptr), page_aligned_byte_count, prot, flags, fd.get(),
                      0);
        if (actual != MAP_FAILED) {
          break;
        }
      } else {
        // Skip over last page.
        ptr = tail_ptr;
      }
    }

    if (actual == MAP_FAILED) {
      strerr = "Could not find contiguous low-memory space.";
    }
  } else {
        actual = mmap(expected, page_aligned_byte_count, prot, flags, fd.get(), 0);
        strerr = strerror(errno);
  }
  return actual;
#endif
};

__attribute__((visibility("hidden"))) uint32_t munmap32(void *ptr,uint32_t size){
    return munmap(ptr,size);
};

__attribute__((visibility("hidden"))) uint32_t memcpy32(void *dest,void *src,uint32_t size){
    uint32_t i;
    for(i=0; i<size; ++i){
        ((char*)dest)[i]=((char*)src)[i];
    }
    return dest;
}

__attribute__((visibility("hidden"))) void reverse(char str[], int length){
    int start = 0;
    int end = length - 1;
    while (start < end) {
        char temp = str[start];
        str[start] = str[end];
        str[end] = temp;
        end--;
        start++;
    }
}

__attribute__((visibility("hidden"))) int uint32_t2string(uint32_t num,char* str, int base){
    int i = 0;
    int isNegative = 0;
    if (num == 0) {
        str[i++] = '0';
        str[i] = '\0';
        return i;
    }
    if (num < 0 && base == 10) {
        isNegative = 1;
        num = -num;
    }
    while (num != 0) {
        int rem = num % base;
        str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        num = num / base;
    }
    if (isNegative)
        str[i++] = '-';

    str[i] = '\0';
    reverse(str, i);

    return i;
}

void initSID(struct SID **sid){
    *sid=map32(sizeof(struct SID));
    (*sid)->Revesion=1;
    (*sid)->SubAuthorityCount=1;
    setAuthority(*sid,NullAccount);
    setSubAuthority(*sid,0);
};

void destroySID(struct SID *sid){
    if(sid->SubAuthorityCount!=0)
        munmap32(sid->SubAuthority[1],(sizeof(uint32_t)*sid->SubAuthorityCount));
    munmap32(sid,sizeof(struct SID));
};

int SIDcpy(struct SID *dest,struct SID *src){
    memcpy32(dest,src,sizeof(struct SID));

    int written=0;

    dest->SubAuthority[1]=map32(src->SubAuthorityCount*sizeof(uint32_t));

    for(int i=0; i<src->SubAuthorityCount; ++i){
        dest->SubAuthority[i]=src->SubAuthority[i];
    }

    return written+sizeof(struct SID);
};

void setAuthority(struct SID *sid,Authority authority){
    int i;

    for(i=0; i<6; ++i){
        sid->IdentifierAuthority.Value[i]=authority[i];
    }
}

void setSubAuthority(struct SID *sid,uint32_t uid){
    sid->SubAuthority[0]=uid;
    sid->SubAuthorityCount=2;
}

void setDomainIndentfier(struct SID *sid,uint32_t* did,uint8_t count){
    if(sid->SubAuthorityCount!=0){
        munmap32(sid->SubAuthority[1],(sizeof(uint32_t)*sid->SubAuthorityCount));
    }

    if(sid->SubAuthority[0]==21){
        sid->SubAuthority[1]=map32(sizeof(uint32_t)*count);

        for(uint32_t i=0; i<count; ++i){
            sid->SubAuthority[i+1]=did[i];
        }

        sid->SubAuthorityCount=(count+2);
    }else{
        assert("only SubAuthority with value 21 supports domain indentfier !");
    }
}

int parseSID(struct SID *sid,const char *input,int size){
    int i=0;
    if(input[i++]!='S' || input[i++]!='-')
        return -1;

    sid->Revesion=(uint8_t)input[i++]-'0';

    int ii=++i,old=i;

    while(input[++ii]!='-');
    i=ii;

    int e=6;
    while(old<ii){
        sid->IdentifierAuthority.Value[--e]=input[--ii]-'0';
    }

    int c =i;

    while( c< size){
        if(input[c++]=='-')
            ++sid->SubAuthorityCount;
    }

    if(sid->SubAuthorityCount==0)
        return 0;

    sid->SubAuthority[1]=map32(sid->SubAuthorityCount*sizeof(uint32_t));

    int iis,ia;


    for (iis= 0; iis < sid->SubAuthorityCount; ++iis){
        sid->SubAuthority[iis]=0;
    }

    for (iis= 0; iis < sid->SubAuthorityCount; ++iis) {
        ++i;
        for(ia=0; i+ia<size && input[i+ia]!='-'; ++ia);
        sid->SubAuthority[iis]=string2uint32_t(input+i,ia);
        i+=ia;
    }
    return sid->SubAuthorityCount;
};

int printSID(struct SID *sid,char *output,int size){
    int written = 0;
    output[written++]='S';
    output[written++]='-';
    output[written++]=sid->Revesion+'0';
    output[written++]='-';

    int i,z=0,ii;

    for(ii=0; ii<6; ++ii){
        if(sid->IdentifierAuthority.Value[ii]!=0){
            output[written++]=sid->IdentifierAuthority.Value[ii]+'0';
            z=1;
        }
    }

    if(z==0)
        output[written++]='0';

    for (int ii = 0; ii <  sid->SubAuthorityCount; ++ii) {
        if(written>size)
            break;
        output[written++]='-';
        char tmp[255];
        uint32_t wt=uint32_t2string(sid->SubAuthority[ii],tmp,10);
        memcpy32(output+written,&tmp,wt);
        written += wt;
    }
    output[written]='\0';
    return written;
};

void generateDomainIdentfier(uint32_t *did, int count){

    FILE *devrandom;

    devrandom = fopen("/dev/random","r");

    for(int i=0; i<count; ++i){
        while(did[i]< 1000000000){
            did[i] = 1000000000 << fgetc(devrandom);
        }
    }

    fclose(devrandom);
}

void setRid(struct SID* sid, uint32_t rid){
    sid->SubAuthority[sid->SubAuthorityCount-1]=rid;
}

uint32_t getRid(struct SID* sid){
    return sid->SubAuthority[sid->SubAuthorityCount-1];
}

