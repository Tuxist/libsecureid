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

#include "stdint.h"

#pragma once

typedef const uint8_t Authority[6];

extern Authority NullAccount;
extern Authority World;
extern Authority Local;
extern Authority Creator;
extern Authority NonUnique;
extern Authority NT;
extern Authority ResourceManager;
extern Authority MandatoryLevel;

struct SID_IDENTIFIER_AUTHORITY {
    /**
    * Stores authority;
    */
    uint8_t Value[6];
};

struct SID {
    /**
    * The revesion mostly 1
    */
    uint8_t                         Revesion;
    /**
    * The count of subauthority
    */
    uint8_t                         SubAuthorityCount;
    /**
    * The authority type
    */
    struct SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    /**
    * The SubAuthority identifier value
    * Waring the real size is subauthoritycount
    */
    uint32_t                        SubAuthority[1];
};

#ifdef __cplusplus
extern "C" {
#endif
    /**
    * With this function will be the memory allocated for SID struct and set as NULL Authority
    * Don't do that by malloc,calloc or new its a 32bit pointer !!
    * @param sid that will be initalized
    **/
    void initSID(struct SID **sid);

    /**
    * With this function will be the memory dellocated for SID struct
    * Don't do that with free or delete its a 32bit pointer !!
    * @param sid that will be dellocated
    **/
    void destroySID(struct SID *sid);

    /**
    * This function will copy from sid to another sid struct
    * importend you initSID for dest before you copy !!
    * @param dest copy destination
    * @param src copy source
    **/
    int  SIDcpy(struct SID *dest,struct SID *src);

    /**
    * This function will set your Authority for example NT look for Authority type.
    * @param sid SID struct set will be the value set
    * @param authority type of authority that genarated the Identifier
    * @param uid the indentifier array that will you set
    * @param count the indentifier array size
    **/
    void setAuthority(struct SID *sid,Authority authority,uint32_t* uid,uint8_t count);

    /**
    * This function will be parse a sid cstring to struct sid
    * @param sid SID struct set will be the destination for parsing
    * @param input a cstring that included the secure indentfier
    * @param size the length of the input
    **/
    int parseSID(struct SID *sid,const char *input,int size);

    /**
    * This function will be parse a sid cstring to struct sid
    * @param sid SID struct set will be the source for printing
    * @param output a cstring that included the secure indentfier
    * @param size the maximum size that output can be carrier
    **/
    int printSID(struct SID *sid,char *output,int size);

#ifdef __cplusplus
};
#endif
