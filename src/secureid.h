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
    uint8_t Value[6];
};

struct SID {
    uint8_t                         Revesion;
    uint8_t                         SubAuthorityCount;
    struct SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    uint32_t                        SubAuthority[1];
};

#ifdef __cplusplus
extern "C" {
#endif
    void initSID(struct SID **sid);
    void destroySID(struct SID *sid);

    int  SIDcpy(struct SID *dest,struct SID *src);

    void setAuthority(struct SID *sid,Authority authority,uint32_t* uid,uint8_t count);

    int parseSID(struct SID *sid,const char *input,int size);

    int printSID(struct SID *sid,char *input,int size);

#ifdef __cplusplus
};
#endif
