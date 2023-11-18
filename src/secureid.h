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

/*! \file secureid.h
    \brief A Documented file.

    Details.
*/


/**
* Secure Identfier authority
*/

struct SID_IDENTIFIER_AUTHORITY {
    /**
    * Stores authority;
    */
    uint8_t Value[6];
};

/**
* Secure Identfier Data
*/
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
    /*!
      \fn initSID(struct SID **sid)
      \brief With this function will be the memory allocated for SID struct and set as NULL Authority
      \brief Don't do that by malloc,calloc or new its a 32bit pointer !!
      \param sid that will be initalized
    */
    void initSID(struct SID **sid);

    /*!
      \fn void destroySID(struct SID *sid)
      \brief With this function will be the memory dellocated for SID struct
      \brief Don't do that with free or delete its a 32bit pointer !!
      \param sid that will be dellocated
    */
    void destroySID(struct SID *sid);

    /*!
      \fn SIDcpy(struct SID *dest,struct SID *src)
      \brief This function will copy from sid to another sid struct
      \brief importend you initSID for dest before you copy !!
      \param dest copy destination
      \param src copy source
    */
    int  SIDcpy(struct SID *dest,struct SID *src);

    /*!
      \fn setAuthority(struct SID *sid,Authority authority)
      \brief This function will set your Authority for example NT look for Authority type.
      \param sid SID struct set will be the value set
      \param authority type of authority that genarated the Identifier
    */
    void setAuthority(struct SID *sid,Authority authority);

     /*!
      \fn setSubAuthority(struct SID *sid,uint32_t* uid,uint8_t count)
      \brief This function will set your SubAuthority.
      \param sid SID struct set will be the value set
      \param uid the indentifier array that will you set
      \param count the indentifier array size
    */
    void setSubAuthority(struct SID *sid,uint32_t* uid,uint8_t count);

    /*!
      \fn int parseSID(struct SID *sid,const char *input,int size)
      \brief This function will be parse a sid cstring to struct sid
      \param sid SID struct set will be the destination for parsing
      \param input a cstring that included the secure indentfier
      \param size the length of the input
    */
    int parseSID(struct SID *sid,const char *input,int size);

    /*!
      \fn int printSID(struct SID *sid,char *output,int size)
      \brief This function will be parse a sid cstring to struct sid
      \param sid SID struct set will be the source for printing
      \param output a cstring they will be printed the secure indentfier
      \param size the maximum size that output can be carrier
    */
    int printSID(struct SID *sid,char *output,int size);

     /*!
      \fn void generateDomainIdentfier(uint32_t *output,int count)
      \brief This function will genarated domain indentfier numbers
      \param output a uint32_t array that included the unique number
      \param count the max size of output
    */
    void generateDomainIdentfier(uint32_t *output,int count);


    /*!
      \fn void setRid(struct SID *sid,uint32_t rid)
      \brief This function will set the real id of a user without domain indentfier
      \param sid SID struct set will be set the real id
      \param rid the real id number the will be set
    */
    void setRid(struct SID *sid,uint32_t rid);

    /*!
      \fn int getRid(struct SID *sid)
      \brief This function will get the real id of a user without domain indentfier
      \param sid SID struct set will be set the real id
    */
    uint32_t getRid(struct SID *sid);


#ifdef __cplusplus
};
#endif
