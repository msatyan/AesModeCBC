/*
Copyright 2017 Sathyanesh Krishnan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


extern "C" {
#include "openssl/aes.h"
#include <stdio.h>
}

#include "AesModeCBC.h"

AesModeCBC::AesModeCBC(const unsigned char *key, AesKeySize ks, const unsigned char *iv, int enc)
{
    int i = 0;


    for (i = 0; i < IV_SIZE; ++i)
    {
        BuffIV[i] = *(iv + i);
    }
    
    if (enc)
    {
        // AESkey is a data structure holding a transformed version of the key, for efficiency.
        AES_set_encrypt_key((const unsigned char *)key, ks, &AESkey);
    }
    else
    {
        AES_set_decrypt_key((const unsigned char *)key, ks, &AESkey);
    }

}


void AesModeCBC::GetIvCtrMode(size_t c, unsigned char IvCtr[IV_SIZE])
{
    const unsigned char *iv = piv;
    size_t *data = (size_t *)IvCtr;
    size_t d = 0;
    size_t n = 0;

    const union
    {
        long one;
        char little;
    } is_endian = {1};

    if (is_endian.little || ((size_t)iv % sizeof(size_t)) != 0)
    {
        // Little Endian Platforms
        n = IV_SIZE;
        do
        {
            --n;
            c += iv[n];
            IvCtr[n] = (u8)c;

            c >>= 8;
        } while (n);
        return;
    }

    // Big Endian Platforms
    n = IV_SIZE / sizeof(size_t);
    do
    {
        --n;
        d = data[n] += c;

        c = ((d - c) ^ d) >> (sizeof(size_t) * 8 - 1);
    } while (n);

    return;
}

size_t AesModeCBC::Encrypt(const unsigned char *in, unsigned char *out, size_t len)
{
    // The output buffer should have minimum of the same size as input data (len)
    
    size_t LenOut = 0;
    const unsigned char *iv = piv; // Initial IV
    size_t n = 0;
    unsigned int i = 0;

    size_t PartialBlockBytes = len & (BLOCK_SIZE - 1);

    LenOut = len;
    while (len >= BLOCK_SIZE) // A full AES block
    {
        for (n = 0; n < BLOCK_SIZE; n += sizeof(size_t))
        {
            // In CBC mode, each input block is XORed with the previous 
            // ciphertext block; Then IT is sent it for encryption
            *(size_t *)(out + n) =  *(size_t *)(in + n) ^ *(size_t *)(iv + n);
        }

        // Encrypt this IvCtr block
        AES_encrypt(out, out, (const AES_KEY *)&AESkey);
        
        iv   = out; // This Cipher block  will be IV for next operation
        len -= BLOCK_SIZE;
        in  += BLOCK_SIZE;
        out += BLOCK_SIZE;
    }

    if (len)
    {
        unsigned char Buff1[BLOCK_SIZE];
        unsigned char Buff2[BLOCK_SIZE];
        unsigned char pad = (u8)(BLOCK_SIZE - len);
        unsigned char *out_saved = out;
        unsigned int c = 0;

        for (i = 0; i < BLOCK_SIZE; ++i)
        {
            if (i < len) 
            {
                // Fill the Partial block of data 
                Buff1[i] = *(in + i);
            }
            else
            {
                // pad the remaining part of the block;
                Buff1[i] = pad;
            }
        }

        in = Buff1;
        out = Buff2;

        for (n = 0; n < BLOCK_SIZE; n += sizeof(size_t))
        {
            // In CBC mode, each input block is XORed with the previous ciphertext block; 
            // Then it is send it for encryption
            *(size_t *)(out + n) = *(size_t *)(in + n) ^ *(size_t *)(iv + n);
        }

        // Encrypt this block
        AES_encrypt(out, out, (const AES_KEY *)&AESkey);
        
        if (padding)
        {
            LenOut += (BLOCK_SIZE - PartialBlockBytes);
            c = BLOCK_SIZE;
        }
        else
        {
            c = (unsigned int)len;
        }
            
        out = out_saved;
        for (i = 0; i < c; ++i)
        {
            *(out + i) = Buff2[i];
        }
    }


    for (i = 0; i < IV_SIZE; ++i)
    {
        BuffIV[i] = *(iv + i);
    }
    

    return(LenOut);
}

size_t AesModeCBC::Decrypt(const unsigned char *in, unsigned char *out, size_t len)
{
    size_t LenOut = len;
    size_t n=0;
    const unsigned char *iv = piv; // Initial IV
    unsigned char *FinalBlock = NULL;
    int i = 0;

    while (len >= BLOCK_SIZE)
    {
        size_t *out_t = (size_t *)out;
        size_t *iv_t = (size_t *)iv;

        AES_decrypt(in, out, (const AES_KEY *)&AESkey);

        for (n = 0; n < IV_SIZE / sizeof(size_t); n++)
        {
            out_t[n] ^= iv_t[n];
        }

        iv  = in;
        len -= BLOCK_SIZE;
        in  += BLOCK_SIZE;
        FinalBlock = out; 
        out += BLOCK_SIZE;
    }

    for (i = 0; i < IV_SIZE; ++i)
    {
        BuffIV[i] = *(iv + i);
    }

    LenOut -= len;

    if( padding && len == 0 && LenOut > 1)
    {
        // int n;
        unsigned int b = BLOCK_SIZE;
        n = FinalBlock[b - 1];

        for (i = 0; i < n; i++)
        {
            if (FinalBlock[--b] != n)
            {
                //EVPerr(EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_BAD_DECRYPT);
                return (0);
            }
            
        }
        LenOut -= n;
        n = BLOCK_SIZE - n;
        for (i = 0; i < n; i++)
            out[i] = FinalBlock[i];

        //*outl = n;
    }

    return(LenOut);
}

