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
#include <stdlib.h>
#include <string.h>
}

#include "AesModeCBC.h"

void MyMemSet(unsigned char *p, unsigned int t);
void MyPrintBinData(const unsigned char *BinData, size_t len);


int main()
{
    unsigned char *OriginalData = (unsigned char *)"We will send this message for encryption and then try decrypt too!.";
    unsigned char key[] = "01234567890123456789012345678901";  // Key is of 256 bit 
    unsigned char iv[] = "01234567890123456"; // IV is 128 bit 
    AesModeCBC aescbc(key, AesKeySize::AES256, iv, 1);
    unsigned char BuffEncrypted[1024];
    unsigned char BuffDecrypted[1024];
    size_t len = 0;
    size_t lenEncripted = 0;

    MyMemSet(BuffEncrypted, sizeof(BuffEncrypted));
    MyMemSet(BuffDecrypted, sizeof(BuffDecrypted));

    len = strlen((const char *)OriginalData);

    // Encrypt the OriginalData
    lenEncripted = aescbc.Encrypt(OriginalData, BuffEncrypted, len);
    MyPrintBinData(BuffEncrypted, lenEncripted);


    // On remote system
    if (1)
    {
        size_t lenAfterDecrypt = 0;
        // We will use this object for decrypt  (FYI: with same key and iv)
        AesModeCBC RemoteAesCbcObj(key, AesKeySize::AES256, iv, 0);

        // Decrypt: We can get the original data by sending it out for 
        // one more encryption operation (with same key and iv).
        lenAfterDecrypt = RemoteAesCbcObj.Decrypt(BuffEncrypted, BuffDecrypted, lenEncripted);
        BuffDecrypted[lenAfterDecrypt] = 0;

        printf("\n Original :[%s]", OriginalData);
        printf("\n Decrypted:[%s]", BuffDecrypted);

        printf("\n Total data length = %d,   Number of AES Blocks = %d,   Bytes in Partial Block = %d",
            (unsigned int)len, (unsigned int)(len/BLOCK_SIZE), (unsigned int)(len % BLOCK_SIZE));

        if (len != lenAfterDecrypt)
        {
            printf("\n ***** Mismatch in the length before and after encryption **********");
        }

        printf("\n");
    }

    return(0);
}

void MyMemSet(unsigned char *p, unsigned int t)
{
    unsigned int i = 0;
    for (i = 0; i < t; ++i)
    {
        *p++ = 0;
    }
}


void MyPrintBinData(const unsigned char *BinData, size_t len)
{
    size_t i;
    int DisplayBlockSeparation = 0;

    for (i = 0; i < len; i++)
    {
        printf("%X", BinData[i] / 16);
        printf("%X", BinData[i] % 16);

        ++DisplayBlockSeparation;
        if (DisplayBlockSeparation == 4)
        {
            DisplayBlockSeparation = 0;
            printf(" ");
        }
    }
    printf("\n");
}


/*
Output:
0AFCA133 80237866 28185790 1C85E23E BB8C4C11 E50E75D9 A9E9B41D 04754266 2AEC907C 956F9022 E90C8CD1 F8E2C12F E3D1EEFB 8D303DE0 05560028 A9F21E9B 26C246

 Original  : [We will send this message for encryption and then try decrypt too!.]
 Decrypted : [We will send this message for encryption and then try decrypt too!.]
 Total data length = 67, Number of AES Blocks = 4, Bytes in Partial Block = 3
*/
