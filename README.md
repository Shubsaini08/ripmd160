HII  guys, its ME : (shub) again bring up again something that isnt gonna help or may be gonna help you out !!!.......

## presenting :: 

1. genrip.exe
   > generates and saves the outputs into a file !!

3. re160.exe
    > splits the ripmd hashes from file and save ripmd hashes in diff file !!

5. genrip160-match.exe
   > idk i dont trust computer to match  and generate at same time but it is accurate  generates and match and will gonna save the findings into a file  !!

## ITS ALL DOING IS GENERATING AND SAVING THE RIPMD160 HASHES INTO FILE NOTHING SPECIAL SO ITS UPTO YOU GUYS 
> ITS JUST A RESOURCE THAT CAN HELP UH IN UNDERSTANDINGS OF BITCOINS

## REQUIREMENTS :: 

1. [SECP256K1](https://github.com/bitcoin-core/secp256k1.git)

2. A GOOD PC !!
   > KIDDING IT CAN BE IN MOBILES TOOO WAY OF COMPILE CHANGES NOTHING ELSE :)

3. COMPILING COMMANDS !!
   > EITHER USE .EXE ONES PROVIDED OR COMPILE YOURS ITS NOT AN ISSUE FOR ME BUT BE COMFORTABLE WITH HUNTING !!
   > BELOW I WILL EXPLAIN HOW TO COMPILE ??

## COMPILING ::
1. LETS GO FIRST AT :

Ripmd160-gen.cpp ??..... [CMD,LINUX]

'''
> g++ -o genrip160.exe ripmd160-gen.cpp -std=c++17 -lssl -lcrypto -lsecp256k1 -pthread
'''
> g++ -o genrip160 ripmd160-gen.cpp -std=c++17 -lssl -lcrypto -lsecp256k1 -pthread
'''

ripemd_extraction.cpp ??..... [CMD,LINUX]

'''
> g++ -std=c++17 -pthread -o re160.exe ripemd_extraction.cpp
'''
> g++ -std=c++17 -pthread -o re160 ripemd_extraction.cpp
'''

ripmd160-match.cpp  ??..... [CMD,LINUX]

'''
> g++ -o genrip160-match.exe ripmd160-match.cpp -std=c++17 -lssl -lcrypto -lsecp256k1 -pthread
'''
> g++ -o genrip160-match ripmd160-match.cpp -std=c++17 -lssl -lcrypto -lsecp256k1 -pthread
'''

[HOPE THIS MUCH GONNA HELP ?? IF NOT CHANNELS LINKS PROVIDED BELOW]

## WORKFLOW ::

'''
GEN::
[Start]
   |
   v
[Check dependencies]
   |
   v
[Generate Private Key]  --> [Randomly generate 32-byte private key]
   |
   v
[Generate Public Key]   --> [Create compressed/uncompressed public keys from private key using secp256k1]
   |
   v
[Generate Hashes]       --> [Use OpenSSL to hash the public key with SHA256 + RIPEMD160]
   |
   v
[Save Data]             --> [Save the private key and hashes to a file (FOUNDripmd.txt)]
   |
   v
[Display Stats]         --> [Show key generation stats (speed, total keys)]
   |
   v
[End]
'''

HOPE SO YOU WILL FIND SOMETHING SUPER SOON AND DONATE SOME 

# DOORS are always open for DONATIONS 
========================================
# HOPE IT WILL HELP
[FOR ANY QUESTIONS TEXT US AT]

> [code_Crusaders0](https://t.me/code_Crusaders0)
> 
> [KEYFOUND](https://t.me/privatekeydirectorygroup)
> 
> [ALSO FOR TRADING WITH BOTS](https://t.me/+ggaun3gLB900MGY0)
> 
> [GITHUB LINK FOR MORRE](https://github.com/Shubsaini08)





