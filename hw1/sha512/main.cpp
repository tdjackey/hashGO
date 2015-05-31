#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include <fstream>
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#define SHA512_ROTL(a,b) (((a>>(64-b))&(0x7fffffffffffffff>>(63-b)))|(a<<b))
#define SHA512_SR(a,b) ((a>>b)&(0x7fffffffffffffff>>(b-1)))
#define SHA512_Ch(x,y,z) ((x&y)^((~x)&z))
#define SHA512_Maj(x,y,z) ((x&y)^(x&z)^(y&z))
#define SHA512_E0(x) (SHA512_ROTL(x,36)^SHA512_ROTL(x,30)^SHA512_ROTL(x,25))
#define SHA512_E1(x) (SHA512_ROTL(x,50)^SHA512_ROTL(x,46)^SHA512_ROTL(x,23))
#define SHA512_O0(x) (SHA512_ROTL(x,63)^SHA512_ROTL(x,56)^SHA512_SR(x,7))
#define SHA512_O1(x) (SHA512_ROTL(x,45)^SHA512_ROTL(x,3)^SHA512_SR(x,6))

char* SHA512(const char* str, char* sha512, long long length, FILE* file=NULL, bool space=false){
    char *pp, *ppend;
    unsigned long long l, i, W[80], T1, T2, A, B, C, D, E, F, G, H, H0, H1, H2, H3, H4, H5, H6, H7;
    H0 = 0x6a09e667f3bcc908, H1 = 0xbb67ae8584caa73b, H2 = 0x3c6ef372fe94f82b, H3 = 0xa54ff53a5f1d36f1;
    H4 = 0x510e527fade682d1, H5 = 0x9b05688c2b3e6c1f, H6 = 0x1f83d9abfb41bd6b, H7 = 0x5be0cd19137e2179;
    unsigned long long K[80] = {
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
		0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
		0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
		0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
		0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
		0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
		0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
		0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
		0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
		0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
		0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
		0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
		0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };
    l = length + ((length % 128 > 112) ? (256 - length % 128) : (128 - length % 128));
    if (!(pp = (char*)malloc(l))) return 0;
    for (i = 0; i < length; pp[i + 7 - 2 * (i % 8)] = str[i], i++);
    for (pp[i + 7 - 2 * (i % 8)] = 128, i++; i < l; pp[i + 7 - 2 * (i % 8)] = 0, i++);
    *((unsigned long long*)(pp + l - 8)) = length << 3;
    *((unsigned long long*)(pp + l - 16)) = length >> 61;
    for (ppend = pp + l; pp < ppend; pp += 128){
        for (i = 0; i < 16; W[i] = ((unsigned long long*)pp)[i], i++);
        for (i = 16; i < 80; W[i] = (SHA512_O1(W[i - 2]) + W[i - 7] + SHA512_O0(W[i - 15]) + W[i - 16]), i++);
        A = H0, B = H1, C = H2, D = H3, E = H4, F = H5, G = H6, H = H7;
        for (i = 0; i < 80; i++){
            T1 = H + SHA512_E1(E) + SHA512_Ch(E, F, G) + K[i] + W[i];
            T2 = SHA512_E0(A) + SHA512_Maj(A, B, C);
            H = G, G = F, F = E, E = D + T1, D = C, C = B, B = A, A = T1 + T2;
			if(file)fprintf(file, "%08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X\n", 
		(unsigned int)(A>>32), (unsigned int)(A&0xffffffff), 
		(unsigned int)(B>>32), (unsigned int)(B&0xffffffff), 
		(unsigned int)(C>>32), (unsigned int)(C&0xffffffff), 
		(unsigned int)(D>>32), (unsigned int)(D&0xffffffff), 
		(unsigned int)(E>>32), (unsigned int)(E&0xffffffff), 
		(unsigned int)(F>>32), (unsigned int)(F&0xffffffff), 
		(unsigned int)(G>>32), (unsigned int)(G&0xffffffff), 
		(unsigned int)(H>>32), (unsigned int)(H&0xffffffff)); 
        }
        H0 += A, H1 += B, H2 += C, H3 += D, H4 += E, H5 += F, H6 += G, H7 += H;
    }
	free(pp - l);
    if(space) sprintf(sha512, "%08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X", 
		(unsigned int)(H0>>32), (unsigned int)(H0&0xffffffff), 
		(unsigned int)(H1>>32), (unsigned int)(H1&0xffffffff), 
		(unsigned int)(H2>>32), (unsigned int)(H2&0xffffffff), 
		(unsigned int)(H3>>32), (unsigned int)(H3&0xffffffff), 
		(unsigned int)(H4>>32), (unsigned int)(H4&0xffffffff), 
		(unsigned int)(H5>>32), (unsigned int)(H5&0xffffffff), 
		(unsigned int)(H6>>32), (unsigned int)(H6&0xffffffff), 
		(unsigned int)(H7>>32), (unsigned int)(H7&0xffffffff));
	else sprintf(sha512, "%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X", 
		(unsigned int)(H0>>32), (unsigned int)(H0&0xffffffff), 
		(unsigned int)(H1>>32), (unsigned int)(H1&0xffffffff), 
		(unsigned int)(H2>>32), (unsigned int)(H2&0xffffffff), 
		(unsigned int)(H3>>32), (unsigned int)(H3&0xffffffff), 
		(unsigned int)(H4>>32), (unsigned int)(H4&0xffffffff), 
		(unsigned int)(H5>>32), (unsigned int)(H5&0xffffffff), 
		(unsigned int)(H6>>32), (unsigned int)(H6&0xffffffff), 
		(unsigned int)(H7>>32), (unsigned int)(H7&0xffffffff));
    return sha512;
}
int main(){
/*
    
    char *result=new char[700];


    char *str1 = "";
    cout << "*********************************************************************************************" << endl;
    cout << "test1: NULL " << endl;
    cout << "*********************************************************************************************" << endl;
    cout << "中间结果：" << endl;
    SHA256(str1,result,0,1);
    cout << "最终结果: " << endl;
    cout << result << endl;
    cout << endl;
    

    char *str2 = "abc";
    cout << "*********************************************************************************************" << endl;
    cout << "test2:  abc " << endl;
    cout << "*********************************************************************************************" << endl;
    cout << "中间结果：" << endl;
    SHA256(str2,result,3,1);
    cout << "最终结果: " << endl;
    cout << result << endl;
    cout << endl;


    char *str3 = "gongjieP14200004";
    cout << "*********************************************************************************************" << endl;
    cout << "test3:  gongjieP14200004 " << endl;
    cout << "*********************************************************************************************" << endl;
    cout << "中间结果：" << endl;
    SHA256(str3,result,16,1);
    cout << "最终结果: " << endl;
    cout << result << endl;
    cout << endl;


    char *str4 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    cout << "*********************************************************************************************" << endl;
    cout << "test4:  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 " << endl;
    cout << "*********************************************************************************************" << endl;
    cout << "中间结果：" << endl;
    SHA256(str4,result,62,1);
    cout << "最终结果: " << endl;
    cout << result << endl;
    cout << endl;


    char *str5 = new char[1000001];
    for(int i=0;i<1000000;i++){
        str5[i]='a';
    }
    str5[1000000]=0;
    cout << "*********************************************************************************************" << endl;
    cout << "test5:  一百万个a " << endl;
    cout << "*********************************************************************************************" << endl;
    cout << "中间结果：" << endl;
    SHA256(str5,result,1000000,1);
    cout << "最终结果: " << endl;
    cout << result << endl;
    cout << endl;
    */

    char *str1="";
    char *str2="abc";
    char *str3="gongjieP14200004";
    char *str4="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    char *str5=new char[1000001];
    for(int i=0;i<1000000;i++){
        str5[i]='a';
    }
    str5[1000000]=0;

    char *ans=new char[1000];
    char* (*f[1])(const char* str, char* sha1, long long length, FILE* file, bool space)={SHA512};
    char fname[1][10]={"SHA512"};
    FILE* file=fopen("out.txt","w");

    for(int i=0;i<1;i++){
        fprintf(file,"%s:\n",fname[i]);
        fprintf(file,"Test1: %s\n",str1);
        fprintf(file,"Test1中间结果:\n");
        f[i](str1,ans,0,file,1);
        fprintf(file,"Test1最终结果:\n%s\n",ans);
        fprintf(file,"Test2: %s\n",str2);
        fprintf(file,"Test2中间结果:\n");
        f[i](str2,ans,3,file,1);
        fprintf(file,"Test2最终结果:\n%s\n",ans);
        fprintf(file,"Test3: %s\n",str3);
        fprintf(file,"Test3中间结果:\n");
        f[i](str3,ans,16,file,1);
        fprintf(file,"Test3最终结果:\n%s\n",ans);
        fprintf(file,"Test4最终结果:\n%s\n",f[i](str4,ans,62,NULL,1));
        fprintf(file,"Test5最终结果:\n%s\n",f[i](str5,ans,1000000,NULL,1));
        fprintf(file,"\n");
    }
    fclose(file);
    
    return 0;
}
