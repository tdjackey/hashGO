#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include <fstream>
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
using namespace std;

#define SHA1_ROTL(a,b) (SHA1_tmp=(a),((SHA1_tmp>>(32-b))&(0x7fffffff>>(31-b)))|(SHA1_tmp<<b))
#define SHA1_F(B,C,D,t) ((t<40)?((t<20)?((B&C)|((~B)&D)):(B^C^D)):((t<60)?((B&C)|(B&D)|(C&D)):(B^C^D)))
long SHA1_tmp;
char* SHA1(const char* str, char* sha1, unsigned int length,  bool space=false){
    char *pp, *ppend;
    unsigned int  l, i, K[80], W[80], TEMP, A, B, C, D, E, H0, H1, H2, H3, H4;
    H0 = 0x67452301, H1 = 0xEFCDAB89, H2 = 0x98BADCFE, H3 = 0x10325476, H4 = 0xC3D2E1F0;
    for (i = 0; i < 20; K[i++] = 0x5A827999);
    for (i = 20; i < 40; K[i++] = 0x6ED9EBA1);
    for (i = 40; i < 60; K[i++] = 0x8F1BBCDC);
    for (i = 60; i < 80; K[i++] = 0xCA62C1D6);
    l = length + ((length % 64 > 56) ? (128 - length % 64) : (64 - length % 64));
    if (!(pp = (char*)malloc((unsigned int )l))) return 0;
    for (i = 0; i < length; pp[i + 3 - 2 * (i % 4)] = str[i], i++);
    for (pp[i + 3 - 2 * (i % 4)] = 128,i++; i < l; pp[i + 3 - 2 * (i % 4)] = 0,i++);
    *((unsigned int *)(pp + l - 4)) = length << 3;
    *((unsigned int *)(pp + l - 8)) = length >> 29;
    for (ppend = pp + l; pp < ppend; pp += 64){
        for (i = 0; i < 16; W[i] = ((unsigned int *)pp)[i], i++);
        for (i = 16; i < 80; W[i] = SHA1_ROTL((W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]), 1), i++);
        A = H0, B = H1, C = H2, D = H3, E = H4;
        for (i = 0; i < 80; i++){
            TEMP = SHA1_ROTL(A, 5) + SHA1_F(B, C, D, i) + E + W[i] + K[i];
            E = D, D = C, C = SHA1_ROTL(B, 30), B = A, A = TEMP;
			//if(file)fprintf(file, "%08X %08X %08X %08X %08X\n", A, B, C, D, E); 
        }
        H0 += A, H1 += B, H2 += C, H3 += D, H4 += E;
    }
    free(pp - l);
	if(space) sprintf(sha1, "%08X %08X %08X %08X %08X", H0, H1, H2, H3, H4); 
	else sprintf(sha1, "%08X%08X%08X%08X%08X", H0, H1, H2, H3, H4); 
    return sha1;
}
int main(){

     
    char *result=new char[1000];

   
    char str1[] = "";
    cout << "*********************************************************************************************" << endl;
    cout << "test1: NULL " << endl;
    cout << "*********************************************************************************************" << endl;
    cout << "中间结果：" << endl;
    SHA1(str1,result,0,1);
    cout << "最终结果: " << endl;
    cout << result << endl;
    cout << endl;
    

    char str2[] = "abc";
    cout << "*********************************************************************************************" << endl;
    cout << "test2:  abc " << endl;
    cout << "*********************************************************************************************" << endl;
    cout << "中间结果：" << endl;
    SHA1(str2,result,3,1);
    cout << "最终结果: " << endl;
    cout << result << endl;
    cout << endl;


    char str3[] = "gongjieP14200004";
    cout << "*********************************************************************************************" << endl;
    cout << "test3:  gongjieP14200004 " << endl;
    cout << "*********************************************************************************************" << endl;
    cout << "中间结果：" << endl;
    SHA1(str3,result,16,1);
    cout << "最终结果: " << endl;
    cout << result << endl;
    cout << endl;


    char str4[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    cout << "*********************************************************************************************" << endl;
    cout << "test4:  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 " << endl;
    cout << "*********************************************************************************************" << endl;
    cout << "中间结果：" << endl;
    SHA1(str4,result,62,1);
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
    SHA1(str5,result,1000000,1);
    cout << "最终结果: " << endl;
    cout << result << endl;
    cout << endl;
    /*

    char str1[] = "";
    char str2[] = "abc";
    char str3[] = "gongjieP14200004";
    char str4[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    char *str5=new char[1000001];
    for(int i=0;i<1000000;i++){
        str5[i]='a';
    }
    str5[1000000]=0;

    char *ans=new char[1000];
    char* (*f[1])(const char* str, char* sha1, unsigned int length, FILE* file, bool space)={SHA1};
    char fname[1][10]={"SHA1"};
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
    */
    system("pause");
    return 0;
}
