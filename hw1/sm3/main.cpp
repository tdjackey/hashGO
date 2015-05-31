#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include <fstream>
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
using namespace std;

long SM3_ROTL(long a,long b) {return (((a << (b % 32)) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - (b % 32))));}
long SM3_FF(long X,long Y,long Z,int j) {return ((j < 16) ? (X ^ Y ^ Z) : ((X & Y) | (X & Z) | (Y & Z)));}
long SM3_GG(long X,long Y,long Z,int j) {return ((j < 16) ? (X ^ Y ^ Z) : ((X & Y) | ((~ X) & Z)));}
long SM3_P0(long X) {return (X ^ (SM3_ROTL(X, 9)) ^ (SM3_ROTL(X, 17)));}
long SM3_P1(long X) {return (X ^ (SM3_ROTL(X, 15)) ^ (SM3_ROTL(X, 23)));}

char* SM3(const char *str, char *sm3, long long length, FILE *file=NULL, bool space=false){
	char *pp,*ppend;
	long l, i, j, T[64], W[68], W1[64], A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2;
	long IV[8] = {0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d ,0xb0fb0e4e};
	for (int i = 0; i < 16;T[i++] = 0x79cc4519);
	for (int i = 16; i < 64;T[i++] = 0x7a879d8a);
	l = length + ((length % 64 > 56) ? (128 - length % 64) : (64 - length % 64));
	if (!(pp = (char*)malloc((unsigned long)l))) return 0;
	for (i = 0; i < length; pp[i + 3 - 2 * (i % 4)] = str[i], i++);
    for (pp[i + 3 - 2 * (i % 4)] = 128,i++; i < l; pp[i + 3 - 2 * (i % 4)] = 0,i++);
	*((long*)(pp + l - 4)) = length<<3;
	*((long*)(pp + l - 8)) = length>>29;
	for (ppend = pp + l; pp < ppend; pp += 64){
		for (j = 0;j < 16; j++)W[j]=*((long*)(pp)+j);
		for (j = 16;j < 68; j++)W[j] = SM3_P1(W[j-16] ^ W[j-9] ^ (SM3_ROTL(W[j-3], 15))) ^ (SM3_ROTL(W[j-13], 7)) ^ W[j-6];
		for (j = 0;j < 64; j++)W1[j] = W[j] ^ W[j+4];
		A = IV[0], B = IV[1], C = IV[2], D = IV[3], E = IV[4], F = IV[5], G = IV[6], H = IV[7];
		for (j = 0;j < 64;j++){
			SS1 = SM3_ROTL(((SM3_ROTL(A, 12)) + E + (SM3_ROTL(T[j], j))) & 0xFFFFFFFF, 7);
			SS2 = SS1 ^ (SM3_ROTL(A, 12));
			TT1 = (SM3_FF(A, B, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF;
			TT2 = (SM3_GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;
			D = C, C = SM3_ROTL(B, 9), B = A, A = TT1, H = G, G = SM3_ROTL(F, 19), F = E, E = SM3_P0(TT2);
			if(file)fprintf(file, "%08X %08X %08X %08X %08X %08X %08X %08X\n", A, B, C, D, E, F, G, H); 
		}
		IV[0] ^= A, IV[1] ^= B, IV[2] ^= C, IV[3] ^= D, IV[4] ^= E, IV[5] ^= F, IV[6] ^= G, IV[7] ^= H;
    }
	free(pp - l);
	if(space) sprintf(sm3, "%08X %08X %08X %08X %08X %08X %08X %08X", IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7]);
	else sprintf(sm3, "%08X%08X%08X%08X%08X%08X%08X%08X", IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7]);
	return sm3;
}


int main(){
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
	char* (*f[1])(const char* str, char* sha1, long long length, FILE* file, bool space)={SM3};
	char fname[1][10]={"SM3"};
	FILE* file=fopen("out.txt","w");
	for(int i=0;i<1;i++){
		fprintf(file,"%s:\n",fname[i]);
		fprintf(file,"实例1: %s\n",str1);
		fprintf(file,"实例1中间结果:\n");
		f[i](str1,ans,0,file,1);
		fprintf(file,"实例1最终结果:\n%s\n",ans);
		fprintf(file,"实例2: %s\n",str2);
		fprintf(file,"实例2中间结果:\n");
		f[i](str2,ans,3,file,1);
		fprintf(file,"实例2最终结果:\n%s\n",ans);
		fprintf(file,"实例3: %s\n",str3);
		fprintf(file,"实例3中间结果:\n");
		f[i](str3,ans,17,file,1);
		fprintf(file,"实例3最终结果:\n%s\n",ans);
		fprintf(file,"实例4最终结果:\n%s\n",f[i](str4,ans,62,NULL,1));
		fprintf(file,"实例5最终结果:\n%s\n",f[i](str5,ans,1000000,NULL,1));
		fprintf(file,"\n");
	}
	fclose(file);
	system("pause");
}
