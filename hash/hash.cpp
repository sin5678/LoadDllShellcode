// hash.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>

int main(int argc, char* argv[])
{
	char *name = argv[1];
	unsigned short hash = 0;
	__asm{
		xor edx,edx
		xor eax,eax
		mov edi,name
		cdq
hash_loop:
		xor dl,byte ptr [edi]
		ror dx,0x1
		scas byte ptr [edi]
		jnz hash_loop
		mov hash,dx
	}
	printf("0x%04X",hash);
	return 0;
}

