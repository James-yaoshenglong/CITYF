#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string>
#include <iostream>
#include<sys/ptrace.h>
#include "tea.h"

#define BUFSIZE 16

int main()
{
	int pipefd[2];
	pid_t pid;
	char cbuf[BUFSIZE];
	if(ptrace(PTRACE_TRACEME)==-1){
		return 0;
	}
	
	if (pipe(pipefd) == -1) {
		perror("pipe()");
		exit(1);
	}
	
	__asm__ ("call L1+1\n\t" 
             "L1: xor %rax, %rax\n\t"
             "pop %rax\n\t"
             "add $0xa,%rax\n\t"
             "push %rax\n\t"
             "ret\n");
            
	printf("Decrypting...\n");
	snprintf(cbuf, BUFSIZE, "`jwzeXMLW|EOBD^");
	
	for(int i =0;i<15; i++){
		cbuf[i] ^= 0x23;
	}
	
	tea::Key real_key(cbuf);
	tea::Bytes data({115, 133, 167, 95, 165, 237, 5, 90, 64, 76, 35, 125, 57, 72, 102, 133, 230, 236, 15, 146, 223, 209, 90, 172, 246, 49, 144, 202, 132, 130, 51, 124, 186, 51, 57, 19, 212, 189, 106, 72, 237, 142, 103, 112, 120, 46, 191, 13});
	
	std::string flag = tea::decrpy_string(data, real_key, 16);
	return 0;
}
