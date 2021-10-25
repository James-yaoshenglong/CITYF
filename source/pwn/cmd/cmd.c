#include <stdio.h>
#include <string.h>

int filter(char* cmd){
	int r=0;
	r += strstr(cmd, "flag")!=0;
	r += strstr(cmd, "sh")!=0;
	r += strstr(cmd, "tmp")!=0;
	r += strstr(cmd, "cat")!=0;
	return r;
}
int main(int argc){
	putenv("PATH=/nopathenv");
	char input[30];
	gets(input);
	if (strlen(input)>=30) return 0;
	if(filter(input)) return 0;
	system( input);
	return 0;
}
