#include<stdio.h>
#include<stdlib.h>

void print_username(char* username)
{
	printf("Welcome:");
	if (strlen(username) > 32){
		printf("Not allowed!");
	}
	printf("\n");
	printf(username);
	
}

void welcome(){
	char input[32];
	int num;
	printf("Username:\n");
	fflush(stdout);
	read(0, input, 32);
	print_username(input);
	return;
}

int main(){
	int i =0;
	for (i = 0; i < 10; i++){
		welcome();
	}
	return 0;
}
