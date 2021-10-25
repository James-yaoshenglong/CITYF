#include <stdio.h>
#include <stdlib.h>
#include <time.h>

char buf2[100];

void secure(void)
{
    int secretcode, input;
    srand(time(NULL));

    secretcode = rand();
    scanf("%d", &input);
    if(input == secretcode)
        puts("secret");
}

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);

    char buf1[150];

    printf("Can you find the shell?");
    gets(buf1);

    return 0;
}
