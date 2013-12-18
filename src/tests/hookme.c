#include <stdio.h>
#include <unistd.h>

static int it = 0;
int hookme(int a1, int a2, int a3, int a4) {
    printf("Inside the hook %d %d %d %d (it=%d)\n", a1, a2, a3, a4, it++);
    return a1 + a2 + a3 + a4;
}

int main(int argc, char **argv) {
    int i = 0;
    while (i++ < 10000) {
        sleep(1);
        hookme(1, 2, 3, 4);
    }

    return 0;
}

