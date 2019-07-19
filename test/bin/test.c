#include <stdio.h>

const char MESSAGE[15] = "Test Message\n";

int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}

int mul(int a, int b) {
    return a * b;
}

void do_nothing() {
    printf("This doesn't do anything.\n");
    return;
}

void print_const() {
    printf(MESSAGE);
}

int main(int argc, char** argv) {
    int a = add(3, 4),
        b = sub(9, 3),
        c = sub(8, 2),
        d = mul(8, 4);

    printf("3 + 4 = %d\n", a);
    printf("9 - 3 = %d\n", b);
    printf("8 - 2 = %d\n", c);
    printf("8 * 4 = %d\n", d);

    if(a == b) {
        do_nothing();
    } else {
        print_const();
    }

    do_nothing();
    print_const();


    printf("That's all\n");

    return 0;
}
    
