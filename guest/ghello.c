#include <unistd.h>
int main(void) {
    static const char msg[] = "glibc hello under myos\n";
    write(1, msg, sizeof(msg) - 1);
    return 7;
}
