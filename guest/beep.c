/* beep: 8-bit sound check for /dev/audio.
 *
 * Writes a 0.5s 440Hz sine (unsigned 8-bit mono, 8000Hz) to /dev/audio,
 * which the kernel streams to the host player. Usage: beep [freq-hz].
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>

int main(int argc, char **argv) {
    int freq = argc > 1 ? atoi(argv[1]) : 440;
    if (freq <= 0 || freq > 4000) {
        fprintf(stderr, "beep: bad frequency\n");
        return 1;
    }
    int fd = open("/dev/audio", O_WRONLY);
    if (fd < 0) {
        perror("beep: /dev/audio");
        return 1;
    }
    static unsigned char buf[4000];
    const double PI = 3.14159265358979;
    for (int i = 0; i < 4000; i++) {
        double t = (double)i / 8000.0;
        /* No libm in a static guest: Bhaskara sine, good to ~0.2%. */
        double y = 2.0 * PI * freq * t;
        while (y >= 2.0 * PI) y -= 2.0 * PI;
        double s;
        if (y <= PI) {
            s = 16.0 * y * (PI - y) / (5.0 * PI * PI - 4.0 * y * (PI - y));
        } else {
            y -= PI;
            s = -16.0 * y * (PI - y) / (5.0 * PI * PI - 4.0 * y * (PI - y));
        }
        buf[i] = (unsigned char)(128.0 + 100.0 * s);
    }
    size_t left = sizeof(buf);
    const unsigned char *p = buf;
    while (left > 0) {
        ssize_t n = write(fd, p, left);
        if (n <= 0) {
            perror("beep: write");
            close(fd);
            return 1;
        }
        p += n;
        left -= (size_t)n;
    }
    close(fd);
    printf("beep %dHz\n", freq);
    return 0;
}
