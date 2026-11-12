#include <csignal>
#include <iostream>
#include <sys/syscall.h>

static volatile bool exiting = false;

void sig_handler(int sig) {
    exiting = true;
}

int main() {
    std::string name;
    volatile long long* i = new long long(0);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    pid_t tid = syscall(SYS_gettid);

    std::cout << "[" << tid << "] Hello from A! (" << (void*)i << "): " << *i << "\n";
    while (!exiting) {
        *i += 1;
    }
    std::cout << "Final value: " << *i << "\n";
    return 0;
}
