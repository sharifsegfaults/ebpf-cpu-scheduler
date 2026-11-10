#include <iostream>

int main() {
    std::string name;
    while (true) {
        std::cout << "Name: ";
        std::cin >> name;
        std::cout << "Hello from B!\n";
    }
    return 0;
}
