#include <vector>
#include <string>

std::string base64Encode(std::string input_data);

std::string base64Decode(std::string encoded);

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || c == '+' || c == '/');
}