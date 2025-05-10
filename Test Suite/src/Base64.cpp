
#include "../header/Base64.h"


std::string base64Encode(std::string input_data) {
    using namespace boost::archive::iterators;
    using b64it = base64_from_binary<transform_width<const unsigned char*, 6, 8>>;
    int output_size = (input_data.length() * 8 + 5) / 6;
    std::string encoded(output_size, '*');
    auto data = new char[input_data.length()];
    if (data == nullptr) {
      // return empty string. as we are using this in tests only that would just
      // mean that we have failed a test. log line will show reason why.
      std::cerr << "Memory allocation Failed for Base64 encode!" << std::endl;
      return "";
    }
    std::memcpy(data, input_data.c_str(), input_data.length());
    std::copy(b64it(data), b64it((char*)data + (input_data.length())), encoded.begin());
    for (int i = 0; i < (3 - (input_data.length() % 3)) % 3; i++) {
      encoded.push_back('=');
    }
    delete[] data;
    return encoded;
  }
  
  std::string base64Decode(std::string encoded) {
    using namespace boost::archive::iterators;
    using b64it =
        transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
  
    auto decoded =
        std::string(b64it(std::begin(encoded)), b64it(std::end(encoded)));
    int padded_chars = 0;
    while (true) {
      if (encoded[encoded.size() - 1] != '=') {
        return decoded.substr(0, decoded.size() - padded_chars);
      }
      encoded.pop_back();
      padded_chars++;
    }
  }