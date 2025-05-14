
#include "../header/Base64.h"


std::string base64Encode(std::string input_data) {
    std::string output;
    int val = 0;
    int valb = -6;
    for (unsigned char c : input_data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            output.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        output.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (output.size() % 4) {
        output.push_back('=');
    }
    return output;
  }
  
  std::string base64Decode(std::string encoded) {
      std::vector<int> T(256, -1);
      for (int i = 0; i < 64; i++) {
          T[base64_chars[i]] = i;
      }

      std::string output;
      int val = 0;
      int valb = -8;
      for (unsigned char c : encoded) {
          if (T[c] == -1) break;
          val = (val << 6) + T[c];
          valb += 6;
          if (valb >= 0) {
              output.push_back(char((val >> valb) & 0xFF));
              valb -= 8;
          }
      }
      return output;
  }