#include <iostream>
#include <cstring>

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
/* Implementation is derived from katran LB */

std::string base64Encode(std::string input_data);

std::string base64Decode(std::string encoded);