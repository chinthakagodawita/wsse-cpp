wsse-cpp
========

Tiny C++ class to generate WSSE authentication headers.

More detailed README coming soon.

For the moment, if you're using CMake, simply add this Git project as a submodule (say into _vendor/wsse-cpp_) and then add it as a subdirectory in your CMake project:

```lang=cmake
add_subdirectory(vendor/wsse-cpp)
```

You can then link against this library:

```lang=cmake
target_link_libraries (MY_APPLICATION wsse-cpp)
```

## Examples

```lang=cpp
#import <iostream>
#import "wsse.hpp"

Wsse auth;
string wsse_header;

auth.set_user("api_user")
auth.set_pass("api_key")

wsse_header = auth.get_header();

std::cout << "Header:" << std::endl;
std::cout << "X-WSSE: " << wsse_header << std::endl;

# To generate a new header:
wsse_header = auth.get_header(true);
```
