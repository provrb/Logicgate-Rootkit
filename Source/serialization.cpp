#include "../Headers/serialization.h"

BYTESTRING Serialization::SerializeString(std::string s) {
    BYTESTRING bs;
    for ( BYTE c : s )
        bs.push_back(c);
    return bs;
}