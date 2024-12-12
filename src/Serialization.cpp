#include "serialization.h"

/**
 * Convert a string into a bytestring (std::vector<unsigned char> by copying each char.
 * 
 * \param s - the string to convert
 * \return 's' as a BYTESTRING
 */
BYTESTRING Serialization::SerializeString(std::string s) {
    BYTESTRING bs(s.begin(), s.end());
    return bs;
}

/**
 * Convert a BYTESTRING (std::vector<unsigned char> to an std::string.
 * 
 * \param in - the BYTESTRING to convert
 * \return 'in' as an std::string 
 */
std::string Serialization::BytestringToString(const BYTESTRING& in) {
    return std::string(in.begin(), in.end());
}
