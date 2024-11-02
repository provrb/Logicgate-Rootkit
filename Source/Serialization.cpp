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
 * Convert an OpenSSL BIO* type to a string.
 * 
 * \param bio - the BIO* object to convert to a string
 * \return 'bio' as a std::string
 */
std::string Serialization::ConvertBIOToString(BIO* bio) {
    char* charString;
    long bytes = BIO_get_mem_data(bio, &charString);
    return std::string(charString, bytes);
}

/**
 * Convert a BYTESTRING (std::vector<unsigned char> to an std::string.
 * 
 * \param in - the BYTESTRING to convert
 * \return 'in' as an std::string 
 */
std::string Serialization::BytestringToString(BYTESTRING in) {
    return std::string(in.begin(), in.end());
}
