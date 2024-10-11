#pragma once

#include "framework.h"
#include "net_types.h"

typedef std::vector<unsigned char> BYTESTRING;

namespace Serialization {
    inline std::string BytestringToString(BYTESTRING in) {
        return std::string(in.begin(), in.end());
    }

    template <typename _Struct>
    inline _Struct DeserializeToStruct(BYTESTRING b) {
        if constexpr ( std::is_same<BYTESTRING, _Struct>::value )
            return b;
        return *reinterpret_cast< _Struct* >( b.data() );
    }

    template <typename _Struct>
    inline BYTESTRING SerializeStruct(_Struct data) {
        BYTESTRING serialized(sizeof(_Struct));
        std::memcpy(serialized.data(), &data, sizeof(_Struct));

        return serialized;
    }

    inline std::string ConvertBIOToString(BIO* bio) {
        char* charString;
        long bytes = BIO_get_mem_data(bio, &charString);
        return std::string(charString, bytes);
    }

    /*
        Convert an std::string to a BYTESTRING
        (std::vector<unsigned char>)
    */
    BYTESTRING SerializeString(std::string s);
}