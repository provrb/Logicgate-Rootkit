#pragma once

#include "Framework.h"
#include "NetworkTypes.h"

typedef std::vector<unsigned char> BYTESTRING;

namespace Serialization {

    template <typename _Struct>
    inline _Struct DeserializeToStruct(BYTESTRING b) {
        if constexpr ( std::is_same<BYTESTRING, _Struct>::value )
            return b;

        //_Struct out;
        //std::memcpy(&out, b.data(), sizeof(b));
        //return out;
        return *reinterpret_cast< _Struct* >( b.data() );
    }

    template <typename _Struct>
    inline BYTESTRING SerializeStruct(_Struct data) {
        BYTESTRING serialized(sizeof(_Struct));
        std::memcpy(serialized.data(), &data, sizeof(_Struct));

        return serialized;
    }

    inline BIO*   GetBIOFromString(std::string s) { return BIO_new_mem_buf(s.c_str(), s.size()); }
    std::string   ConvertBIOToString(BIO* bio);
    std::string   BytestringToString(BYTESTRING in);
    BYTESTRING    SerializeString(std::string s);
}
