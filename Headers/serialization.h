#pragma once

#include "Framework.h"
#include "NetworkTypes.h"

typedef std::vector<unsigned char> BYTESTRING;

namespace Serialization {

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

    std::string   ConvertBIOToString(BIO* bio);
    std::string   BytestringToString(BYTESTRING in);
    BYTESTRING    SerializeString(std::string s);
}