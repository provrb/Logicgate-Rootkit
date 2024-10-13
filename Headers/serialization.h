#pragma once

#include "framework.h"
#include "net_types.h"

typedef std::vector<unsigned char> BYTESTRING;

namespace Serialization {

    template <typename _Struct>
    inline _Struct DeserializeToStruct(BYTESTRING b) {
        return std::is_same<BYTESTRING, _Struct>::value ? b : *reinterpret_cast< _Struct* >( b.data() );
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