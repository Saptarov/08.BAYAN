#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/filesystem/directory.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/functional/hash.hpp>
#include <boost/uuid/detail/sha1.hpp>

using namespace boost::filesystem;

template<typename Hash>
std::string hashBlock(const std::string& block) {
    Hash hasher;
    hasher.process_bytes(block.data(), block.size());
    typename Hash::digest_type digest;
    hasher.get_digest(digest);
    return std::string(reinterpret_cast<const char*>(&digest), sizeof(typename Hash::digest_type));
}

bool isDuplicate(const std::string& path, const std::vector<std::string>& hashes) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    const std::streamsize blockSize = 3;
    std::vector<char> buffer(blockSize);
    while (file.read(buffer.data(), blockSize)) {
        std::string block(buffer.begin(), buffer.begin() + file.gcount());
        std::string blockHash = hashBlock<boost::uuids::detail::sha1>(block);
        if (std::find(hashes.begin(), hashes.end(), blockHash) == hashes.end()) {
            return false;
        }
    }

    return true;
}

void scanDirectory(size_t blockSize, const std::string& path, const std::set<std::string>& excludeDirs, const std::vector<std::string>& allowedExtensions, std::vector<std::string>& hashes, std::vector<std::vector<std::string>>& duplicates) {
    std::vector<std::string> subdirs;
    recursive_directory_iterator dir(path), end;
    while (dir != end) {
        auto iter = excludeDirs.find(dir->path().string());
        if (is_directory(dir->path()) && iter == excludeDirs.end()) {
            subdirs.push_back(dir->path().string());
        } else if (is_regular_file(dir->path())) {
            std::string fileExtension = boost::algorithm::to_lower_copy(dir->path().extension().string());
            if (std::find(allowedExtensions.begin(), allowedExtensions.end(), fileExtension) != allowedExtensions.end() && file_size(dir->path().string()) <= blockSize) {
                std::string blockHash = hashBlock<boost::uuids::detail::sha1>(dir->path().string());
                if (std::find(hashes.begin(), hashes.end(), blockHash) != hashes.end()) {
                    hashes.push_back(blockHash);
                    duplicates.back().push_back(dir->path().string());
                } else {
                    hashes.push_back(blockHash);
                    duplicates.push_back({ dir->path().string() });
                }
            }
        }
    }

    for (const std::string& subdir : subdirs) {
        scanDirectory(blockSize, subdir, excludeDirs, allowedExtensions, hashes, duplicates);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " blocksize directory [exclude_directory]..." << std::endl;
        return 1;
    }

    std::set<std::string> excludeDirs;
    std::vector<std::string> allowedExtensions = { ".txt" };
    size_t blockSize = atoi(argv[2]);
    for (int i = 3; i < argc; ++i) {
        excludeDirs.insert(argv[i]);
      }

      std::string basePath = argv[1];
      std::vector<std::string> hashes;
      std::vector<std::vector<std::string>> duplicates;

      scanDirectory(blockSize, basePath, excludeDirs, allowedExtensions, hashes, duplicates);

      for (const std::vector<std::string>& group : duplicates) {
          for (const std::string& path : group) {
              std::cout << path << std::endl;
          }
          std::cout << std::endl;
      }

      return 0;
  }
