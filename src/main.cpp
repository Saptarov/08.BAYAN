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
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

using namespace boost::filesystem;
namespace po = boost::program_options;
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

void scanDirectory(size_t blockSize
                   , size_t fileSize
                   , bool scan_without_subdir
                   , std::vector<std::string>& directories
                   , std::set<std::string>& excludeDirs
                   , const std::vector<std::string>& allowedExtensions
                   , std::vector<std::string>& hashes, std::vector<std::vector<std::string>>& duplicates
                   )
{
    std::vector<std::string> subdirs;
    for (auto& path : directories) {
        recursive_directory_iterator dir(path), end;
        for (auto const& dir : recursive_directory_iterator(path)) {
            auto iter = excludeDirs.find(dir.path().string());
            if (scan_without_subdir && is_directory(dir.path()) && iter == excludeDirs.end()) {
                subdirs.push_back(dir.path().string());
            } else if (is_regular_file(dir.path())) {
                std::string fileExtension = boost::algorithm::to_lower_copy(dir.path().extension().string());
                auto dir_path = dir.path().string();
                if (std::find(allowedExtensions.begin(), allowedExtensions.end(), fileExtension) != allowedExtensions.end() && file_size(dir_path) <= fileSize) {
                    std::string blockHash = hashBlock<boost::uuids::detail::sha1>(dir.path().string());
                    if (blockHash.size() > blockSize) {
                        continue;
                    }
                    if (std::find(hashes.begin(), hashes.end(), blockHash) != hashes.end()) {
                        hashes.push_back(blockHash);
                        duplicates.back().push_back(dir.path().string());
                    } else {
                        hashes.push_back(blockHash);
                        duplicates.push_back({ dir.path().string() });
                    }
                }
            }
        }
    }
    if (subdirs.size() > 0) {
        scanDirectory(blockSize, fileSize, scan_without_subdir, subdirs, excludeDirs, allowedExtensions, hashes, duplicates);
    }
}

int main(int argc, char* argv[]) {
    po::options_description options("Bayan options");
    options.add_options()
            ("scan_dir,i", po::value<std::vector<std::string>>(), "Include directory")
            ("exclude_dir,e", po::value<std::vector<std::string>>(), "Exclude directory")
            ("scan_depth,d", po::value<size_t>(), "Depth of scanning")
            ("min_file_size,f", po::value<size_t>(), "Minimum file size in bytes")
            ("file_mask,m", po::value<std::string>(), "File mask")
            ("block_size,s", po::value<size_t>(), "Block size")
            ("hash_algo,h", po::value<std::string>(), "Hash algorithm (crc32,md5)")
            ;

    po::variables_map vm;
    po::parsed_options parsed = po::command_line_parser(argc, argv).options(options).allow_unregistered().run();
    po::store(parsed, vm);
    po::notify(vm);

    if (vm.size() == 0) {
        std::cout << options << std::endl;
        return 0;
    }

    if (vm.find("scan_dir") == vm.end()) {
        std::cout << "option scan_dir should be specified" << std::endl;
        return -1;
    }
    std::vector<std::string> basePath = vm["scan_dir"].as<std::vector<std::string>>();

    if (vm.find("exclude_dir") == vm.end()) {
        std::cout << "option exclude_dir should be specified" << std::endl;
        return -1;
    }
    std::vector<std::string> exclude_dir = vm["exclude_dir"].as<std::vector<std::string>>();

    bool scan_without_subdir = false;
    if (vm.find("scan_depth") != vm.end()) {
        scan_without_subdir = vm["scan_depth"].as<size_t>() == 0;
    } else {
        std::cout << "option scan_depth is not specified, will be to set 1" << std::endl;
    }

    size_t min_file_size = 1;
    if (vm.find("min_file_size") != vm.end()) {
        min_file_size = vm["min_file_size"].as<size_t>();
    } else {
        std::cout << "option min_file_size is not specified, will be to set 1 byte" << std::endl;
    }

    std::string file_mask;
    if (vm.find("file_mask") != vm.end()) {
        file_mask = vm["file_mask"].as<std::string>();
        std::cout << "specified file mask = " << file_mask << std::endl;
    }

    size_t block_size = 1;
    if (vm.find("block_size") == vm.end()) {
        std::cout << "option block_size should be specified" << std::endl;
        return -1;
    }

    std::string hash_algo = "sha1";
    if (vm.find("hash_algo") != vm.end()) {
        file_mask = vm["hash_algo"].as<std::string>();
    } else {
        std::cout << "option hash_algo is not specified, will be to set crc32" << std::endl;
    }
    std::vector<std::string> allowedExtensions = { ".txt" };

    std::vector<std::string> hashes;
    std::set<std::string> excludeDirs;
    std::vector<std::vector<std::string>> duplicates;

    std::for_each(exclude_dir.begin(), exclude_dir.end(), [&excludeDirs] (std::string& path) {
        excludeDirs.insert(path);
    });

    scanDirectory(block_size, min_file_size, scan_without_subdir, basePath, excludeDirs, allowedExtensions, hashes, duplicates);

    for (const std::vector<std::string>& group : duplicates) {
        for (const std::string& path : group) {
            std::cout << path << std::endl;
        }
        std::cout << std::endl;
    }
    return 0;
}
