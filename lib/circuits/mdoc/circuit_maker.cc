// Copyright 2025 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This program generates a circuit for mdoc_zk, computes its ID, and writes
// the circuit to a file named after the circuit ID in a specified output
// directory.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "base/init_google.h"
#include "file/base/path.h"
#include "circuits/mdoc/mdoc_zk.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/flags/flag.h"
#include "third_party/absl/flags/parse.h"

ABSL_FLAG(std::string, output_dir, "circuits",
          "Output directory for the circuit file");
ABSL_FLAG(int, num_attributes, 1,
          "Number of attributes for the circuit (selects ZkSpec)");

std::string BytesToHexString(const uint8_t* bytes, size_t len) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) {
    ss << std::setw(2) << static_cast<int>(bytes[i]);
  }
  return ss.str();
}

// Helper to find a ZkSpecStruct matching the desired number of attributes.
// If no exact match, returns nullptr. In a real scenario, you might pick the
// latest or closest one, or error out.
const ZkSpecStruct* FindZkSpecByNumAttributes(int n_attrs) {
  for (size_t i = 0; i < kNumZkSpecs; ++i) {
    if (static_cast<int>(kZkSpecs[i].num_attributes) == n_attrs) {
      return &kZkSpecs[i];
    }
  }
  return nullptr;  // Or handle as an error, or pick a default.
}

int main(int argc, char* argv[]) {
  InitGoogle(argv[0], &argc, &argv, true);
  absl::ParseCommandLine(argc, argv);

  std::string output_dir_path = absl::GetFlag(FLAGS_output_dir);
  int n_attributes_requested = absl::GetFlag(FLAGS_num_attributes);
  std::cout << "Output directory: " << output_dir_path << std::endl;
  std::cout << "Requested number of attributes: " << n_attributes_requested
            << std::endl;

  // Find a ZkSpecStruct based on the number of attributes requested
  const ZkSpecStruct* selected_zk_spec =
      FindZkSpecByNumAttributes(n_attributes_requested);
  if (selected_zk_spec == nullptr) {
    std::cerr << "Error: No ZkSpec available in kZkSpecs array." << std::endl;
    return 1;
  }

  std::cout << "Using ZkSpec: " << selected_zk_spec->system
            << ", version: " << selected_zk_spec->version
            << ", attributes: " << selected_zk_spec->num_attributes
            << std::endl;

  std::ifstream dir(output_dir_path, std::ios::binary);
  if (!dir.is_open()) {
    std::cerr << "Error: Could not open dir  " << output_dir_path << std::endl;
    return 1;
  }
  dir.close();

  uint8_t* circuit_bytes = nullptr;
  size_t circuit_len = 0;
  // Use absl mechanism to ensure that the memory is freed.
  absl::Cleanup free_circuit_bytes = [&circuit_bytes] {
    if (circuit_bytes) {
      free(circuit_bytes);  // mdoc_zk.h uses C-style allocation
    }
  };

  std::cout << "Generating circuit..." << std::endl;
  CircuitGenerationErrorCode circuit_gen_status =
      generate_circuit(selected_zk_spec, &circuit_bytes, &circuit_len);
  if (circuit_gen_status != CIRCUIT_GENERATION_SUCCESS) {
    std::cerr << "Error generating circuit. Code: " << circuit_gen_status
              << std::endl;
    return 1;
  }
  if (circuit_bytes == nullptr || circuit_len == 0) {
    std::cerr << "Error: generate_circuit succeeded but output is empty."
              << std::endl;
    return 1;
  }
  std::cout << "Circuit generated successfully. Size: " << circuit_len
            << " bytes." << std::endl;

  // Compute circuit ID.
  constexpr size_t kSHA256DigestSize = 32;
  uint8_t c_id[kSHA256DigestSize];
  std::cout << "Computing circuit ID." << std::endl;
  if (!circuit_id(c_id, circuit_bytes, circuit_len, selected_zk_spec)) {
    std::cerr << "Error computing circuit ID." << std::endl;
    return 1;
  }
  std::string circuit_id_hex = BytesToHexString(c_id, kSHA256DigestSize);
  std::cout << "Circuit ID (hex): " << circuit_id_hex << std::endl;

  // Write circuit bytes to file.
  std::string output_file_path =
      file::JoinPath(output_dir_path, circuit_id_hex);
  std::cout << "Writing circuit to: " << output_file_path << std::endl;
  std::ofstream out_file(output_file_path, std::ios::binary | std::ios::trunc);
  if (!out_file.is_open()) {
    std::cerr << "Error: Could not open file for writing: " << output_file_path
              << std::endl;
    return 1;
  }
  out_file.write(reinterpret_cast<const char*>(circuit_bytes), circuit_len);
  if (!out_file) {  // Check for write errors
    std::cerr << "Error writing circuit to file: " << output_file_path
              << std::endl;
    out_file.close();
    return 1;
  }
  out_file.close();
  std::cout << "Circuit successfully written to " << output_file_path
            << std::endl;
  return 0;
}
