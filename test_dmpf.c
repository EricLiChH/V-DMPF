#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/common.h"
#include "include/dmpf.h"
#include "include/dpf.h"

int main() {
  printf("Testing DMPF Implementation\n");
  printf("============================\n\n");

  // Initialize OpenSSL context
  uint8_t key[16] = {0};
  EVP_CIPHER_CTX *ctx = getDPFContext(key);
  if (!ctx) {
    printf("Failed to create OpenSSL context\n");
    return 1;
  }

  // Test parameters
  int domain_size = 8; // 2^8 = 256 domain
  int data_size = 4;   // 4 bytes per data element
  uint64_t num_inputs = 3;

  // Test inputs (must be sorted)
  uint64_t inputs[] = {10, 50, 200};

  // Create custom test data as continuous memory block
  uint8_t *test_data = malloc(data_size * num_inputs);

  // Set different test data for each input
  // Input 10: [0x01, 0x02, 0x03, 0x04]
  test_data[0] = 0x01;
  test_data[1] = 0x02;
  test_data[2] = 0x03;
  test_data[3] = 0x04;

  // Input 50: [0xAA, 0xBB, 0xCC, 0xDD]
  test_data[4] = 0xAA;
  test_data[5] = 0xBB;
  test_data[6] = 0xCC;
  test_data[7] = 0xDD;

  // Input 200: [0xFF, 0xEE, 0xDD, 0xCC]
  test_data[8] = 0xFF;
  test_data[9] = 0xEE;
  test_data[10] = 0xDD;
  test_data[11] = 0xCC;

  printf("Test Parameters:\n");
  printf("- Domain size: 2^%d = %d\n", domain_size, 1 << domain_size);
  printf("- Data size: %d bytes\n", data_size);
  printf("- Number of inputs: %lu\n", num_inputs);
  printf("- Input values: ");
  for (uint64_t i = 0; i < num_inputs; i++) {
    printf("%lu ", inputs[i]);
  }
  printf("\n");
  printf("- Test data:\n");
  for (uint64_t i = 0; i < num_inputs; i++) {
    printf("  Input %lu: [", inputs[i]);
    for (int j = 0; j < data_size; j++) {
      printf("%02x", test_data[i * data_size + j]);
      if (j < data_size - 1)
        printf(" ");
    }
    printf("]\n");
  }
  printf("\n");

  // Allocate key space (generous allocation)
  size_t key_size = 1024 + data_size * num_inputs * 4;
  uint8_t *k0 = malloc(key_size);
  uint8_t *k1 = malloc(key_size);
  memset(k0, 0, key_size);
  memset(k1, 0, key_size);

  printf("Generating DMPF keys...\n");

  // Generate DMPF
  genDMPF(ctx, domain_size, data_size, inputs, num_inputs, test_data, k0, k1);

  printf("DMPF keys generated successfully!\n\n");

  // Test evaluation at specific points
  printf("Testing DMPF evaluation:\n");
  printf("------------------------\n");

  uint8_t *output0 = malloc(data_size);
  uint8_t *output1 = malloc(data_size);

  // Test at input points (should give non-zero results)
  for (uint64_t i = 0; i < num_inputs; i++) {
    memset(output0, 0, data_size);
    memset(output1, 0, data_size);

    evalBigStateDMPF(ctx, k0, inputs[i], data_size, output0);
    evalBigStateDMPF(ctx, k1, inputs[i], data_size, output1);

    printf("Input %lu: ", inputs[i]);
    printf("Share0=[");
    for (int j = 0; j < data_size; j++) {
      printf("%02x", output0[j]);
      if (j < data_size - 1)
        printf(" ");
    }
    printf("] Share1=[");
    for (int j = 0; j < data_size; j++) {
      printf("%02x", output1[j]);
      if (j < data_size - 1)
        printf(" ");
    }
    printf("] Sum=[");
    for (int j = 0; j < data_size; j++) {
      printf("%02x", output0[j] ^ output1[j]);
      if (j < data_size - 1)
        printf(" ");
    }
    printf("]\n");
  }

  // Test at non-input points (should give zero results)
  uint64_t test_points[] = {0, 15, 25, 100, 255};
  size_t num_test_points = sizeof(test_points) / sizeof(test_points[0]);

  printf("\nTesting at non-input points (should be zero):\n");
  for (size_t i = 0; i < num_test_points; i++) {
    uint64_t test_point = test_points[i];

    // Skip if this is actually an input point
    bool is_input = false;
    for (uint64_t j = 0; j < num_inputs; j++) {
      if (test_point == inputs[j]) {
        is_input = true;
        break;
      }
    }
    if (is_input)
      continue;

    memset(output0, 0, data_size);
    memset(output1, 0, data_size);

    evalBigStateDMPF(ctx, k0, test_point, data_size, output0);
    evalBigStateDMPF(ctx, k1, test_point, data_size, output1);

    printf("Point %lu: ", test_point);
    printf("Share0=[");
    for (int j = 0; j < data_size; j++) {
      printf("%02x", output0[j]);
      if (j < data_size - 1)
        printf(" ");
    }
    printf("] Share1=[");
    for (int j = 0; j < data_size; j++) {
      printf("%02x", output1[j]);
      if (j < data_size - 1)
        printf(" ");
    }
    printf("] Sum=[");
    bool all_zero = true;
    for (int j = 0; j < data_size; j++) {
      uint8_t sum = output0[j] ^ output1[j];
      printf("%02x", sum);
      if (j < data_size - 1)
        printf(" ");
      if (sum != 0)
        all_zero = false;
    }
    printf("] %s\n", all_zero ? "✓ ZERO" : "✗ NON-ZERO");
  }

  printf("\nTest completed!\n");

  // Test full domain evaluation
  printf("\nTesting full domain evaluation:\n");
  printf("-------------------------------\n");

  size_t full_domain_size = 1ULL << domain_size;
  uint8_t *full_output0 = malloc(full_domain_size * data_size);
  uint8_t *full_output1 = malloc(full_domain_size * data_size);

  printf("Evaluating DMPF over full domain (size: %zu)...\n", full_domain_size);

  fullDomainBigStateDMPF(ctx, k0, data_size, full_output0);
  fullDomainBigStateDMPF(ctx, k1, data_size, full_output1);

  printf("Full domain evaluation completed!\n");

  // Verify that input points have correct values
  printf("Verifying input points in full domain output:\n");
  bool all_correct = true;

  for (uint64_t i = 0; i < num_inputs; i++) {
    uint64_t input_idx = inputs[i];
    if (input_idx >= full_domain_size) {
      printf("Warning: Input %lu exceeds domain size\n", input_idx);
      continue;
    }

    printf("  Input %lu: Expected=[", input_idx);
    for (int j = 0; j < data_size; j++) {
      printf("%02x", test_data[i * data_size + j]);
      if (j < data_size - 1)
        printf(" ");
    }
    printf("] Actual=[");

    bool point_correct = true;
    for (int j = 0; j < data_size; j++) {
      uint8_t actual = full_output0[input_idx * data_size + j] ^
                       full_output1[input_idx * data_size + j];
      printf("%02x", actual);
      if (j < data_size - 1)
        printf(" ");

      if (actual != test_data[i * data_size + j]) {
        point_correct = false;
        all_correct = false;
      }
    }
    printf("] %s\n", point_correct ? "✓ CORRECT" : "✗ INCORRECT");
  }

  // Verify that non-input points are zero
  printf("Verifying random non-input points are zero:\n");
  uint64_t sample_points[] = {0, 15, 25, 100, 128, 200, 255};
  size_t num_samples = sizeof(sample_points) / sizeof(sample_points[0]);

  for (size_t i = 0; i < num_samples; i++) {
    uint64_t point = sample_points[i];
    if (point >= full_domain_size)
      continue;

    // Check if this is an input point
    bool is_input = false;
    for (uint64_t j = 0; j < num_inputs; j++) {
      if (point == inputs[j]) {
        is_input = true;
        break;
      }
    }
    if (is_input)
      continue;

    printf("  Point %lu: [", point);
    bool is_zero = true;
    for (int j = 0; j < data_size; j++) {
      uint8_t actual = full_output0[point * data_size + j] ^
                       full_output1[point * data_size + j];
      printf("%02x", actual);
      if (j < data_size - 1)
        printf(" ");

      if (actual != 0) {
        is_zero = false;
        all_correct = false;
      }
    }
    printf("] %s\n", is_zero ? "✓ ZERO" : "✗ NON-ZERO");
  }

  printf("\nFull domain test %s!\n", all_correct ? "PASSED" : "FAILED");

  free(full_output0);
  free(full_output1);

  printf("\nAll tests completed!\n");

  // Cleanup
  free(output0);
  free(output1);
  free(k0);
  free(k1);

  // Free test data
  free(test_data);

  destroyContext(ctx);

  return 0;
}