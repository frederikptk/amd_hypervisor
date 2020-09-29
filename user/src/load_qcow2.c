#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <byteswap.h>

struct __attribute__ ((__packed__)) qcowheader {
    uint32_t magic;
    uint32_t version;
    uint64_t backing_file_offset;
    uint32_t backing_file_size;
    uint32_t cluster_bits;
    uint64_t size;
    uint32_t crypt_method;
    uint32_t l1_size;
    uint64_t l1_table_offset;
    uint64_t refcount_table_offset;
    uint32_t refcount_table_clusters;
    uint32_t nb_snapshots;
    uint64_t snapshots_offset;
    uint64_t incompatible_features;
    uint64_t compatible_features;
    uint64_t autoclear_features;
    uint32_t refcount_order;
    uint32_t header_length;
    uint8_t compression_type;
    uint8_t padding[7];
} typedef qcowheader;

int main(int argc, char** argv) {
    FILE*           fp;
    qcowheader      header;

    if (argc < 2) {
        printf("Provide a path to a qcow2 file!\n");
        return EXIT_FAILURE;
    }

    fp = fopen(argv[1], "r+b");
	if (fp == NULL) {
		printf("Cannot open file\n");
		return EXIT_FAILURE;
	}

    if (fread(&header, sizeof(qcowheader), 1, fp) != 1) {
		printf("Could not read qcow2 header\n");
		return EXIT_FAILURE;
	}

    printf("Snapshots offset in file: 0x%lx\n", __bswap_64(header.snapshots_offset));
    printf("Snapshots count in file: 0x%lx\n", __bswap_32(header.nb_snapshots));
    printf("L1 table offset in file: 0x%lx\n", __bswap_64(header.l1_table_offset));
    printf("L1 table size in file: 0x%lx\n", __bswap_32(header.l1_size));
}