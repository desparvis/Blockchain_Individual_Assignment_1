#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define MAX_STUDENTS 100

// Student Registry Structure
typedef struct {
    char student_id[20];
    char full_name[50];
    char course_code[10];
} Student;

// Blockchain Block Structure
typedef struct Block {
    int index;
    time_t timestamp;
    char student_id[20];
    char full_name[50];
    char course_code[10];
    char status[10];
    char previous_hash[65];
    unsigned char signature[72]; // DER-encoded ECDSA signature
    int signature_len;           // Length of the generated signature
    char hash[65];
    struct Block* next;          // Linked list pointer
} Block;

// Global State Variables
Student student_registry[MAX_STUDENTS];
int student_count = 0;
Block* blockchain_head = NULL;
Block* blockchain_tail = NULL;

// Cryptographic Keys (Global for application simulation convenience)
EVP_PKEY* private_key = NULL;
EVP_PKEY* public_key = NULL;

// --- CRYPTOGRAPHIC UTILITIES ---

// Helper function to generate an EC keypair (P-256 curve) for ECDSA signatures
int generate_crypto_keys() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) return 0;
    
    // Use the standard secp256r1 (NIST P-256) curve
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) return 0;
    if (EVP_PKEY_keygen(ctx, &private_key) <= 0) return 0;
    
    // Extract public key component for validation
    public_key = EVP_PKEY_dup(private_key);
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

// Computes the SHA-256 hash of a block's core data fields combined
void calculate_block_hash(Block* block, char* output_hash) {
    char input_buffer[2048];
    unsigned char raw_hash[SHA256_DIGEST_LENGTH];

    // Combine all fields except the block's own hash and signature
    snprintf(input_buffer, sizeof(input_buffer), "%d%ld%s%s%s%s%s",
             block->index, (long)block->timestamp, block->student_id,
             block->full_name, block->course_code, block->status, block->previous_hash);

    SHA256((unsigned char*)input_buffer, strlen(input_buffer), raw_hash);

    // Convert raw bytes to a 64-character hexadecimal string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&output_hash[i * 2], "%02x", raw_hash[i]);
    }
    output_hash[64] = '\0';
}

// Signs the block's hash using the private key (ECDSA)
int sign_block_data(Block* block) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    size_t sig_len = 72; // Maximum signature size for ECDSA P-256

    if (!md_ctx || EVP_SignInit(md_ctx, EVP_sha256()) <= 0) return 0;
    if (EVP_SignUpdate(md_ctx, block->hash, strlen(block->hash)) <= 0) return 0;
    if (EVP_SignFinal(md_ctx, block->signature, (unsigned int*)&sig_len, private_key) <= 0) return 0;

    block->signature_len = (int)sig_len;
    EVP_MD_CTX_free(md_ctx);
    return 1;
}

// Verifies the block's signature using the public key
int verify_block_signature(Block* block) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx || EVP_VerifyInit(md_ctx, EVP_sha256()) <= 0) return 0;
    if (EVP_VerifyUpdate(md_ctx, block->hash, strlen(block->hash)) <= 0) return 0;
    
    int result = EVP_VerifyFinal(md_ctx, block->signature, block->signature_len, public_key);
    EVP_MD_CTX_free(md_ctx);
    return (result == 1); // Returns 1 if authentic, 0 if invalid/tampered
}

// --- CORE SYSTEM FUNCTIONS ---

// Load data from students.txt into memory
int load_student_registry(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("\n[-] ERROR: Student registry file '%s' is missing!\n", filename);
        return 0;
    }

    char line[120];
    student_count = 0;

    while (fgets(line, sizeof(line), file) && student_count < MAX_STUDENTS) {
        line[strcspn(line, "\r\n")] = 0; // Strip newlines
        if (strlen(line) == 0) continue;

        char* token = strtok(line, ",");
        if (token) strcpy(student_registry[student_count].student_id, token);

        token = strtok(NULL, ",");
        if (token) strcpy(student_registry[student_count].full_name, token);

        token = strtok(NULL, ",");
        if (token) strcpy(student_registry[student_count].course_code, token);

        student_count++;
    }
    fclose(file);

    if (student_count == 0) {
        printf("\n[-] ERROR: Student registry file is empty!\n");
        return 0;
    }
    printf("[+] Successfully loaded %d students from registry.\n", student_count);
    return 1;
}

// Looks up a student ID in memory
Student* lookup_student(const char* id) {
    for (int i = 0; i < student_count; i++) {
        if (strcmp(student_registry[i].student_id, id) == 0) {
            return &student_registry[i];
        }
    }
    return NULL;
}

// Builds the structural Genesis Block (Index 0)
void create_genesis_block() {
    Block* genesis = (Block*)malloc(sizeof(Block));
    genesis->index = 0;
    genesis->timestamp = time(NULL);
    strcpy(genesis->student_id, "SYSTEM_GENESIS");
    strcpy(genesis->full_name, "Genesis Block");
    strcpy(genesis->course_code, "NONE");
    strcpy(genesis->status, "SYSTEM");
    
    // 64 Zeros as designated by instructions
    memset(genesis->previous_hash, '0', 64);
    genesis->previous_hash[64] = '\0';

    calculate_block_hash(genesis, genesis->hash);
    
    // Sign the genesis block
    sign_block_data(genesis);

    genesis->next = NULL;
    blockchain_head = genesis;
    blockchain_tail = genesis;
    printf("[+] Genesis Block initialized successfully.\n");
}

// Adds an authentic record to the chain after looking up student ID
void mark_attendance(const char* id, const char* status) {
    Student* student = lookup_student(id);
    if (!student) {
        printf("\n[-] ERROR: Student ID not found! Aborting block creation.\n");
        return;
    }

    Block* new_block = (Block*)malloc(sizeof(Block));
    new_block->index = blockchain_tail->index + 1;
    new_block->timestamp = time(NULL);
    strcpy(new_block->student_id, student->student_id);
    strcpy(new_block->full_name, student->full_name);
    strcpy(new_block->course_code, student->course_code);
    strcpy(new_block->status, status);
    
    // Link to previous block's hash string
    strcpy(new_block->previous_hash, blockchain_tail->hash);

    // Compute cryptographic identity
    calculate_block_hash(new_block, new_block->hash);
    
    // Generate digital authentication signature
    if (!sign_block_data(new_block)) {
        printf("[-] ERROR: Cryptographic signing failed.\n");
        free(new_block);
        return;
    }

    new_block->next = NULL;
    blockchain_tail->next = new_block;
    blockchain_tail = new_block;

    printf("[+] Attendance tracked successfully in Block #%d!\n", new_block->index);
}

// Iterates through entire list validating cryptographic linkages and signatures
int validate_blockchain() {
    Block* current = blockchain_head;
    Block* prev = NULL;
    int index = 0;

    while (current != NULL) {
        // 1. Recalculate hash to detect structural modification
        char recomputed_hash[65];
        calculate_block_hash(current, recomputed_hash);
        if (strcmp(current->hash, recomputed_hash) != 0) {
            printf("\n TAMPER DETECTED: Block #%d data has been modified!\n", index);
            printf("    Expected Hash: %s\n", current->hash);
            printf("    Calculated Hash: %s\n", recomputed_hash);
            return 0;
        }

        // 2. Verify historical chain linkage continuity
        if (prev != NULL) {
            if (strcmp(current->previous_hash, prev->hash) != 0) {
                printf("\n TAMPER DETECTED: Chain broken at Block #%d! Previous hash pointer mismatch.\n", index);
                return 0;
            }
        }

        // 3. Cryptographically check signature validity
        if (!verify_block_signature(current)) {
            printf("\n TAMPER DETECTED: Block #%d contains an invalid digital signature!\n", index);
            return 0;
        }

        prev = current;
        current = current->next;
        index++;
    }
    return 1;
}

// Prints the entire ledger out to terminal readable formatting
void view_records() {
    Block* current = blockchain_head;
    printf("\n======================= ATTENDANCE BLOCKCHAIN LEDGER =======================\n");
    while (current != NULL) {
        char time_str[26];
        struct tm* tm_info = localtime(&current->timestamp);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

        printf("Block Record #%d\n", current->index);
        printf("  Timestamp:   %s\n", time_str);
        printf("  Student ID:  %s\n", current->student_id);
        printf("  Full Name:   %s\n", current->full_name);
        printf("  Course Code: %s\n", current->course_code);
        printf("  Status:      %s\n", current->status);
        printf("  Prev Hash:   %s\n", current->previous_hash);
        printf("  Block Hash:  %s\n", current->hash);
        printf("  Signature:   [Validated %d Bytes DER Stream]\n", current->signature_len);
        printf("----------------------------------------------------------------------------\n");
        current = current->next;
    }
}

// Purposefully tampers with a past record data to break integrity check
void execute_tamper_simulation() {
    if (blockchain_head == NULL || blockchain_head->next == NULL) {
        printf("\n[-] Please add at least one valid attendance block before testing tampering.\n");
        return;
    }
    // Target Block 1 (the first real attendance block after Genesis)
    Block* target = blockchain_head->next;
    printf("\n[!] Maliciously changing Block #%d status from '%s' to 'PRESENT'...\n", target->index, target->status);
    strcpy(target->status, "PRESENT"); 
    printf("[+] Modification executed. Re-run chain validation to see results.\n");
}

// Free allocated memory on close
void cleanup_memory() {
    Block* current = blockchain_head;
    while (current != NULL) {
        Block* next = current->next;
        free(current);
        current = next;
    }
    if (private_key) EVP_PKEY_free(private_key);
    if (public_key) EVP_PKEY_free(public_key);
}

// --- CLI INTERFACE ENTRY POINT ---
int main() {
    printf("=== INITIALIZING BLOCKCHAIN ATTENDANCE TRACKING SYSTEM ===\n");
    
    // Setup keys and registry
    if (!generate_crypto_keys()) {
        printf("[-] Critical initialization failure: Keypair generation failed.\n");
        return 1;
    }
    
    if (!load_student_registry("students.txt")) {
        return 1;
    }

    create_genesis_block();

    int choice;
    char id_input[20];
    char status_input[10];

    while (1) {
        printf("\n--- CORE MANAGEMENT MENU ---\n");
        printf("1. Mark Attendance Record\n");
        printf("2. View Complete Ledger Records\n");
        printf("3. Validate Entire Chain Integrity\n");
        printf("4. Simulate Malicious Data Tampering\n");
        printf("5. Exit Application\n");
        printf("Select an option (1-5): ");
        
        if (scanf("%d", &choice) != 1) {
            printf("Invalid input type entered.\n");
            break;
        }

        switch (choice) {
            case 1:
                printf("Enter Student ID (e.g., ALU001): ");
                scanf("%s", id_input);
                printf("Enter Status (PRESENT, ABSENT, LATE): ");
                scanf("%s", status_input);
                mark_attendance(id_input, status_input);
                break;
            case 2:
                view_records();
                break;
            case 3:
                printf("\n[*] Scanning blockchain integrity...\n");
                if (validate_blockchain()) {
                    printf(" SUCCESS: Blockchain is completely valid. Every signature matches and hashes are unbroken.\n");
                }
                break;
            case 4:
                execute_tamper_simulation();
                break;
            case 5:
                printf("Shutting down core system safely.\n");
                cleanup_memory();
                return 0;
            default:
                printf("Invalid selection choice. Try again.\n");
        }
    }

    cleanup_memory();
    return 0;
}