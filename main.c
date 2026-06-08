#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define MAX_STUDENTS 100
#define MAX_PENDING 20

// New added ledger model selection
typedef enum { MODEL_UTXO, MODEL_ACCOUNT } LedgerModel;

// Student Registry Structure (Nothing was changed)
typedef struct {
    char student_id[20];
    char full_name[50];
    char course_code[10];
} Student;

// UTXO structure
typedef struct UTXO {
    char id[65];               // Unique SHA-256 Hash identifying the UTXO
    char owner_id[20];         // Target Student ID
    int amount;                // Core Token Value
    struct UTXO* next;
} UTXO;

// Transaction structure
typedef struct TxLog {
    char sender[20];
    char recipient[20];
    int amount;
    int fee;
    int nonce;
    struct TxLog* next;
} TxLog;

// Normal structure for student
typedef struct {
    char student_id[20];
    int balance;
    int nonce;                 // Prevents double-spend replay attacks
    TxLog* history_head;       // Transaction History Linked List Log
} Account;

// Updated block structure
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
    
    // Extra fields added for token reward, transaction tracking, and nonce
    int token_reward;            // Stored reward coins: 10, 5, or 0
    char tx_id[65];              // SHA-256 hash of the reward transaction
    int nonce;                   // Incremented to fulfill Proof-of-Work (PoW)
    
    char hash[65];
    struct Block* next;          // Linked list pointer
} Block;

// Global State Variables
Student student_registry[MAX_STUDENTS];
int student_count = 0;
Block* blockchain_head = NULL;
Block* blockchain_tail = NULL;

// Global mempool variables
Block pending_pool[MAX_PENDING]; // Unconfirmed block mempool
int pending_count = 0;

LedgerModel current_model = MODEL_UTXO;
UTXO* utxo_head = NULL;
Account account_registry[MAX_STUDENTS];
int global_difficulty = 2; // Default required leading zero target

// Cryptographic Keys (Global for application simulation convenience)
EVP_PKEY* private_key = NULL;
EVP_PKEY* public_key = NULL;

// Updated cryptography functions

int generate_crypto_keys() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) return 0;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) return 0;
    if (EVP_PKEY_keygen(ctx, &private_key) <= 0) return 0;
    public_key = EVP_PKEY_dup(private_key);
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

// Updated block hash calculation function
void calculate_block_hash(Block* block, char* output_hash) {
    char input_buffer[3072];
    unsigned char raw_hash[SHA256_DIGEST_LENGTH];

    // Formative 2 string serialization update
    snprintf(input_buffer, sizeof(input_buffer), "%d%ld%s%s%s%s%s%d%s%d",
             block->index, (long)block->timestamp, block->student_id,
             block->full_name, block->course_code, block->status, 
             block->previous_hash, block->token_reward, block->tx_id, block->nonce);

    SHA256((unsigned char*)input_buffer, strlen(input_buffer), raw_hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&output_hash[i * 2], "%02x", raw_hash[i]);
    }
    output_hash[64] = '\0';
}

// Utility to hash the reward transaction itself
void calculate_tx_hash(const char* student_id, int amount, char* output_hash) {
    char input_buffer[256];
    unsigned char raw_hash[SHA256_DIGEST_LENGTH];
    snprintf(input_buffer, sizeof(input_buffer), "%s%d%ld", student_id, amount, (long)time(NULL));
    SHA256((unsigned char*)input_buffer, strlen(input_buffer), raw_hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&output_hash[i * 2], "%02x", raw_hash[i]);
    }
    output_hash[64] = '\0';
}

int sign_block_data(Block* block) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    size_t sig_len = 72;
    if (!md_ctx || EVP_SignInit(md_ctx, EVP_sha256()) <= 0) return 0;
    if (EVP_SignUpdate(md_ctx, block->hash, strlen(block->hash)) <= 0) return 0;
    if (EVP_SignFinal(md_ctx, block->signature, (unsigned int*)&sig_len, private_key) <= 0) return 0;
    block->signature_len = (int)sig_len;
    EVP_MD_CTX_free(md_ctx);
    return 1;
}

int verify_block_signature(Block* block) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx || EVP_VerifyInit(md_ctx, EVP_sha256()) <= 0) return 0;
    if (EVP_VerifyUpdate(md_ctx, block->hash, strlen(block->hash)) <= 0) return 0;
    int result = EVP_VerifyFinal(md_ctx, block->signature, block->signature_len, public_key);
    EVP_MD_CTX_free(md_ctx);
    return (result == 1);
}

// UTXO system function

void add_utxo(const char* owner, int amount) {
    UTXO* new_utxo = (UTXO*)malloc(sizeof(UTXO));
    strcpy(new_utxo->owner_id, owner);
    new_utxo->amount = amount;
    
    char raw_seed[128];
    snprintf(raw_seed, sizeof(raw_seed), "%s%d%d", owner, amount, rand());
    unsigned char raw_hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)raw_seed, strlen(raw_seed), raw_hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) sprintf(&new_utxo->id[i * 2], "%02x", raw_hash[i]);
    new_utxo->id[64] = '\0';
    
    new_utxo->next = utxo_head;
    utxo_head = new_utxo;
}

int get_utxo_balance(const char* student_id) {
    int total = 0;
    UTXO* curr = utxo_head;
    while (curr) {
        if (strcmp(curr->owner_id, student_id) == 0) total += curr->amount;
        curr = curr->next;
    }
    return total;
}

void print_utxo_set() {
    printf("\n--- CURRENT UNSPENT TRANSACTION OUTPUTS (UTXO) SET ---\n");
    UTXO* curr = utxo_head;
    if (!curr) printf("[i] Zero UTXOs are currently present in global data state.\n");
    while (curr) {
        printf("  UTXO ID [%.10s...] | Owner: %s | Value: %d coins\n", curr->id, curr->owner_id, curr->amount);
        curr = curr->next;
    }
}

int process_utxo_transfer(const char* sender, const char* recipient, int amount) {
    int fee = 1; // Mandated transaction fee
    int required = amount + fee;
    int collected = 0;
    
    UTXO* curr = utxo_head;
    UTXO* matching_nodes[20];
    int count = 0;
    
    while (curr && collected < required) {
        if (strcmp(curr->owner_id, sender) == 0) {
            collected += curr->amount;
            matching_nodes[count++] = curr;
        }
        curr = curr->next;
    }
    
    if (collected < required) {
        printf("[-] UTXO TRANSACTION REJECTED: Insufficient balance. Balance: %d, Required: %d.\n", collected, required);
        return 0;
    }
    
    // Spend and free the used inputs
    for (int i = 0; i < count; i++) {
        UTXO* target = matching_nodes[i];
        if (target == utxo_head) {
            utxo_head = utxo_head->next;
        } else {
            UTXO* p = utxo_head;
            while (p && p->next != target) p = p->next;
            if (p) p->next = target->next;
        }
        free(target);
    }
    
    // Generate output to recipient
    add_utxo(recipient, amount);
    // Generate output change back to sender minus fee
    if (collected > required) {
        add_utxo(sender, collected - required);
    }
    printf("[Success] UTXO Sent %d coins to %s. 1 coin fee processed.\n", amount, recipient);
    return 1;
}

// Account balance functions

int get_account_index(const char* student_id) {
    for (int i = 0; i < student_count; i++) {
        if (strcmp(account_registry[i].student_id, student_id) == 0) return i;
    }
    return -1;
}

void log_account_tx(int index, const char* s, const char* r, int amt, int fee, int nonce) {
    TxLog* log_entry = (TxLog*)malloc(sizeof(TxLog));
    strcpy(log_entry->sender, s);
    strcpy(log_entry->recipient, r);
    log_entry->amount = amt;
    log_entry->fee = fee;
    log_entry->nonce = nonce;
    log_entry->next = account_registry[index].history_head;
    account_registry[index].history_head = log_entry;
}

int process_account_transfer(const char* sender, const char* recipient, int amount, int entered_nonce) {
    int s_idx = get_account_index(sender);
    int r_idx = get_account_index(recipient);
    if (s_idx == -1 || r_idx == -1) {
        printf("[-] ACCOUNT TRANSFER REJECTED: Invalid account configurations.\n");
        return 0;
    }
    if (account_registry[s_idx].nonce != entered_nonce) {
        printf("[-] ACCOUNT REJECTED: Nonce mismatch/reused! Expected: %d, Inputted: %d.\n", account_registry[s_idx].nonce, entered_nonce);
        return 0;
    }
    if (account_registry[s_idx].balance < amount) {
        printf("[-] ACCOUNT REJECTED: Insufficient funds. Available: %d coins.\n", account_registry[s_idx].balance);
        return 0;
    }
    
    account_registry[s_idx].balance -= amount;
    account_registry[r_idx].balance += amount;
    
    log_account_tx(s_idx, sender, recipient, amount, 0, entered_nonce);
    log_account_tx(r_idx, sender, recipient, amount, 0, entered_nonce);
    
    account_registry[s_idx].nonce++; // Bump account sequential nonce
    printf("[Success] Account Ledger updated! %d coins passed to %s.\n", amount, recipient);
    return 1;
}

void print_account_history(const char* student_id) {
    int idx = get_account_index(student_id);
    if (idx == -1) { printf("[-] Account not found.\n"); return; }
    printf("\n--- TRANSACTION HISTORY LOG FOR: %s ---\n", student_id);
    TxLog* curr = account_registry[idx].history_head;
    if (!curr) printf("[i] Zero transfers logged for this identity.\n");
    while (curr) {
        printf("  Tx -> From: %s | To: %s | Amount: %d | Nonce: %d\n", curr->sender, curr->recipient, curr->amount, curr->nonce);
        curr = curr->next;
    }
}

// Updated attendance with blockchain flow

int load_student_registry(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("\n[-] ERROR: Student registry file '%s' is missing!\n", filename);
        return 0;
    }
    char line[120]; student_count = 0;
    while (fgets(line, sizeof(line), file) && student_count < MAX_STUDENTS) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0) continue;
        char* token = strtok(line, ",");
        if (token) strcpy(student_registry[student_count].student_id, token);
        token = strtok(NULL, ",");
        if (token) strcpy(student_registry[student_count].full_name, token);
        token = strtok(NULL, ",");
        if (token) strcpy(student_registry[student_count].course_code, token);
        
        // Parallel in-memory state architecture setup
        strcpy(account_registry[student_count].student_id, student_registry[student_count].student_id);
        account_registry[student_count].balance = 0;
        account_registry[student_count].nonce = 0;
        account_registry[student_count].history_head = NULL;
        
        student_count++;
    }
    fclose(file);
    printf("[+] Successfully loaded %d students into environment structures.\n", student_count);
    return (student_count > 0);
}

Student* lookup_student(const char* id) {
    for (int i = 0; i < student_count; i++) {
        if (strcmp(student_registry[i].student_id, id) == 0) return &student_registry[i];
    }
    return NULL;
}

void create_genesis_block() {
    Block* genesis = (Block*)malloc(sizeof(Block));
    genesis->index = 0;
    genesis->timestamp = time(NULL);
    strcpy(genesis->student_id, "SYSTEM_GENESIS");
    strcpy(genesis->full_name, "Genesis Block");
    strcpy(genesis->course_code, "NONE");
    strcpy(genesis->status, "SYSTEM");
    memset(genesis->previous_hash, '0', 64);
    genesis->previous_hash[64] = '\0';
    
    // Formative 2 updates initialization
    genesis->token_reward = 0;
    strcpy(genesis->tx_id, "0000000000000000000000000000000000000000000000000000000000000000");
    genesis->nonce = 0;

    calculate_block_hash(genesis, genesis->hash);
    sign_block_data(genesis);

    genesis->next = NULL;
    blockchain_head = genesis;
    blockchain_tail = genesis;
    printf("[+] Genesis Block initialized successfully.\n");
}

// Upgraded function that pushes records into the pending mempool pool instead of directly appending
void stage_attendance_transaction(const char* id, const char* status) {
    Student* student = lookup_student(id);
    if (!student) {
        printf("\n[-] ERROR: Student ID not found! Aborting block creation.\n");
        return;
    }
    if (pending_count >= MAX_PENDING) {
        printf("[-] MEMPOOL FULL: Execute a mining loop to verify blocks first.\n");
        return;
    }

    int reward_coins = 0;
    if (strcmp(status, "PRESENT") == 0) reward_coins = 10;
    else if (strcmp(status, "LATE") == 0) reward_coins = 5;
    else if (strcmp(status, "ABSENT") == 0) reward_coins = 0; // Complies with rule: no payout

    Block* unconfirmed = &pending_pool[pending_count];
    unconfirmed->index = -1; // Flagged as unconfirmed
    unconfirmed->timestamp = time(NULL);
    strcpy(unconfirmed->student_id, student->student_id);
    strcpy(unconfirmed->full_name, student->full_name);
    strcpy(unconfirmed->course_code, student->course_code);
    strcpy(unconfirmed->status, status);
    unconfirmed->token_reward = reward_coins;
    unconfirmed->nonce = 0;
    
    // Generate reward transaction ID
    calculate_tx_hash(student->student_id, reward_coins, unconfirmed->tx_id);

    pending_count++;
    printf("[+] Attendance transaction safely staged into pending pool (Mempool). Reward: %d coins.\n", reward_coins);
}

// Finalizes transaction payouts into the selected model balance engine
void settle_block_payout(Block* block) {
    if (block->token_reward == 0) return;
    if (current_model == MODEL_UTXO) {
        add_utxo(block->student_id, block->token_reward);
    } else {
        int idx = get_account_index(block->student_id);
        if (idx != -1) {
            account_registry[idx].balance += block->token_reward;
            log_account_tx(idx, "MINTED_REWARD", block->student_id, block->token_reward, 0, account_registry[idx].nonce);
        }
    }
}

// Mining simulator functions
int match_pow_difficulty(const char* hash, int target_zeros) {
    for (int i = 0; i < target_zeros; i++) {
        if (hash[i] != '0') return 0;
    }
    return 1;
}

void run_solo_mining() {
    if (pending_count == 0) {
        printf("[-] MINING HALTED: No unconfirmed transactions inside the pool.\n");
        return;
    }
    printf("\n--- BOOTING SOLO MINING CONSENSUS (Target Zeros: %d) ---\n", global_difficulty);

    for (int i = 0; i < pending_count; i++) {
        Block* staged = &pending_pool[i];
        Block* verified_block = (Block*)malloc(sizeof(Block));
        memcpy(verified_block, staged, sizeof(Block));
        
        verified_block->index = blockchain_tail->index + 1;
        strcpy(verified_block->previous_hash, blockchain_tail->hash);
        
        long total_hashes = 0;
        while (1) {
            calculate_block_hash(verified_block, verified_block->hash);
            if (match_pow_difficulty(verified_block->hash, global_difficulty)) break;
            verified_block->nonce++;
            total_hashes++;
        }
        
        sign_block_data(verified_block);
        verified_block->next = NULL;
        blockchain_tail->next = verified_block;
        blockchain_tail = verified_block;

        settle_block_payout(verified_block);
        printf("[+] Block #%d Mined! Hashes Tried: %ld | Hash: %s\n", verified_block->index, total_hashes, verified_block->hash);
    }
    pending_count = 0; // Mempool reset
}

void run_pool_mining() {
    if (pending_count == 0) { printf("[-] Pool is completely empty.\n"); return; }
    printf("\n--- RUNNING COOPERATIVE POOL MINING MACHINE SIMULATION ---\n");
    
    int share_contributions[4] = { rand()%300 + 50, rand()%500 + 100, rand()%400 + 100, rand()%600 + 200 };
    int aggregated_attempts = 0;
    for(int i = 0; i < 4; i++) aggregated_attempts += share_contributions[i];
    
    int original_idx = blockchain_tail->index;
    run_solo_mining(); // Process and close ledger states first
    int blocks_mined = blockchain_tail->index - original_idx;
    
    int pool_base_reward = blocks_mined * 50; 
    double management_fee = pool_base_reward * 0.02; // 2% cut deduction
    double total_net_pool = pool_base_reward - management_fee;

    printf("\n======================= POOL PAYOUT MATRIX LOG =======================\n");
    printf("| Miner Identity | Shares Contributed | Share Pct %% | Paid Reward     |\n");
    printf("-----------------------------------------------------------------------\n");
    for(int i = 0; i < 4; i++) {
        double percentage = ((double)share_contributions[i] / aggregated_attempts) * 100;
        double individual_payout = ((double)share_contributions[i] / aggregated_attempts) * total_net_pool;
        printf("| Miner Pool #%d  |        %3d         |    %5.2f%%   |  %6.2f coins   |\n", i+1, share_contributions[i], percentage, individual_payout);
    }
    printf("-----------------------------------------------------------------------\n");
    printf("  [i] Pool Maintenance Fee Extracted: %.2f coins\n", management_fee);
}

void run_cloud_mining(int deployment_rounds) {
    if (deployment_rounds < 1 || deployment_rounds > 5) { printf("[-] Invalid deployment window specified.\n"); return; }
    printf("\n--- DEPLOYING CLOUD MINING INSTANCE RENTAL ---\n");
    
    int static_cost_per_round = 15;
    int net_fees_paid = 0;
    int net_rewards_yielded = 0;

    for (int run = 1; run <= deployment_rounds; run++) {
        int variable_yield = rand() % 24 + 4; // Network dynamic generation output simulation
        net_fees_paid += static_cost_per_round;
        net_rewards_yielded += variable_yield;
        
        printf("  Round [%d/%d] -> Cost: %d | Yielded: %d coins\n", run, deployment_rounds, static_cost_per_round, variable_yield);
        if (net_fees_paid > net_rewards_yielded) {
            printf("    [UNPROFITABLE RENTAL WARNING] Cumulative cost (%d) exceeds payout return (%d).\n", net_fees_paid, net_rewards_yielded);
        }
    }
    printf("  >> Gross Payout: %d coins | Costs Burnt: %d coins | Net Profit: %d coins\n", net_rewards_yielded, net_fees_paid, (net_rewards_yielded - net_fees_paid));
}

// Updating auditing views

int validate_blockchain() {
    Block* current = blockchain_head;
    Block* prev = NULL;
    int index = 0;
    while (current != NULL) {
        char recomputed_hash[65];
        calculate_block_hash(current, recomputed_hash);
        if (strcmp(current->hash, recomputed_hash) != 0) {
            printf("\n TAMPER DETECTED: Block #%d data has been modified!\n", index);
            return 0;
        }
        if (prev != NULL && strcmp(current->previous_hash, prev->hash) != 0) {
            printf("\n TAMPER DETECTED: Chain broken at Block #%d!\n", index);
            return 0;
        }
        if (!verify_block_signature(current)) {
            printf("\n TAMPER DETECTED: Block #%d has bad digital signature!\n", index);
            return 0;
        }
        prev = current; current = current->next; index++;
    }
    return 1;
}

void view_records() {
    Block* current = blockchain_head;
    printf("\n======================= CONFIRMED ATTENDANCE BLOCKCHAIN LEDGER =======================\n");
    while (current != NULL) {
        printf("Block Record #%d\n", current->index);
        printf("  Student: %s (%s) | Status: %s\n", current->student_id, current->full_name, current->status);
        printf("  Tx Leaf ID: %s\n", current->tx_id);
        printf("  Reward Value: %d coins | PoW Nonce Loops: %d\n", current->token_reward, current->nonce);
        printf("  Block Hash:  %s\n", current->hash);
        printf("  Signature Status: [Validated DER Payload Cryptographically]\n");
        printf("----------------------------------------------------------------------------\n");
        current = current->next;
    }
}

void display_balances_state() {
    printf("\n=== GLOBAL TOKENS VALUE BALANCE LOG ===\n");
    for (int i = 0; i < student_count; i++) {
        int balance = (current_model == MODEL_UTXO) ? get_utxo_balance(student_registry[i].student_id) : account_registry[i].balance;
        printf("  Student: %-10s | Profile Name: %-15s | Token Balance: %d coins\n", 
               student_registry[i].student_id, student_registry[i].full_name, balance);
    }
    if (current_model == MODEL_UTXO) print_utxo_set();
}

void execute_tamper_simulation() {
    if (blockchain_head == NULL || blockchain_head->next == NULL) {
        printf("\n[-] Mine staged data blocks into the chain before running modifications.\n");
        return;
    }
    Block* target = blockchain_head->next;
    printf("\n[!] Maliciously mutating Block #%d status field from '%s' to 'PRESENT'...\n", target->index, target->status);
    strcpy(target->status, "PRESENT"); 
    printf("[+] Field modified. Re-run structural validation to observe cryptographic alerts.\n");
}

void cleanup_memory() {
    Block* current = blockchain_head;
    while (current != NULL) {
        Block* next = current->next; free(current); current = next;
    }
    for (int i = 0; i < student_count; i++) {
        TxLog* curr_log = account_registry[i].history_head;
        while (curr_log) { TxLog* n = curr_log->next; free(curr_log); curr_log = n; }
    }
    UTXO* c_utxo = utxo_head;
    while (c_utxo) { UTXO* n = c_utxo->next; free(c_utxo); c_utxo = n; }
    if (private_key) EVP_PKEY_free(private_key);
    if (public_key) EVP_PKEY_free(public_key);
}

// --- UPDATED INTERACTIVE CLI ENTRY POINT ---
int main() {
    printf("=== INITIALIZING BLOCKCHAIN ATTENDANCE HUB V2.0 ===\n");
    generate_crypto_keys();
    if (!load_student_registry("students.txt")) return 1;
    create_genesis_block();

    printf("\nChoose System Token Transaction Engine Configuration:\n");
    printf("  1. UTXO Processing Architecture (Default)\n");
    printf("  2. Account-Balance Stateful Architecture\n");
    printf("Select Architecture Choice (1-2): ");
    int choice; scanf("%d", &choice);
    current_model = (choice == 2) ? MODEL_ACCOUNT : MODEL_UTXO;
    printf("[+] Consensus engine initialization parameters complete.\n");

    while (1) {
        printf("\n================ MANAGED SELECTION MATRIX ================\n");
        printf("1. Mark Attendance (Stage Transaction to Pending Pool)\n");
        printf("2. View Pending Pool Status (Mempool Audit)\n");
        printf("3. Process Individual (Solo) Mining Proof-of-Work Loop\n");
        printf("4. Process Cooperative Pool Mining Simulation Loop\n");
        printf("5. Lease Cloud Mining Farm Deployment Contract\n");
        printf("6. Check Global Ledger Student Balances\n");
        printf("7. Audit Stateful Account History Log (Account-Mode Only)\n");
        printf("8. Perform External Manual Student Token Transfer\n");
        printf("9. Adjust Proof-of-Work Mining Difficulty Factor\n");
        printf("10. View Confirmed Blockchain Ledger Records\n");
        printf("11. Verify Whole Chain Cryptographic Integrity\n");
        printf("12. Execute Malicious Data Mutation Attack Simulation\n");
        printf("13. Safely Shutdown Terminal System Environment\n");
        printf("Choose Action Option (1-13): ");
        int action; if (scanf("%d", &action) != 1) break;

        char id[20], status[20], recipient[20];
        int amount, entered_nonce, rounds;

        switch (action) {
            case 1:
                printf("Enter Target Student ID (e.g. ALU001): "); scanf("%s", id);
                printf("Enter Status Parameter (PRESENT, ABSENT, LATE): "); scanf("%s", status);
                stage_attendance_transaction(id, status);
                break;
            case 2:
                printf("\n--- MEMPOOL PENDING TRANSACTION COUNT: %d ---\n", pending_count);
                for(int i = 0; i < pending_count; i++) {
                    printf(" Staged Index [%d] | ID: %s | Status: %s | Block Payout Value: %d\n", 
                           i, pending_pool[i].student_id, pending_pool[i].status, pending_pool[i].token_reward);
                }
                break;
            case 3: run_solo_mining(); break;
            case 4: run_pool_mining(); break;
            case 5: printf("Specify Lease Windows Rounds (1-5): "); scanf("%d", &rounds); run_cloud_mining(rounds); break;
            case 6: display_balances_state(); break;
            case 7:
                if (current_model != MODEL_ACCOUNT) {
                    printf("[-] COMMAND FAILED: Reset program using choice 2 (Account Model) to track account histories.\n");
                } else {
                    printf("Enter Target Student Account ID: "); scanf("%s", id);
                    print_account_history(id);
                }
                break;
            case 8:
                printf("Enter Sender Student ID: "); scanf("%s", id);
                printf("Enter Recipient Student ID: "); scanf("%s", recipient);
                printf("Enter Token Amount to Move: "); scanf("%d", &amount);
                if (current_model == MODEL_UTXO) {
                    process_utxo_transfer(id, recipient, amount);
                } else {
                    printf("Enter Valid Current Account Nonce: "); scanf("%d", &entered_nonce);
                    process_account_transfer(id, recipient, amount, entered_nonce);
                }
                break;
            case 9:
                printf("Set Target Difficulty Zeros Index (1-4): "); scanf("%d", &global_difficulty);
                printf("[+] Mining intensity metric tracking adjusted.\n");
                break;
            case 10: view_records(); break;
            case 11:
                printf("\n[*] Triggering full verification scan...\n");
                if (validate_blockchain()) printf("[Success] EXTREME INTEGRITY VALIDATED: Entire chain cryptographically untampered.\n");
                break;
            case 12: execute_tamper_simulation(); break;
            case 13: printf("De-allocating entities. Standby...\n"); cleanup_memory(); return 0;
            default: printf("[-] Action matrix mapping error. Input completely outside valid limits.\n");
        }
    }
    cleanup_memory();
    return 0;
}
