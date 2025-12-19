#ifdef __linux__

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/md5.h>
#include <pthread.h>
#include <semaphore.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_USUARIOS 50
#define MAX_HILOS 6
#define ARR_LEN(arr) sizeof arr / sizeof arr[0]
#define MAX_PASSWORD_LENGHT 4

struct Account {
    char *user;
    char *password;
    char *hashed_password;
};

struct Thread {
    int id;
    pthread_t *thread;
    sem_t *semaphore;
    sem_t *next_semaphore;
};

struct Account read_next_account();
void setMemAccount(struct Account *account);
void freeAccount(struct Account *account);
char *gen_hash(const char *seed);
int decrypt(struct Account *account);
int createThread(struct Thread *thread);
void *thread_function(void *args);
struct Thread *createThreads(int amount);
int deleteThread(struct Thread *thread);
int deleteThreads(struct Thread *thread, int amount);

FILE *file = NULL;
struct Account read_next_account() {
    struct Account account = {NULL, NULL, NULL};
    setMemAccount(&account);

    char *line = (char *)malloc(sizeof(char[128]));
    if (fgets(line, 128, file) == NULL) {
        if (!feof(file)) {
            freeAccount(&account);
            return account;
        } else {
            freeAccount(&account);
            return account;
        }
    }

    size_t i = 0;
    for (; i < strlen(line); i++) {
        if (line[i] == ':') {
            i += 2;
            break;
        }
        strncat(account.user, &line[i], 1);
    }
    for (; i < strlen(line); i++) {
        if (line[i] == '\n' || line[i] == '\r')
            break;
        strncat(account.hashed_password, &line[i], 1);
    }

    free(line);
    line = NULL;
    return account;
}

void freeAccount(struct Account *account) {
    free(account->user);
    free(account->password);
    free(account->hashed_password);
    account->user = NULL;
    account->password = NULL;
    account->hashed_password = NULL;
}

void setMemAccount(struct Account *account) {
    account->user = (char *)malloc(sizeof(char[128]));
    account->password = (char *)malloc(sizeof(char[MAX_PASSWORD_LENGHT + 1]));
    account->hashed_password = (char *)malloc(sizeof(char[32 + 1]));

    memset(account->user, '\0', 128);
    memset(account->password, '\0', MAX_PASSWORD_LENGHT + 1);
    memset(account->hashed_password, '\0', 32 + 1);
}

char *gen_hash(const char *seed) {
    MD5_CTX context;
    MD5_Init(&context);
    unsigned char digest[MD5_DIGEST_LENGTH];
    char *hash = (char *)malloc(sizeof(char[MD5_DIGEST_LENGTH * 2 + 1]));

    MD5_Update(&context, seed, strlen(seed));
    MD5_Final(digest, &context);

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        snprintf(&hash[i * 2], MD5_DIGEST_LENGTH * 2, "%02x", digest[i]);
    }

    return hash;
}

const char *abecedario = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
int setNextCombination(char *combination) {
    size_t abc_len = strlen(abecedario);

    if (combination[0] == 0) {
        combination[0] = abecedario[0];
        return 0;
    }

    size_t comb_len = strlen(combination);

    for (int i = comb_len - 1; i >= 0; i--) {
        size_t index = strchr(abecedario, combination[i]) - abecedario;

        if (index < abc_len - 1) {
            combination[i] = abecedario[index + 1];
            return 0;
        }

        combination[i] = abecedario[0];
    }

    if (comb_len < MAX_PASSWORD_LENGHT) {
        combination[comb_len] = abecedario[0];
        return 0;
    }

    return 1;
}

int decrypt(struct Account *account) {
    char *combination = (char *)malloc(sizeof(char[MAX_PASSWORD_LENGHT + 1]));
    memset(combination, '\0', MAX_PASSWORD_LENGHT + 1);
    int found = 1;

    while (setNextCombination(combination) == 0) {
        char *hash = gen_hash(combination);
        if (strcmp(account->hashed_password, hash) != 0) {
            free(hash);
            hash = NULL;
            continue;
        }
        free(hash);
        hash = NULL;
        found = 0;
        break;
    }

    memcpy(account->password, combination, strlen(combination));
    free(combination);
    combination = NULL;
    return found;
}

int createThread(struct Thread *thread) {
    thread->id = 0;
    thread->thread = (pthread_t *)malloc(sizeof(pthread_t));
    thread->semaphore = (sem_t *)malloc(sizeof(sem_t));
    thread->next_semaphore = NULL;
    sem_init(thread->semaphore, 0, 0);

    pthread_create(thread->thread, NULL, thread_function, thread);

    return 0;
}

int deleteThread(struct Thread *thread) {
    pthread_join(*(thread->thread), NULL);
    sem_destroy(thread->semaphore);
    thread->thread = NULL;
    thread->semaphore = NULL;
    thread->next_semaphore = NULL;

    return 0;
}

int deleteThreads(struct Thread *thread, int amount) {
    for (size_t i = 0; i < amount; i++) {
        deleteThread(&thread[i]);
    }
    return 0;
}

struct Thread *createThreads(int amount) {
    struct Thread *threads = (struct Thread *)malloc(sizeof(struct Thread[amount]));

    for (size_t i = 0; i < amount; i++) {
        createThread(&threads[i]);
        threads[i].id = i + 1;
    }
    for (size_t i = 0; i < amount; i++) {
        threads[i].next_semaphore = i != amount - 1 ?
            threads[i + 1].semaphore
            : threads[0].semaphore;
    }

    return threads;
}

void *thread_function(void *args) {
    struct Thread *data = (struct Thread *)args;

    while (1) {
        sem_wait(data->semaphore);

        struct Account account = read_next_account();
        if (account.user == NULL) {
            sem_post(data->next_semaphore);
            freeAccount(&account);
            pthread_exit(NULL);
            return NULL;
        }

        sem_post(data->next_semaphore);

        decrypt(&account);
        fprintf(stdout, "%-16s %-4s\n", account.user, account.password);
        freeAccount(&account);
    }

    pthread_exit(NULL);
    return NULL;
}


int main(int argc, char *argv[]) {
    file = fopen("./users.txt", "r");

    int threads_amount = 0;
    if (argc < 2) {
        threads_amount = 6;
        file = fopen("users.txt", "r");
    } else if (argc < 3) {
        threads_amount = atoi(argv[1]);
        file = fopen("users.txt", "r");

        if (threads_amount > MAX_HILOS) return 1;
        if (file == NULL) return 1;
    } else {
        threads_amount = atoi(argv[1]);
        file = fopen(argv[2], "r");

        if (threads_amount > MAX_HILOS) return 1;
        if (file == NULL) return 1;
    }

    struct Thread *threads = createThreads(threads_amount);
    sem_post(threads[0].semaphore);
    deleteThreads(threads, threads_amount);

    free(threads);
    fclose(file);

    return 0;
}
#elif _WIN32

#define _CRT_SECURE_NO_WARNINGS 
#include <windows.h>
#include <wincrypt.h>
#include <process.h> 
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")

#define MAX_USUARIOS 50
#define MAX_HILOS 6
#define MAX_PASSWORD_LENGHT 4
#define MD5_DIGEST_LENGTH 16

struct Account {
    char *user;
    char *password;
    char *hashed_password;
};

struct Thread {
    int id;
    HANDLE thread;
    HANDLE semaphore;
    HANDLE next_semaphore;
};

struct Account read_next_account();
void setMemAccount(struct Account *account);
void freeAccount(struct Account *account);
char *gen_hash(const char *seed);
int decrypt(struct Account *account);
unsigned __stdcall thread_function(void *args);
int createThread(struct Thread *thread);
struct Thread *createThreads(int amount);
int deleteThread(struct Thread *thread);
int deleteThreads(struct Thread *thread, int amount);

FILE *file = NULL;

struct Account read_next_account() {
    struct Account account = {NULL, NULL, NULL};
    setMemAccount(&account);

    char *line = (char *)malloc(sizeof(char[128]));
    if (!line) return account; 

    if (fgets(line, 128, file) == NULL) {
        freeAccount(&account);
        free(line);
        return account;
    }

    size_t i = 0;
    for (; i < strlen(line); i++) {
        if (line[i] == ':') {
            i += 2;
            break;
        }
        strncat(account.user, &line[i], 1);
    }
    for (; i < strlen(line); i++) {
        if (line[i] == '\n' || line[i] == '\r')
            break;
        strncat(account.hashed_password, &line[i], 1);
    }

    free(line);
    return account;
}

void freeAccount(struct Account *account) {
    if (account->user) free(account->user);
    if (account->password) free(account->password);
    if (account->hashed_password) free(account->hashed_password);
    account->user = NULL;
    account->password = NULL;
    account->hashed_password = NULL;
}

void setMemAccount(struct Account *account) {
    account->user = (char *)malloc(sizeof(char[128]));
    account->password = (char *)malloc(sizeof(char[MAX_PASSWORD_LENGHT + 1]));
    account->hashed_password = (char *)malloc(sizeof(char[32 + 1]));

    if(account->user) memset(account->user, '\0', 128);
    if(account->password) memset(account->password, '\0', MAX_PASSWORD_LENGHT + 1);
    if(account->hashed_password) memset(account->hashed_password, '\0', 32 + 1);
}

char *gen_hash(const char *seed) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[MD5_DIGEST_LENGTH];
    DWORD cbHash = MD5_DIGEST_LENGTH;
    char *hash_str = (char *)malloc(sizeof(char[MD5_DIGEST_LENGTH * 2 + 1]));
    
    if (!hash_str) return NULL;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "Error CryptAcquireContext. Error: %x\n", GetLastError());
        free(hash_str);
        return NULL;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        fprintf(stderr, "Error CryptCreateHash. Error: %x\n", GetLastError());
        CryptReleaseContext(hProv, 0);
        free(hash_str);
        return NULL;
    }

    if (!CryptHashData(hHash, (const BYTE *)seed, (DWORD)strlen(seed), 0)) {
        fprintf(stderr, "Error CryptHashData. Error: %x\n", GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        free(hash_str);
        return NULL;
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        fprintf(stderr, "Error CryptGetHashParam. Error: %x\n", GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        free(hash_str);
        return NULL;
    }

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        snprintf(&hash_str[i * 2], MD5_DIGEST_LENGTH * 2 + 1, "%02x", rgbHash[i]);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return hash_str;
}

const char *abecedario = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
int setNextCombination(char *combination) {
    size_t abc_len = strlen(abecedario);

    if (combination[0] == 0) {
        combination[0] = abecedario[0];
        return 0;
    }

    size_t comb_len = strlen(combination);

    for (int i = (int)comb_len - 1; i >= 0; i--) {
        size_t index = strchr(abecedario, combination[i]) - abecedario;

        if (index < abc_len - 1) {
            combination[i] = abecedario[index + 1];
            return 0;
        }

        combination[i] = abecedario[0];
    }

    if (comb_len < MAX_PASSWORD_LENGHT) {
        combination[comb_len] = abecedario[0];
        return 0;
    }

    return 1;
}

int decrypt(struct Account *account) {
    char *combination = (char *)malloc(sizeof(char[MAX_PASSWORD_LENGHT + 1]));
    memset(combination, '\0', MAX_PASSWORD_LENGHT + 1);
    int found = 1;

    while (setNextCombination(combination) == 0) {
        char *hash = gen_hash(combination);
        if (hash == NULL) break;

        if (strcmp(account->hashed_password, hash) != 0) {
            free(hash);
            continue;
        }
        free(hash);
        found = 0;
        break;
    }

    if (found == 0) {
        memcpy(account->password, combination, strlen(combination));
    }
    free(combination);
    return found;
}

int createThread(struct Thread *thread) {
    thread->id = 0;
    thread->semaphore = CreateSemaphore(NULL, 0, 1, NULL);
    thread->next_semaphore = NULL;

    unsigned threadID;
    thread->thread = (HANDLE)_beginthreadex(
        NULL, 0, &thread_function, (void*)thread, 0, &threadID
    );

    if (thread->thread == 0) {
        fprintf(stderr, "Error creando hilo\n");
        return -1;
    }
    return 0;
}

int deleteThread(struct Thread *thread) {
    if (thread->thread) {
        WaitForSingleObject(thread->thread, INFINITE);
        CloseHandle(thread->thread);
        thread->thread = NULL;
    }
    if (thread->semaphore) {
        CloseHandle(thread->semaphore);
        thread->semaphore = NULL;
    }
    thread->next_semaphore = NULL;
    return 0;
}

int deleteThreads(struct Thread *thread, int amount) {
    for (size_t i = 0; i < amount; i++) {
        deleteThread(&thread[i]);
    }
    return 0;
}

struct Thread *createThreads(int amount) {
    struct Thread *threads = (struct Thread *)malloc(sizeof(struct Thread) * amount);

    for (int i = 0; i < amount; i++) {
        createThread(&threads[i]);
        threads[i].id = i + 1;
    }
    for (int i = 0; i < amount; i++) {
        threads[i].next_semaphore = (i != amount - 1) ? 
            threads[i + 1].semaphore : 
            threads[0].semaphore;
    }
    return threads;
}

unsigned __stdcall thread_function(void *args) {
    struct Thread *data = (struct Thread *)args;

    while (1) {
        WaitForSingleObject(data->semaphore, INFINITE);

        struct Account account = read_next_account();
        
        if (account.user == NULL) {
            ReleaseSemaphore(data->next_semaphore, 1, NULL); 
            freeAccount(&account);
            _endthreadex(0);
            return 0;
        }

        ReleaseSemaphore(data->next_semaphore, 1, NULL);

        decrypt(&account);
        fprintf(stdout, "%-16s %-4s\n", account.user, account.password);
        freeAccount(&account);
    }
    _endthreadex(0);
    return 0;
}

int main(int argc, char *argv[]) {
    const char* filename = "./users.txt"; 

    int threads_amount = 0;
    if (argc < 2) {
        threads_amount = 6;
    } else if (argc < 3) {
        threads_amount = atoi(argv[1]);
    } else {
        threads_amount = atoi(argv[1]);
        filename = argv[2];
    }

    file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error abriendo archivo %s\n", filename);
        return 1;
    }
    if (threads_amount > MAX_HILOS) threads_amount = MAX_HILOS; 

    struct Thread *threads = createThreads(threads_amount);

    ReleaseSemaphore(threads[0].semaphore, 1, NULL);

    deleteThreads(threads, threads_amount);

    free(threads);
    fclose(file);

    return 0;
}

#endif
