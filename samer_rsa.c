#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <mpi.h>
#include <pthread.h>
#include <time.h>

/************************
 * Shared Variables
************************/
unsigned long long int public_key, private_key, n, fi = 0;
char files[][30] = {"files/100_words.txt", "files/500_words.txt", "files/1000_words.txt", "files/2500_words.txt", "files/5000_words.txt", "files/10000_words.txt"};
time_t key_start, key_end, enc_start, enc_end, dec_start, dec_end;
double time_taken;

// Shared variable for private key calculation among threads
pthread_mutex_t private_key_mutex = PTHREAD_MUTEX_INITIALIZER; // Mutex to synchronize access to private_key
int private_key_found = 0;

/**************************************************
 * Private key thread arguments
 * Used with the private key calculation PThreads
 ***************************************************/
typedef struct
{
    unsigned long long int start;
    unsigned long long int limit;
    unsigned long long int e;
    unsigned long long int fi;
    unsigned long long int *private_key;
} PrivateKeyArgs;

/*****************************************
 * Encryption thread arguments
 * Used with the encryption PThreads
 *****************************************/
typedef struct
{
    unsigned long long int start;
    unsigned long long int limit;
    unsigned long long *plain_text;
    unsigned long long *encrypted_text;
} EncryptArgs;

/*****************************************
 * Decryption thread arguments
 * Used with the decryption Pthreads
 ****************************************/
typedef struct
{
    unsigned long long int start;
    unsigned long long int end;
    unsigned long long *cipher_text;
    unsigned long long *decrypted_text;
} DecryptArgs;
//----------------------------------------------
//----------------------------------------------
//----------------------------------------------
//----------------------------------------------
//----------------------------------------------
//----------------------------------------------
//----------------------------------------------
/****************************
 *  Mathematical functions
 * *************************/
//----------------------------------------------
/**
 * Power exponent function
 */
unsigned long long power(unsigned long long base, unsigned long long exp, unsigned long long mod)
{
    unsigned long long result = 1;
    base = base % mod;

    while (exp > 0)
    {
        if (exp % 2 == 1)
        {
            result = (result * base) % mod;
        }

        exp = exp >> 1;
        base = (base * base) % mod;
    }

    return result;
}
//--------------------------
/**
 * Miller-Rabin function
 * probabilistic algorithm for generating prime numbers
 */
bool miller_rabin(unsigned long long n, unsigned long long k)
{
    if (n <= 1)
        return false;
    if (n == 2 || n == 3)
        return true;
    if (n % 2 == 0)
        return false;

    unsigned long long r = 0, d = n - 1;
    while (d % 2 == 0)
    {
        r++;
        d /= 2;
    }

    for (unsigned long long i = 0; i < k; i++)
    {
        unsigned long long a = 2 + rand() % (n - 4);
        unsigned long long x = power(a, d, n);

        if (x == 1 || x == n - 1)
            continue;

        for (unsigned long long j = 0; j < r - 1; j++)
        {
            x = power(x, 2, n);
            if (x == n - 1)
                break;
        }

        if (x != n - 1)
            return false;
    }

    return true;
}
//--------------------------
/**
 * Random prime generator
 */
unsigned long long generate_random_prime(unsigned long long bit_length)
{

    unsigned long long min_val = (1ULL << (bit_length - 1)) + 1;
    unsigned long long max_val = (1ULL << bit_length) - 1;
    unsigned long long candidate;

    while (1)
    {
        candidate = rand() % (max_val - min_val + 1) + min_val;
        if (candidate % 2 == 0)
        {
            // Ensure the number is odd
            candidate += 1;
        }

        if (miller_rabin(candidate, 20))
        {
            return candidate;
        }
    }
}
//--------------------------
/**
 * Random number generator
 * Takes two argument min,max
 */
unsigned long long generate_random_number(unsigned long long min, unsigned long long max)
{
    // Seed the random number generator with the current time
    srand((unsigned int)time(NULL));

    // Generate a random number within the specified range
    unsigned long long randomNumber = min + rand() % (max - min + 1);

    return randomNumber;
}
//---------------------------
/**
 * Greatest common divisor
 */
unsigned long long gcd(unsigned long long a, unsigned long long b)
{
    while (b != 0)
    {
        unsigned long long temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}
//---------------------------------------
//---------------------------------------
//---------------------------------------

/************************************************************
 *  RSA Key Generation (Parallel private key generation)
 ************************************************************/
/**
 * Calculate private key using PThreads
 */
void *calculate_private_key(void *arg)
{
    PrivateKeyArgs *args = (PrivateKeyArgs *)arg;

    for (unsigned long long int i = args->start; i < args->limit; i++)
    {
        // Lock the mutex before accessing shared data
        pthread_mutex_lock(&private_key_mutex);

        // Check if another thread has found the private key
        if (private_key_found)
        {
            // Unlock the mutex before returning
            pthread_mutex_unlock(&private_key_mutex);
            return NULL;
        }

        // Unlock the mutex before starting the calculation
        pthread_mutex_unlock(&private_key_mutex);

        if ((i * args->e) % args->fi == 1)
        {
            // Lock the mutex before updating shared data
            pthread_mutex_lock(&private_key_mutex);

            // Set the flag to true to make other processes stop
            private_key_found = 1;

            // setting the value of d in the address of private_key
            *args->private_key = (unsigned long long int)i;

            // Unlock the mutex after updating shared data
            pthread_mutex_unlock(&private_key_mutex);

            return NULL;

            break;
        }
    }

    return NULL;
}

//--------------------------------------------
//--------------------------------------------
//--------------------------------------------
/************************************************************
 *  RSA Key Generation (Sequential private key generation)
 ************************************************************/
void init_rsa(int bit_length)
{

    unsigned long long p, q;

    key_start = clock();
    //--- Step 1: selecting p and q
    p = generate_random_prime(bit_length);
    printf("p with %d bits: %llu\n", bit_length, p);

    q = generate_random_prime(bit_length);
    printf("q with %d bits: %llu\n", bit_length, q);

    //---------------------------
    // Step 2: calculate n
    n = p * q;
    printf("n with %d bits: %llu\n", bit_length, n);

    //---------------------------

    // Step 3: calculate the totient (fi)

    fi = (p - 1) * (q - 1);
    printf("fi with %d bits: %llu\n", bit_length, fi);

    //---------------------------
    // Step 4: Select Public Key;
    // There is an issue here, in the original code, e = 2
    // The public key is always = 3, 5, 11, or 13
    // to avoid this, e starts as a random number while fi/2 < e < fi

    unsigned long long e = generate_random_number(fi / 2, fi);


    while (1)
    {
        if (gcd(e, fi) == 1)
            break;
        e--;
    }
    public_key = e;
    printf("public_key using %d bits: %llu\n", bit_length, public_key);
    //---------------------------
    key_end = clock();

    time_taken = (double)(key_end - key_start) / (double)CLOCKS_PER_SEC;
    //printf("Public key generation time: %f\n", time_taken);
    printf("-----------------------\n");
}

//---------------------------------------
/*******************************
 *  RSA Encryption Functions
 ******************************/
/**
 * Plain text encryption
 * @param (unsigned long long int) message
 */
unsigned long long int encrypt(unsigned long long int message)
{
    unsigned long long int e = public_key;
    unsigned long long int encrypted_text = 1;

    // the following while loop is equivalent to (message ^ e) MOD n
    while (e--)
    {
        encrypted_text *= message;
        encrypted_text %= n;
    }
    return encrypted_text;
}
//----------------------------
/**
 * Encrypt array chunks
 * used for PThreads
 */
void *encrypt_chunk(void *arg)
{
    EncryptArgs *args = (EncryptArgs *)arg;

    for (unsigned long long int i = args->start; i < args->limit; i++)
    {
        args->encrypted_text[i] = encrypt((long long int)args->plain_text[i]);
    }

    return NULL;
}
//--------------------------------------------
//--------------------------------------------
//--------------------------------------------
//--------------------------------------------
//--------------------------------------------
/***********************
 * RSA Decryption
 ***********************/
/**
 * Decrypt ciphered text
 */
long long int decrypt(unsigned long long int encrypted_text)
{
    unsigned long long int d = private_key;
    unsigned long long int decrypted = 1;

    // the following while loop is equivalent to (message ^ d) MOD n
    while (d--)
    {
        decrypted *= encrypted_text;
        decrypted %= n;
    }
    return decrypted;
}
//-------------------
/**
 *  Decrypt chunk of cipher text array
 */
void *decrypt_chunk(void *arg)
{
    DecryptArgs *args = (DecryptArgs *)arg;

    for (unsigned long long int i = args->start; i < args->end; i++)
    {
        args->decrypted_text[i] = decrypt((unsigned long long int)args->cipher_text[i]);
        // decrypt((int)args->encrypted[i]);
    }

    return NULL;
}
//---------------------------------
//---------------------------------
//---------------------------------
//---------------------------------
//---------------------------------
//---------------------------------
/**********************
 * Reading Text Files
 * *******************/
/**
 * Read a text file
 */
char *read_file(const char *filename, long *file_size)
{
    FILE *file;
    char *buffer;

    // Open the file in binary mode
    file = fopen(filename, "rb");

    if (file == NULL)
    {
        perror("Error opening file");
        return NULL;
    }

    // Find the size of the file
    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    rewind(file);

    // Allocate memory for the buffer
    buffer = (char *)malloc((*file_size + 1) * sizeof(char));

    if (buffer == NULL)
    {
        perror("Memory allocation error");
        fclose(file);
        return NULL;
    }

    // Read the file into the buffer
    fread(buffer, sizeof(char), *file_size, file);

    // Null-terminate the buffer
    buffer[*file_size] = '\0';

    // Close the file
    fclose(file);

    return buffer;
}
// -------------------------------------------------
/**********************
 * Declarations
 * *******************/
void sequential(int file_number, int bit_length);
void multi_threads(int file_number, int bit_length, int number_of_threads);
//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------
/**
 * Main
 * 
 * The main() allows to user to enter a few parameters via console
 */

int main(int argc, char *argv[])
{
    int chosen_algorithm;
    int chosen_file;
    int chosen_processes;
    int chosen_threads;
    int chosen_bit_length;
    unsigned long long int chosen_private_key;
    unsigned long long int chosen_public_key;
    unsigned long long int chosen_n;

    printf("Choose an algorithm:\n ");
    printf("1- Sequential\n ");
    printf("2- MPI\n ");
    printf("3- Multi-threading\n ");
    printf("4- Compare all\n ");
    scanf("%d", &chosen_algorithm);

    if (chosen_algorithm < 1 || chosen_algorithm > 4)
    {
        chosen_algorithm = 1;
    }
    //-------------------------------------
    if (chosen_algorithm != 4)
    {
        printf("Do you have a public key? (0 if you don't):\n ");
        scanf("%d", &chosen_public_key);

        if (chosen_public_key > 0)
        {
            public_key = chosen_public_key;
        }
        //---------------------------------
        printf("Do you have a private key? (0 if you don't):\n ");
        scanf("%d", &chosen_private_key);

        if (chosen_private_key > 0)
        {
            private_key = chosen_private_key;
        }
        //---------------------------------
        printf("Do you have a value for N? (0 if you don't):\n ");
        scanf("%d", &chosen_n);

        if (chosen_n > 0)
        {
            n = chosen_n;
        }
    }
    //---------------------------------
    printf("Choose a file to encrypt:\n ");
    printf("1- 100 words text file:\n ");
    printf("2- 500 words text file:\n ");
    printf("3- 1,000 words text file:\n ");
    printf("4- 2,500 words text file:\n ");
    printf("5- 5,000 words text file:\n ");
    printf("6- 10,000 words text file:\n ");

    scanf("%d", &chosen_file);

    // File number must be between 1 and max fil_names array length
    if (chosen_file < 1 || chosen_file > (sizeof(files) / sizeof(files[0])))
    {
        chosen_file = 0; // set default to 0
    }

    //---------------------------------
    printf("Enter the bit length (max. 16):\n ");
    printf("Note: 16 bits will generate a 10-digit key length\n ");
    scanf("%d", &chosen_bit_length);

    // bit length between 1 & 33
    if (chosen_bit_length < 6 || chosen_bit_length > 16)
    {
        chosen_bit_length = 10; // default
    }
    //---------------------------------
    if (chosen_algorithm == 2)
    {
        // MPI
        printf("Enter number of processes:\n");
        scanf("%d", &chosen_processes);

        if (chosen_processes < 1 || chosen_processes > 16)
        {
            chosen_processes = 4; // default
        }

        // Call the compiled mpi file
        char command[250];
        // Embedding variables in a string using sprintf
        sprintf(command, "mpiexec -n %d samer_rsa_mpi.exe %d %d", chosen_processes, chosen_file, chosen_bit_length);
        printf("========================================================\n");
        printf("RSA using MPI: %d processes, %d bit length, on %s file \n", chosen_processes, chosen_bit_length, files[chosen_file - 1]);
        printf("========================================================\n");

        // Run MPI program
        system(command);
    }
    else if (chosen_algorithm == 3)
    {
        // PThreads & default
        printf("Enter number of threads:\n");
        scanf("%d", &chosen_threads);

        if (chosen_threads < 1 || chosen_threads > 8)
        {
            chosen_threads = 4; // default
        }

        multi_threads(chosen_file, chosen_bit_length, chosen_threads);
    }
    else if (chosen_algorithm == 4)
    {

        printf("Enter number of processes for MPI:\n");
        scanf("%d", &chosen_processes);
        if (chosen_processes < 1 || chosen_bit_length > 16)
        {
            chosen_processes = 4; // default
        }

        printf("Enter number of threads for PThreads:\n");
        scanf("%d", &chosen_threads);

        if (chosen_threads < 1 || chosen_threads > 8)
        {
            chosen_threads = 4; // default
        }

        // running sequential
        sequential(chosen_file, chosen_bit_length);
        //-------------------------------------

        // run multithreading
        multi_threads(chosen_file, chosen_bit_length, chosen_threads);

        //-------------------------------------
        // running MPI
        // --- Call the compiled mpi file
        char command[300];
        // --- Embedding variables in a string using sprintf
        sprintf(command, "mpiexec -n %d samer_rsa_mpi.exe %d %d %llu %llu %llu", chosen_processes, chosen_file, chosen_bit_length, public_key, private_key, n);
        printf("========================================================\n");
        printf("RSA using MPI: %d processes, %d bit length, on %s file, PbKey: %llu, PrKey: %llu, N: %llu \n", chosen_processes, chosen_bit_length, files[chosen_file - 1], public_key, private_key, n);
        printf("========================================================\n");
        // Run MPI program
        system(command);
        //-------------------------------------
       
    }
    else
    {
        sequential(chosen_file, chosen_bit_length);
    }

    return 0;
}
//--------------------------------------------------------------------

/**
 * Sequential function
 */
void sequential(int file_number, int bit_length)
{
    printf("=============================================\n");
    printf("RSA using sequential method: %d bit length\n", bit_length);
    printf("=============================================\n");
    long file_size;
    char *plain_text;
    //-------------------------
    // Init rsa

    if (public_key == 0 || private_key == 0 || n == 0)
    {
        init_rsa(bit_length);
    }

    //-------------------------
    // Read chosen file
    const char *filename = files[file_number - 1]; // file name

    plain_text = read_file(filename, &file_size);

    if (plain_text == NULL)
    {
        printf("Unable to read file");
        exit(0);
    }

    int message_length = strlen(plain_text);
    //-------------------------
    long long int encrypted[message_length * sizeof(unsigned long long int)];
    long long int decrypted[message_length * sizeof(unsigned long long int)];

    printf("Encrypting...\n");

    // Encryption
    enc_start = clock();

    for (int i = 0; i < message_length; i++)
    {
        encrypted[i] = encrypt((long long int)plain_text[i]);
    }

    enc_end = clock();

    /* printf("\nEncrypted Message (ciphertext):\n");
    for (int i = 0; i < message_length; i++)
    {
        printf("%llu", encrypted[i]);
    } */

    time_taken = (double)(enc_end - enc_start) / (double)CLOCKS_PER_SEC;
    printf("\nEncryption time: %f\n", time_taken);
    printf("-----------------------\n");

    //-------------------------
    // Decryption

    printf("Decrypting...\n");
     // Step 5: Select Private Key;
    unsigned long long d = 2;

    key_start = clock();

    while (1)
    {
        if ((d * public_key) % fi == 1)
            break;
        d++;
    }

    private_key = d;
    key_end = clock();

    printf("private key using %llu bits: %llu\n", bit_length, private_key);
    time_taken = (double)(key_end - key_start) / (double)CLOCKS_PER_SEC;
    //printf("Private key generation time: %f\n", time_taken);
    printf("-----------------------\n");

    dec_start = clock();

    for (int i = 0; i < message_length; i++)
    {
        decrypted[i] = decrypt(encrypted[i]);
    }

    dec_end = clock();

    //------------------------------------------------------------
    // Print has been commented to avoid print buffer issues
    /* printf("\n\nDecrypted Message (plaintext):\n");
    for (int i = 0; i < message_length; i++)
    {
        printf("%c", decrypted[i]);
    } */
    //------------------------------------------------------------
    time_taken = (double)(dec_end - dec_start) / (double)CLOCKS_PER_SEC;
    printf("\nDecryption time: %f\n", time_taken);

    free(plain_text);
}

//--------------------------------------------------------------------
void multi_threads(int file_number, int bit_length, int number_of_threads)
{
    printf("========================================================\n");
    printf("RSA using multithreading: %d threads, %d bit length\n", number_of_threads, bit_length);
    printf("========================================================\n");
    /***************
     * Variables
     ***************/
    char *plain_text; // file lines as plaintext.
    long file_size;   // file size

    //-------------------------
    // Init rsa
    if (public_key == 0 || private_key == 0 || n == 0)
    {
        init_rsa(bit_length);
    }
    //-------------------------

    // Read chosen file
    const char *filename = files[file_number - 1]; // file name

    plain_text = read_file(filename, &file_size);

    if (plain_text == NULL)
    {
        printf("Unable to read file");
        exit(0);
    }

    int message_length = strlen(plain_text);
    //-----------------------------------------------

    // Result Arrays
    unsigned long long int *encrypted_text = (unsigned long long int *)malloc(message_length * sizeof(unsigned long long int));

    if (encrypted_text == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(0);
    }

    unsigned long long int *decrypted_text = (unsigned long long int *)malloc(message_length * sizeof(unsigned long long int));

    if (decrypted_text == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(0);
    }

    /******************
     *  Encryption
     * ****************/

    printf("\nEncrypting...\n");


    // Convert plaint_text from "char" to "long long int" (tries everything. This is the only solution that works!!)
    unsigned long long int to_encrypt[message_length];

    for (int i = 0; i < message_length; i++)
    {
        to_encrypt[i] = (unsigned long long int)plain_text[i];
    }

    // Perform encryption in parallel
    //--------------------------------
    //
    // Each thread encrypts a chunk of the to_encrypt array (same logic as in the MPI code).
    // Based on the thread id, the stating index is specified. For example:
    // Thread 1 has an id = 0, Thread 2 has an id = 1, etc.
    //
    // Since all threads has the same arguments (starting index, limit, and the array chunk),
    // A Struct has bee created to send multiple arguments through the pthread_create function.
    // which makes the parameters easy to access
    //-----------------------------------------------------------------
    //

    pthread_t enc_threads[number_of_threads];
    EncryptArgs encrypt_args[number_of_threads];

    // calculate chunk size for each thread
    int chunk_size = message_length / number_of_threads;

    enc_start = clock();
    // generate the threads
    for (int i = 0; i < number_of_threads; i++)
    {
        encrypt_args[i].start = i * chunk_size;
        encrypt_args[i].limit = (i == number_of_threads - 1) ? message_length : (i + 1) * chunk_size;
        encrypt_args[i].plain_text = to_encrypt;

        encrypt_args[i].encrypted_text = encrypted_text; // Pass the shared array
        pthread_create(&enc_threads[i], NULL, encrypt_chunk, (void *)&encrypt_args[i]);
    }

    for (int i = 0; i < number_of_threads; i++)
    {
        pthread_join(enc_threads[i], NULL);
    }

    enc_end = clock();

    //-----------------------------------------------
    /* printf("\nEncrypted Message (ciphertext):\n");
    for (int i = 0; i < message_length; i++)
    {
        printf("%llu", encrypted_text[i]);
    } */
    //-----------------------------------------------

    time_taken = (double)(enc_end - enc_start) / (double)CLOCKS_PER_SEC;
    printf("\nEncryption time: %f\n", time_taken);
    printf("---------------------\n");

    //------------------------------
    /******************
     *  Decryption
     * ****************/
    //---------------------------
    // Step 5: Calculate Private Key;
    // Calculating private key using pthreads
    //
    // Based on the massive time taken by the sequential algorithm to find 'd'
    // especially when e and fi are relatively large numbers, parallelizing the calculation
    // of private key is necessary.
    //
    // The decomposition depends splitting the fi values from 2 to fi, and assign each chunk to a thread.
    //---------------------------------------
    printf("Decrypting...\n");
    pthread_t pr_key_threads[number_of_threads]; // PThread objects
    PrivateKeyArgs pr_key_args[number_of_threads]; // PThread args (struct)

    key_start = clock();
    // calculate chunk size for each thread
    unsigned long long int dec_chunk_size = (fi) / number_of_threads;

    // generate the threads
    for (int i = 0; i < number_of_threads; i++)
    {
        pr_key_args[i].start = (i * dec_chunk_size == 0) ? 2 : i * dec_chunk_size;
        pr_key_args[i].limit = (i == number_of_threads - 1) ? (fi) : (i + 1) * dec_chunk_size;
        pr_key_args[i].fi = fi;
        pr_key_args[i].e = public_key;
        pr_key_args[i].private_key = &private_key; // Pass the shared variable

        pthread_create(&pr_key_threads[i], NULL, calculate_private_key, (void *)&pr_key_args[i]);
    }

    // Joining Threads to main thread
    for (int i = 0; i < number_of_threads; i++)
    {
        pthread_join(pr_key_threads[i], NULL);
    }

    key_end = clock();

    printf("private_key using %llu bits: %llu\n", bit_length, private_key);
    time_taken = (double)(key_end - key_start) / (double)CLOCKS_PER_SEC;
    //printf("private key generation time: %f\n", time_taken);
    printf("---------------------\n");

    //---------------------------------------------

    // Perform decryption in parallel
    pthread_t decrypt_threads[number_of_threads];
    DecryptArgs decrypt_args[number_of_threads];

    chunk_size = message_length / number_of_threads;

    dec_start = clock();
    for (int i = 0; i < number_of_threads; i++)
    {
        decrypt_args[i].start = i * chunk_size;
        decrypt_args[i].end = (i == number_of_threads - 1) ? message_length : (i + 1) * chunk_size;
        decrypt_args[i].cipher_text = encrypted_text;
        decrypt_args[i].decrypted_text = decrypted_text;

        pthread_create(&decrypt_threads[i], NULL, decrypt_chunk, (void *)&decrypt_args[i]);
    }

    for (int i = 0; i < number_of_threads; i++)
    {
        pthread_join(decrypt_threads[i], NULL);
    }

    dec_end = clock();

    //--------------------------------------------------------
   /*  printf("\nDecrypted Message (plaintext):\n");
    for (int i = 0; i < message_length; i++)
    {
        printf("%c", decrypted_text[i]);
    } */
    //--------------------------------------------------------

    time_taken = (double)(dec_end - dec_start) / (double)CLOCKS_PER_SEC;
    printf("\n\nDecryption time: %f\n", time_taken);

    free(plain_text);
}
