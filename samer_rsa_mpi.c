#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <mpi.h>
#include <pthread.h>
#include <time.h>

unsigned long long int public_key, private_key, n = 0;
char files[][30] = {"files/100_words.txt", "files/500_words.txt", "files/1000_words.txt", "files/2500_words.txt", "files/5000_words.txt", "files/10000_words.txt"};
time_t key_start, key_end, enc_start, enc_end, dec_start, dec_end;

//----------------------------------------------
/****************************
 *  Mathematical functions
 * *************************/
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
 *
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
/***********************
 * RSA Decryption
 ***********************/
/**
 * Decrypt ciphered text
 */
long long int decrypt(unsigned long long int encrypted_text)
{
    int d = private_key;
    long long int decrypted = 1;

    // the following while loop is equivalent to (message ^ d) MOD n
    while (d--)
    {
        decrypted *= encrypted_text;
        decrypted %= n;
    }
    return decrypted;
}
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
//--------------------------------------------------

int main(int argc, char *argv[])
{
    /***************
     * Variables
     ***************/
    int proc_n, proc_rank; // number of processes & process rank
    char *plain_text;      // file lines as plaintext.
    long file_size;        // file size
    double total_enc, total_dec;

    int file_number = 1;
    int bit_length = 10;

    // the first arg are number of process
    if (argc > 1)
    { // if true, there are more parameters

        if (argc == 3)
        { // the process arg + filename index + bitlength

            // File number must be between 1 and max fil_names array length
            file_number = atoi(argv[1]);
            bit_length = atoi(argv[2]);
        }
        else if (argc == 6)
        {
            file_number = atoi(argv[1]);
            bit_length = atoi(argv[2]);
            public_key = atoi(argv[3]);
            private_key = atoi(argv[4]);
            n = atoi(argv[5]);
        }
        else
        {
            file_number = 1;
            bit_length = 10;
        }
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
    // Init rsa
    unsigned long long p, q, fi, e;

    if (private_key == 0 || public_key == 0 || n == 0)
    {

        time_t key_start, key_end;

        key_start = clock();

        //--- Step 1: selecting p and q
        p = generate_random_prime(bit_length);
        //printf("p with %d bits: %llu\n", bit_length, p);

        q = generate_random_prime(bit_length);
        //printf("q with %d bits: %llu\n", bit_length, q);

        //---------------------------
        // Step 2: calculate n
        n = p * q;
        //printf("n with %d bits: %llu\n", bit_length, n);

        //---------------------------
        // Step 3: calculate the totient (fi)
        fi = (p - 1) * (q - 1);
        //printf("fi with %d bits: %llu\n", bit_length, fi);

        //---------------------------
        // Step 4: Select Public Key;
        // There is an issue here, in the original code, e = 2
        // The public key is always = 3
        // to avoid this, e starts as a random number while fi/2 < e < fi

        e = generate_random_number(fi / 2, fi);
        //unsigned long long int e = fi - 1;

        while (1)
        {
            if (gcd(e, fi) == 1)
                break;
            e--;
        }

        key_end = clock();

        public_key = e;
        //printf("public_key using %d bits: %llu\n", bit_length, public_key);
    }
    /* double time_taken = (double)(key_end - key_start) / (double)CLOCKS_PER_SEC;
    printf("Key generation time: %f\n", time_taken); */

    //---------------------------
    // Step 5: calculate Private Key;

    // needs mpi
    // the private key can't be greater than fi
    // So, to distribute the calculation of d, first an array will be generated from 2 -> fi
    // then the array will be distributed among processes
    //-------------------------

    // the final encryption result
    unsigned long long int encrypted_result[message_length * sizeof(unsigned long long int)];
    if (encrypted_result == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(0);
    }

    // the final decryption result
    unsigned long long int decrypted_result[message_length * sizeof(unsigned long long int)];
    if (decrypted_result == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(0);
    }
    //-------------------------------------------------------
    // double total_pr_time; // to calculate private key generation time
    int private_key_found = 0;
    //-------------------------------------------------------
    // Init. MPI
    MPI_Init(&argc, &argv);
    MPI_Comm_size(MPI_COMM_WORLD, &proc_n);
    MPI_Comm_rank(MPI_COMM_WORLD, &proc_rank);

    //-----------------------------------------------------------------
    // Calculating the private key

    //------------------------------------------------
    time_t enc_start, enc_end, dec_start, dec_end;
    /***************
     * Encryption
     ***************/
    int message_chunk_size = ceil((double)message_length / (proc_n)); // sub-array for each process
    int starting_index = proc_rank * message_chunk_size;
    unsigned long long int local_encrypted[message_chunk_size];
    unsigned long long int index = 0; // to always start from zero if the starting index wasn't zeo

    enc_start = clock();

    for (long long int i = starting_index; i < starting_index + message_chunk_size; i++)
    {
        local_encrypted[index] = encrypt((unsigned long long int)plain_text[i]);
        index++;
    }

    enc_end = clock();

    double time_taken = (double)(enc_end - enc_start) / (double)CLOCKS_PER_SEC;

    // Gather the encrypted result array
    MPI_Gather(&local_encrypted, message_chunk_size, MPI_UNSIGNED_LONG_LONG, encrypted_result, message_chunk_size, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);
    MPI_Reduce(&time_taken, &total_enc, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);

    // Broadcast to all process (assuming the decryption on another node or called by another function)
    MPI_Bcast(&encrypted_result, message_length, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);

    MPI_Barrier(MPI_COMM_WORLD);

    //----------------------------------------
    /***************
     * Decryption
     ***************/
    unsigned long long int local_decrypted[message_chunk_size];


    if (private_key == 0 || public_key == 0 || n == 0)
    {
        unsigned long long chunk_size = ceil(fi / proc_n);
        unsigned long long value_index = (proc_rank * chunk_size); // set starting value for d
        unsigned long long int local_d = 0;
        unsigned long long limit = chunk_size;

        if (value_index == 0)
            value_index = 2;

        if ( value_index == 2 ){
            limit = chunk_size;
        }else{
            limit = value_index + chunk_size;
        }

        for (unsigned long long int i = value_index; i < limit; i++)
        {
            if (private_key_found == 1)
            {
                break;
            }
            else
            {
                if ((i * e) % fi == 1)
                {
                    local_d = i;
                    //printf("Process %d: %llu\n", proc_rank, local_d);
                    private_key_found = 1;
                    break;
                }
            }
        }

        MPI_Reduce(&local_d, &private_key, 1, MPI_UNSIGNED_LONG_LONG, MPI_MAX, 0, MPI_COMM_WORLD);

        // Broadcast the signal to stop to all processes
        MPI_Bcast(&private_key, 1, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);

        MPI_Barrier(MPI_COMM_WORLD);
    }

    index = 0;
    dec_start = clock();
    for (int i = starting_index; i < starting_index + message_chunk_size; i++)
    {
        local_decrypted[index] = (long long int)decrypt(encrypted_result[i]);
        index++;
    }

    dec_end = clock();

    time_taken = (double)(dec_end - dec_start) / (double)CLOCKS_PER_SEC;

    MPI_Gather(&local_decrypted, message_chunk_size, MPI_UNSIGNED_LONG_LONG, decrypted_result, message_chunk_size, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);
    MPI_Reduce(&time_taken, &total_dec, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);

    MPI_Barrier(MPI_COMM_WORLD);

    MPI_Finalize();

    //---------------------------------------------------

    if (proc_rank == 0)
    {

        /* printf("\nEncrypted (ciphertext): %f (s)\n", total_enc);
        for (int i = 0; i < message_length; i++)
        {
            printf("%llu", encrypted_result[i]);
        }
        printf("\n\nDecrypted (ciphertext): %f (s)\n", total_dec);
        for (int i = 0; i < message_length; i++)
        {
            printf("%c", decrypted_result[i]);
        } */
        
        printf("\n\nEncrypted (ciphertext): %f (s)\n", total_enc);
        printf("Decrypted (plaintext): %f (s)\n", total_dec);
    }


    free(plain_text);

    return 0;
}