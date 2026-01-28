#include "RSA_Threshold.h"
#include "El_Gamal_Threshold.h"

/* Fonctions relatives aux joueurs pour le programme de signature RSA */

void get_rsa_player_secret_key(mpz_t Player_SK, unsigned int Player) // Récupère la clé secrète du joueur Player
{
    char key_path[50];
    snprintf(key_path, sizeof(key_path), "./Player_%d/RSA_Secret_key_%d.txt", Player, Player);

    FILE* fptr;
    fptr = fopen(key_path, "r");

    char key[MAX_HEXA_MPZ_SIZE]; 

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Player_SK, key, HEXA_BASE);

    fclose(fptr);
}


void gen_player_signature(mpz_t Player_Signature, mpz_t Player_SK, mpz_t Hashed_Message, mpz_t Delta, mpz_t n) // Génère la signature d'un joueur et la stock dans Player_Signature
{
    mpz_t exp;
    mpz_init(exp);

    mpz_mul_ui(exp, Delta, 2);
    mpz_mul(exp, Player_SK, exp);

    mpz_powm(Player_Signature, Hashed_Message, exp, n);

    mpz_clear(exp);
}


void send_player_signature(unsigned int Player, mpz_t Player_Signature)
{
    FILE* fptr;
    char file_path[60] = "./Coordinator/Player_Signature_0.txt"; 
    snprintf(file_path, sizeof(file_path), "./Coordinator/Player_Signature_%d.txt", Player);

    fptr = fopen(file_path, "w");
    char* Signature_str = mpz_get_str(NULL, HEXA_BASE, Player_Signature);
    fprintf(fptr, "%s\n", Signature_str);

    free(Signature_str);
    fclose(fptr);
}


void gen_proof_of_correctness(mpz_t Player_signature, mpz_t Player_SK, mpz_t Player_VK, mpz_t Dealer_VK, mpz_t Proof_z, mpz_t Proof_c, mpz_t Hashed_Message, mpz_t Delta, mpz_t n) // Génère la preuve d'exactitude associée à la signature d'un joueur
{
    mpz_t tmp;
    mpz_init(tmp);

    gmp_randstate_t rand;
    gmp_randinit_default(rand);

    unsigned long seed = clock();
    gmp_randseed_ui(rand, seed);

    mpz_t* ptr_for_concatenation = init_mpz_ptr(6); // On veut hacher le concaténé de 6 valeurs

    mpz_set(ptr_for_concatenation[0], Dealer_VK);

    mpz_mul_ui(tmp, Delta, 4);
    mpz_powm(ptr_for_concatenation[1], Hashed_Message, tmp, n);
    
    mpz_set(ptr_for_concatenation[2], Player_VK);
    mpz_powm_ui(ptr_for_concatenation[3], Player_signature, 2, n);

    mpz_urandomb(tmp, rand, (mp_bitcnt_t)((8 * MAIN_HASHED_MESSAGES_BYTES_LEN) + (2 * 8 * (SECONDARY_HASHED_MESSAGES_BYTES_LEN))));

    mpz_powm(ptr_for_concatenation[4], Dealer_VK, tmp, n);
    mpz_powm(ptr_for_concatenation[5], ptr_for_concatenation[1], tmp, n); 

    unsigned char* concatenation_for_hash = mpz_concatenation_to_str(ptr_for_concatenation, 6);

    unsigned int Input_Byte_Len = str_len(concatenation_for_hash);
    secondary_msg_hash_to_mpz(concatenation_for_hash, Input_Byte_Len, Proof_c);

    mpz_mul(Proof_z, Player_SK, Proof_c);
    mpz_add(Proof_z, Proof_z, tmp);

    gmp_randclear(rand);
    mpz_clear(tmp);
    free(concatenation_for_hash);
    free_mpz_ptr(ptr_for_concatenation, 6);
}


void send_player_PoC(unsigned int Player, mpz_t Proof_z, mpz_t Proof_c)
{
    FILE* fptr;
    char file_path[60] = "./Coordinator/Player_PoC_0.txt"; 
    snprintf(file_path, sizeof(file_path), "./Coordinator/Player_PoC_%d.txt", Player);

    fptr = fopen(file_path, "w");
    char* Proof_str = mpz_get_str(NULL, HEXA_BASE, Proof_z);
    fprintf(fptr, "%s\n", Proof_str);
    mpz_get_str(Proof_str, HEXA_BASE, Proof_c);
    fprintf(fptr, "%s\n", Proof_str);

    free(Proof_str);
    fclose(fptr);
}

void full_player_signature_and_PoC(mpz_t Dealer_VK, unsigned int Player, unsigned char* Message, unsigned int Message_size, mpz_t Delta, mpz_t n)
{
    mpz_t Hashed_Message, Player_SK, Player_VK, Player_Signature, Proof_z, Proof_c;
    mpz_inits(Hashed_Message, Player_SK, Player_VK, Player_Signature, Proof_z, Proof_c, NULL);

    main_msg_hash_to_mpz(Message, Message_size, Hashed_Message, n);

    get_rsa_player_secret_key(Player_SK, Player);
    gen_player_signature(Player_Signature, Player_SK, Hashed_Message, Delta, n);

    get_player_verification_key(Player_VK, Player);
    gen_proof_of_correctness(Player_Signature, Player_SK, Player_VK, Dealer_VK, Proof_z, Proof_c, Hashed_Message, Delta, n);

    send_player_signature(Player, Player_Signature);
    send_player_PoC(Player, Proof_z, Proof_c);

    mpz_clears(Hashed_Message, Player_SK, Player_VK, Player_Signature, Proof_z, Proof_c, NULL);
}

/* Fonctions relatives aux joueurs pour le programme de chiffrement El Gamal */

void get_el_gamal_player_secret_key(mpz_t Player_SK, unsigned int Player) // Récupère la clé secrète du joueur Player
{
    char key_path[50];
    snprintf(key_path, sizeof(key_path), "./Player_%d/El_Gamal_Secret_key_%d.txt", Player, Player);

    FILE* fptr;
    fptr = fopen(key_path, "r");

    char key[MAX_HEXA_MPZ_SIZE]; 

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Player_SK, key, HEXA_BASE);

    fclose(fptr);
}


void gen_player_decrypted(mpz_t Player_Decrypted, mpz_t Player_SK, mpz_t Sender_PK, mpz_t Primitive_Polynomial) // Génère le déchiffrement partielle d'un joueur et le stock dans Player_Signature
{
    polynomial_pow_mod(Player_Decrypted, Sender_PK, Player_SK, Primitive_Polynomial);
}

void send_player_decrypted(unsigned int Player, mpz_t Player_Decrypted)
{
    FILE* fptr;
    char file_path[60] = "./Coordinator/Player_Decrypted_0.txt"; 
    snprintf(file_path, sizeof(file_path), "./Coordinator/Player_Decrypted_%d.txt", Player);

    fptr = fopen(file_path, "w");
    char* Decrypted_str = mpz_get_str(NULL, HEXA_BASE, Player_Decrypted);
    fprintf(fptr, "%s\n", Decrypted_str);

    free(Decrypted_str);
    fclose(fptr);
}

void full_player_decryption(unsigned int Player, mpz_t Sender_PK, mpz_t Primitive_Polynomial)
{
    mpz_t Player_SK, Player_Decrypted;
    mpz_inits(Player_SK, Player_Decrypted, NULL);

    get_el_gamal_player_secret_key(Player_SK, Player);
    gen_player_decrypted(Player_Decrypted, Player_SK, Sender_PK, Primitive_Polynomial);

    send_player_decrypted(Player, Player_Decrypted);

    mpz_clears(Player_SK, Player_Decrypted, NULL);
}