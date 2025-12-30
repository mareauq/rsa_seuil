#include "RSA_Seuil.h"

void get_player_secret_key(mpz_t SK, unsigned int Player)
{
    char key_path[50];
    snprintf(key_path, sizeof(key_path), "./Player_%d/Secret_key_%d.txt", Player, Player);

    FILE* fptr;
    fptr = fopen(key_path, "r");

    char key[MAX_HEXA_MPZ_SIZE]; 

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(SK, key, HEXA_BASE);

    fclose(fptr);
}

void gen_player_signature(mpz_t Player_Signature, mpz_t Player_SK, mpz_t Hashed_Message, unsigned int Delta, mpz_t n) // Génère la signature d'un joueur et la stock dans Player_Signature
{
    mpz_t exp;
    mpz_init(exp);

    mpz_mul_ui(exp, Player_SK, 2 * Delta);

    mpz_powm(Player_Signature, Hashed_Message, exp, n);

    mpz_clear(exp);
}

void gen_proof_of_correctness(mpz_t Player_signature, mpz_t Player_SK, mpz_t Player_VK, mpz_t Dealer_VK, mpz_t Proof_c, mpz_t Proof_z, mpz_t Hashed_Message, unsigned int Delta, mpz_t n)
{
    mpz_t tmp;
    mpz_init(tmp);

    gmp_randstate_t rand;
    gmp_randinit_default(rand);

    unsigned long seed = clock();
    gmp_randseed_ui(rand, seed);

    mpz_urandomb(tmp, rand, (mp_bitcnt_t)((8 * MAIN_HASHED_MESSAGES_BYTES_LEN) + (2 * 8 * (SECONDARY_HASHED_MESSAGES_BYTES_LEN))));

    mpz_t* ptr_for_concatenation = init_mpz_ptr(6); // On veut hacher le concaténé de 6 valeurs

    mpz_set(ptr_for_concatenation[0], Dealer_VK);
    mpz_powm_ui(ptr_for_concatenation[1], Hashed_Message, 4 * Delta, n);
    mpz_set(ptr_for_concatenation[2], Player_VK);
    mpz_powm_ui(ptr_for_concatenation[3], Player_signature, 2, n);
    mpz_powm(ptr_for_concatenation[4], Dealer_VK, tmp, n);
    mpz_powm(ptr_for_concatenation[5], ptr_for_concatenation[1], tmp, n); 

    unsigned char* concatenation_for_hash = mpz_concatenation_to_str(ptr_for_concatenation, 6);

    unsigned int Input_Byte_Len = str_len(concatenation_for_hash);
    secondary_msg_hash_to_mpz(concatenation_for_hash, Input_Byte_Len, Proof_c);

    mpz_mul(Proof_z, Player_SK, Proof_c);
    mpz_add(Proof_z, Proof_z, tmp);

    mpz_clear(tmp);
    free_mpz_ptr(ptr_for_concatenation, 6);
}






