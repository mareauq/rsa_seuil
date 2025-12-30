#include "RSA_Seuil.h"

int check_proof_of_correctness(mpz_t Player_signature, mpz_t Player_VK, mpz_t Dealer_VK, mpz_t Proof_c, mpz_t Proof_z, mpz_t Hashed_Message, unsigned int Delta, mpz_t n)
{
    mpz_t tmp, Proof_c_prime;
    mpz_inits(tmp, Proof_c_prime, NULL);

    mpz_t* ptr_for_concatenation = init_mpz_ptr(6); // On veut hacher le concaténé de 6 valeurs


    mpz_set(ptr_for_concatenation[0], Dealer_VK);

    mpz_powm_ui(ptr_for_concatenation[1], Hashed_Message, 4 * Delta, n);
    
    mpz_set(ptr_for_concatenation[2], Player_VK);

    mpz_powm_ui(ptr_for_concatenation[3], Player_signature, 2, n);

    mpz_invert(tmp, Player_VK, n);
    mpz_powm(tmp, tmp, Proof_c, n);
    mpz_powm(ptr_for_concatenation[4], Dealer_VK, Proof_z, n);
    mpz_mul(ptr_for_concatenation[4], ptr_for_concatenation[4], tmp);
    mpz_tdiv_r(ptr_for_concatenation[4], ptr_for_concatenation[4], n);
    
    mpz_invert(tmp, ptr_for_concatenation[3], n);
    mpz_powm(tmp, tmp, Proof_c, n);
    mpz_powm(ptr_for_concatenation[5], ptr_for_concatenation[1], Proof_z, n);
    mpz_mul(ptr_for_concatenation[5], ptr_for_concatenation[5], tmp);
    mpz_tdiv_r(ptr_for_concatenation[5], ptr_for_concatenation[5], n);

    unsigned char* concatenation_for_hash = mpz_concatenation_to_str(ptr_for_concatenation, 6);

    free_mpz_ptr(ptr_for_concatenation, 6);

    unsigned int Input_Byte_Len = str_len(concatenation_for_hash);
    secondary_msg_hash_to_mpz(concatenation_for_hash, Input_Byte_Len, Proof_c_prime);

    if (mpz_cmp(Proof_c, Proof_c_prime) == 0)
    {
        mpz_clears(tmp, Proof_c_prime, NULL);
        return 1;
    }

    mpz_clears(tmp, Proof_c_prime, NULL);
    return 0;
}