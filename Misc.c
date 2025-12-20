#include "RSA_Seuil.h"

void ask_players_param() //Pas sûr de celle-là, d'ailleurs elle est restée vide :)
{

}

mpz_t* init_mpz_ptr(unsigned int size) // Initialise et renvoit un tableau d'entiers mpz de taille size  
{
    mpz_t* ptr = malloc(size*sizeof(mpz_t));

    for (int i = 0; i < size; i++)
    {
        mpz_init(ptr[i]);
    }

    return ptr;
}

void free_mpz_ptr(mpz_t* ptr, unsigned int size) // Clear tous les entiers mpz d'un tableau et libère la mémoire du tableau
{

    for (int i = 0; i < size; i++)
    {
        mpz_clear(ptr[i]);
    }

    free(ptr);
}

void eval_poly_mod(mpz_t eval, mpz_t* coeffs, unsigned int deg, mpz_t x, mpz_t mod) // Evalue en x (mpz_t) le polynôme f = coeffs[0] + coeffs[1]*X + ... + coeffs[deg]*X^(deg) dans Z/modZ
{
    mpz_set(eval, coeffs[deg]);
    
    for (int i = deg - 1; i >= 0; i--)
    {
        mpz_mul(eval, eval, x);
        mpz_add(eval, eval, coeffs[i]);
        mpz_tdiv_r(eval, eval, mod);
    }
}

void eval_poly_mod_ui(mpz_t eval, mpz_t* coeffs, unsigned int deg, unsigned long x, mpz_t mod) // Evalue en x (unsigned long) le polynôme f = coeffs[0] + coeffs[1]*X + ... + coeffs[deg]*X^(deg) dans Z/modZ
{
    mpz_set(eval, coeffs[deg]);
    
    for (int i = deg - 1; i >= 0; i--)
    {
        mpz_mul_ui(eval, eval, x);
        mpz_add(eval, eval, coeffs[i]);
        mpz_tdiv_r(eval, eval, mod);
    }
}



void msg_hash_to_mpz(const unsigned char* Message, unsigned int MessageByteLen, mpz_t Hashed_Message) // Renvoit le hashé SHA3 d'un message de taille MessageByteLen sous forme d'un entier mpz
{
    unsigned char* output = malloc(64*sizeof(unsigned char));
    FIPS202_SHA3_512(Message, MessageByteLen, output);

    mpz_set_str(Hashed_Message, (const char*)output, 10);

    free(output);
}