#include "El_Gamal_Threshold.h"


void encrypt_message(unsigned char* Message, unsigned int Message_size, mpz_t Dealer_PK, mpz_t Sender_PK, mpz_t Encrypted_Message, mpz_t Primitive_Polynomial, mpz_t Generator) // Chiffre Message selon le protocole attendu
{
    mpz_t tmp;
    mpz_init(tmp);

    gmp_randstate_t rand;
    gmp_randinit_default(rand);

    unsigned long seed = clock();
    gmp_randseed_ui(rand, seed);

    mpz_urandomb(tmp, rand, polynomial_deg(Primitive_Polynomial));
    polynomial_pow_mod(Sender_PK, Generator, tmp, Primitive_Polynomial); // Sender_PK = g^b
    polynomial_pow_mod(Encrypted_Message, Dealer_PK, tmp, Primitive_Polynomial); // Encrypted_Message = (g^d)^b

    bytes_to_mpz(Message, Message_size, tmp); // Encodage du message en mpz_t
    polynomial_mul_mod(Encrypted_Message, Encrypted_Message, tmp, Primitive_Polynomial); // Encrypted_Message = M*(g^d)^b

    mpz_clear(tmp);
    gmp_randclear(rand);
}

void send_encrypted_message(unsigned char* Message, unsigned int Message_size, mpz_t Dealer_PK, mpz_t Sender_PK, mpz_t Encrypted_Message, mpz_t Primitive_Polynomial, mpz_t Generator) // Envoie le chiffré au coordinateur
{
    
    FILE* fptr;

    printf("Envoi du message : %s\n\n", Message);

    encrypt_message(Message, Message_size, Dealer_PK, Sender_PK, Encrypted_Message, Primitive_Polynomial, Generator);

    char Encrypted_Message_str[MAX_HEXA_MPZ_SIZE];

    fptr = fopen("./Coordinator/Encrypted_Message.txt", "w");
    mpz_get_str(Encrypted_Message_str, HEXA_BASE, Encrypted_Message);
    fprintf(fptr, "%s\n", Encrypted_Message_str);

    mpz_get_str(Encrypted_Message_str, HEXA_BASE, Sender_PK);
    fprintf(fptr, "%s\n", Encrypted_Message_str);

    fclose(fptr);
}