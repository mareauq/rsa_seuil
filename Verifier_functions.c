#include "RSA_Threshold.h"


unsigned int verifier_get_Message(unsigned char** Message)
{
    FILE* fptr;
    fptr = fopen("./Verifier/Message.txt", "r");

    int c;
    unsigned int Message_size = 0;

    while ((c = fgetc(fptr)) != '\n' && c != EOF)
    {
        unsigned char* tmp = realloc(*Message, Message_size + 2);
        if (!tmp)
        {
            free(*Message);
            *Message = NULL;
            printf("Problème d'allocation mémoire au cours de taille %u\n", Message_size + 2);
            return 0;
        }

        *Message = tmp;
        (*Message)[Message_size] = c;
        Message_size++;
    }

    if (Message_size == 0)
        return 0;
    
    (*Message)[Message_size] = '\0'; 
    
    return Message_size;
}

void verifier_get_Signature(mpz_t Signature)
{
    FILE* fptr;
    fptr = fopen("./Verifier/Signature.txt", "r");

    char signature_str[MAX_HEXA_MPZ_SIZE]; 

    fgets(signature_str, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Signature, signature_str, HEXA_BASE);

    fclose(fptr);
}

int verify_message_signature(mpz_t Hashed_Message, mpz_t Signature, mpz_t e, mpz_t n)
{
    mpz_t tmp;
    mpz_init(tmp);

    mpz_powm(tmp, Signature, e, n);

    int valid_signature = (mpz_cmp(tmp, Hashed_Message) == 0);

    mpz_clear(tmp);

    return valid_signature;
}