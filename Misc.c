#include "RSA_Seuil.h"

void ask_players_param() //Pas sûr de celle-là, d'ailleurs elle est restée vide :)
{

}

unsigned int ask_Message(unsigned char** Message) // Affecte le message entré à la chaîne Message et renvoit la taille du message
{
    printf("Entrer le message à signer : ");

    int c;
    unsigned int Message_size = 0;

    while ((c = getchar()) != '\n' && c != EOF)
    {
        unsigned char* tmp = realloc(*Message, Message_size + 2);
        if (!tmp)
        {
            free(*Message);
            *Message = NULL;
            printf("Problème d'allocation mémoire au cours de taille %d\n", Message_size + 2);
            return 0;
        }
        *Message = tmp;
        (*Message)[Message_size] = c;
        Message_size++;
    }

    (*Message)[Message_size] = '\0'; 
    
    return Message_size;
}

unsigned int str_len(unsigned char* str)
{
    unsigned int len = 0;

    while(str[len] != '\0')
    {
        len++;
    }

    return len;
}

mpz_t* init_mpz_ptr(unsigned int size) // Initialise et renvoit un tableau d'entiers mpz de taille size  
{
    mpz_t* ptr = malloc(size*sizeof(mpz_t));

    if(!ptr)
    {
        printf("Problème d'allocation mémoire\n");
        return NULL;
    }

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

void bytes_to_mpz(const unsigned char* Bytes, unsigned int BytesLen, mpz_t Result) // Encode une chaîne de caractère en un entier mpz 
{
    mpz_set_ui(Result, 0);

    for (int i = 0; i < BytesLen - 1; i++)
    {
        mpz_add_ui(Result, Result, Bytes[i]);
        mpz_mul_2exp(Result, Result, (mp_bitcnt_t)8);
    }

    mpz_add_ui(Result, Result, Bytes[BytesLen - 1]);
}

void main_msg_hash_to_mpz(const unsigned char* Message, unsigned int MessageByteLen, mpz_t Hashed_Message) // Renvoit le hashé d'un message de taille MessageByteLen sous forme d'un entier mpz de taille MAIN_HASHED_MESSAGES_BYTES_LEN
{
    unsigned char output[MAIN_HASHED_MESSAGES_BYTES_LEN];
    Keccak_1024(Message, MessageByteLen, output);

    bytes_to_mpz(output, MAIN_HASHED_MESSAGES_BYTES_LEN, Hashed_Message);

}

void secondary_msg_hash_to_mpz(const unsigned char* Message, unsigned int MessageByteLen, mpz_t Hashed_Message) // Renvoit le hashé d'un message de taille MessageByteLen sous forme d'un entier mpz de taille SECONDARY_HASHED_MESSAGES_BYTES_LEN
{
    unsigned char output[SECONDARY_HASHED_MESSAGES_BYTES_LEN];
    Keccak_128(Message, MessageByteLen, output);

    bytes_to_mpz(output, SECONDARY_HASHED_MESSAGES_BYTES_LEN, Hashed_Message);

}

unsigned char* mpz_concatenation_to_str(mpz_t* ptr, unsigned int ptr_size)
{
    unsigned int concatenation_size = 0;
    
    for (int i = 0; i < ptr_size; i++)
    {
        concatenation_size += mpz_sizeinbase(ptr[i], HEXA_BASE);
    }

    unsigned char* concatenation = malloc((concatenation_size + 1) * sizeof(char));

    int concatenation_index = 0;

    for (int i = 0; i < ptr_size; i++)
    {
        unsigned char* str = (unsigned char*)mpz_get_str(NULL, HEXA_BASE, ptr[i]);
        int str_index = 0;

        while (str[str_index] != '\0')
        {
            concatenation[concatenation_index] = str[str_index];

            concatenation_index++;
            str_index++;
            
        }
    }

    concatenation[concatenation_index] = '\0';

    return concatenation;
}