#include "RSA_Threshold.h"


/* Fonctions générales */


unsigned int str_len(unsigned char* str) // Renvoit la taille d'une chaîne de caractères
{
    unsigned int len = 0;

    while(str[len] != '\0')
    {
        len++;
    }

    return len;
}

unsigned int facto(unsigned int k) // Calcule la factorielle d'un unsigned int
{
    if (k == 0)
        return 1;
    
    return k*facto(k-1);
}

int collision_in_array(unsigned int* array, unsigned int array_size) // Renvoit 1 si on trouve une collision dans une liste (par méthode naïve), et 0 sinon. 
{
    for (int i = 0; i < array_size; i++)
    {
        for (int j = 0; j < i; j++)
        {
            if (array[i] == array[j])
                return 1;
        }
    }

    return 0;
}

int get_bounded_numbers_from_str(char* string, unsigned int amount_numbers_expected, unsigned int* numbers_read, unsigned int bound) // Écrit dans numbers_read les nombres lus dans un chaîne de la forme {9 3 4 1 2 4}. Renvoit 0 en cas d'erreur, et 1 sinon.
{
    unsigned int index = 0;
    unsigned int index2 = 0;
    char number_read_str[BUFFER_SIZE] = "0";
    unsigned int number_read = 0;
    unsigned int numbers_counted = 0;

    while (string[index] != '\0' && string[index] != '\n')
    {
        if (string[index] == ' ')
        {
  
            if (index2 != 0)
            {
                number_read_str[index2] = '\0';
                number_read = atoi(number_read_str);

                if (number_read > bound || number_read == 0)
                {
                    printf("Erreur : les nombres entrés doivent être inférieurs à %u et non nuls\n", bound);
                    return 0;
                }

                if (numbers_counted < amount_numbers_expected)
                    numbers_read[numbers_counted] = number_read;
                
                numbers_counted++;
            }

            index2 = 0;
        }

        else
        {
            number_read_str[index2] = string[index];
            index2++;
        }

        index++;
    }


    if (index2 != 0) // On ajoute le dernier nombre si la chaîne ne se termine pas par un espace
        {
            number_read_str[index2] = '\0';
            number_read = atoi(number_read_str);

            if (number_read > bound || number_read == 0)
            {
                printf("Erreur : les nombres entrés doivent être inférieurs à %u et non nuls\n", bound);
                return 0;
            }

            if (numbers_counted < amount_numbers_expected)
                numbers_read[numbers_counted] = number_read;

            numbers_counted++;
        }

    if (numbers_counted != amount_numbers_expected || collision_in_array(numbers_read, amount_numbers_expected))
    {
        printf("Erreur : vous devez entrer exactement %u nombres tous différents, séparés d'un espace (exemple : %c2 4 34 2 11%c)\n", amount_numbers_expected, '"', '"');
        return 0;
    }

    return 1;
}

int lambda_function(mpz_t res, unsigned int* set, unsigned int set_size, unsigned int i, unsigned int j, mpz_t Delta)
{
    mpz_t tmp;
    mpz_init(tmp);

    mpz_set_ui(res, 1);
    mpz_set_ui(tmp, 1);

    for (int k = 0; k < set_size; k++)
    {
        int j_prime = set[k];

        if (i == j_prime)
        {
            printf("La valeur de i ne doit pas faire partie de l'ensemble set. On renvoit zéro.\n");
            return 0;
        }
        
        if (j != j_prime)
        {
            mpz_mul_si(res, res, (int)i - j_prime);
            mpz_mul_si(tmp, tmp, (int)j - j_prime);
        }
    }

    mpz_tdiv_q(tmp, Delta, tmp);
    mpz_mul(res, res, tmp);
    
    mpz_clear(tmp);

    return 1;
}

int L_function(mpz_t res, unsigned int* set, unsigned int set_size, unsigned int i, unsigned int j, mpz_t Group_order)
{
    mpz_t tmp;
    mpz_init(tmp);

    mpz_set_ui(res, 1);
    mpz_set_ui(tmp, 1);

    for (int k = 0; k < set_size; k++)
    {
        int j_prime = set[k];

        if (i == j_prime)
        {
            printf("La valeur de i ne doit pas faire partie de l'ensemble set. On renvoit zéro.\n");
            return 0;
        }
        
        if (j != j_prime)
        {
            mpz_mul_si(res, res, (int)i - j_prime);
            mpz_mul_si(tmp, tmp, (int)j - j_prime);
        }
    }

    mpz_invert(tmp, tmp, Group_order);
    mpz_mul(res, res, tmp);
    
    mpz_clear(tmp);

    return 1;
}

/* Fonctions relatives aux entier de gmp */


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

unsigned char* mpz_concatenation_to_str(mpz_t* ptr, unsigned int ptr_size) // Concatène l'écriture hexadécimale d'un tableau de mpz en une unique chaîne de caractères
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

        free(str);
    }

    concatenation[concatenation_index] = '\0';

    return concatenation;
}



/* Fonctions relatives aux fonctions de hachage */

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

char* mpz_to_bytes(mpz_t Number_mpz)
{
    size_t count = 0;

    unsigned char *Bytes = mpz_export(NULL, &count, 1, 1, 1, 0, Number_mpz);
    char *Bytes_str = malloc(count + 1);

    for (size_t i = 0; i < count; ++i)
        Bytes_str[i] = (char)Bytes[i];

    Bytes_str[count] = '\0';

    free(Bytes);
    return Bytes_str;
}

void main_msg_hash_to_mpz(const unsigned char* Message, unsigned int MessageByteLen, mpz_t Hashed_Message, mpz_t n) // Renvoit le hashé d'un message de taille MessageByteLen sous forme d'un entier mpz de taille MAIN_HASHED_MESSAGES_BYTES_LEN
{
    unsigned char output[MAIN_HASHED_MESSAGES_BYTES_LEN];
    Keccak_1024(Message, MessageByteLen, output);

    bytes_to_mpz(output, MAIN_HASHED_MESSAGES_BYTES_LEN, Hashed_Message);
    mpz_tdiv_r(Hashed_Message, Hashed_Message, n);

}

void secondary_msg_hash_to_mpz(const unsigned char* Message, unsigned int MessageByteLen, mpz_t Hashed_Message) // Renvoit le hashé d'un message de taille MessageByteLen sous forme d'un entier mpz de taille SECONDARY_HASHED_MESSAGES_BYTES_LEN

{
    unsigned char output[SECONDARY_HASHED_MESSAGES_BYTES_LEN];
    Keccak_128(Message, MessageByteLen, output);

    bytes_to_mpz(output, SECONDARY_HASHED_MESSAGES_BYTES_LEN, Hashed_Message);

}


/* Lois du corps F_q pour q = 2^n */

/* Les polynômes en étant à coefficients binaires, il est naturel de les représenter par des nombres : les coefficients du polynôme 
coïncident alors avec la représentation binaire de ce nombre */

int polynomial_deg(mpz_t a) // Calcule le degré de a
{
    if (mpz_cmp_ui(a, 0) == 0)
        return -1;
    
    return (int)(mpz_sizeinbase(a, 2) - 1);
}

void compute_group_order(mpz_t Primitive_Polynomial, mpz_t Group_Order)
{
    int deg = polynomial_deg(Primitive_Polynomial);
    mpz_set_ui(Group_Order, 1);
    mpz_mul_2exp(Group_Order, Group_Order, deg); //Group_Order = 2^n
    mpz_sub_ui(Group_Order, Group_Order, 1); //Group_Order = 2^n - 1
}

void polynomial_mod(mpz_t P, mpz_t Q) // Réduit P modulo Q
{
    mpz_t tmp;
    mpz_init(tmp);
    
    int n = polynomial_deg(P);
    int m = polynomial_deg(Q);

    while (n >= m)
    {
        mpz_mul_2exp(tmp, Q, n - m);
        mpz_xor(P, P, tmp);
        n = polynomial_deg(P);
    }

    mpz_clear(tmp);
}

// Pour notre structure, l'addition consiste en un simple XOR et donc n'est pas spécifiquement implémentée.

void polynomial_mul_mod(mpz_t res, mpz_t a, mpz_t b, mpz_t P) // Multiplication a*b modulo P 
{

    if (mpz_cmp_ui(a, 0) == 0 || mpz_cmp_ui(b, 0) == 0)
        mpz_set_ui(res, 0);
    
    else
    {
        mpz_t tmp, shifted;
        mpz_inits(tmp, shifted, NULL);

        int deg = polynomial_deg(b);

        for (int i = 0; i <= deg; i++)
        {
            if (mpz_tstbit(b, i))
            {
                mpz_mul_2exp(shifted, a, i); // a << i
                mpz_xor(tmp, tmp, shifted);
            }
        }

        polynomial_mod(tmp, P);
        mpz_set(res, tmp);

        mpz_clears(tmp, shifted, NULL);


    }
}


void polynomial_square_mod(mpz_t res, mpz_t a, mpz_t P) // Calcul de a^2 modulo P (à optimiser)
{
    polynomial_mul_mod(res, a, a, P);
}


void polynomial_pow_mod(mpz_t res, mpz_t a, mpz_t exp, mpz_t P) // Exponentiation a^exp modulo P
{
    mpz_t tmp, base;
    mpz_init_set_ui(tmp, 1);
    mpz_init_set(base, a);

    for (long i = 0; i < mpz_sizeinbase(exp, 2); i++) {
        if (mpz_tstbit(exp, i))
        {
            polynomial_mul_mod(tmp, tmp, base, P);
        }
        
        polynomial_square_mod(base, base, P);
    }

    mpz_set(res, tmp);
    mpz_clear(tmp);
    mpz_clear(base);
}


void polynomial_invert_mod(mpz_t res, mpz_t a, mpz_t P) // Renvoit r = a^{-1} mod P
{
    mpz_t u, v, g1, g2, tmp;
    mpz_inits(u, v, g1, g2, tmp, NULL);

    mpz_set(u, a);
    mpz_set_ui(g1, 1);
    mpz_set(v, P);

    int deg_u;
    int deg_v;
    int t;

    while (mpz_cmp_ui(u, 1) != 0)
    {
        deg_u = polynomial_deg(u);
        deg_v = polynomial_deg(v);

        if (deg_u < deg_v) 
        {
            mpz_swap(u, v);
            mpz_swap(g1, g2);
            t = deg_u; 
            deg_u = deg_v; 
            deg_v = t;
        }

        int shift = deg_u - deg_v;

        /* u = u + (v << shift) */
        mpz_mul_2exp(tmp, v, shift);
        mpz_xor(u, u, tmp);

        /* g1 = g1 + (g2 << shift) */
        mpz_mul_2exp(tmp, g2, shift);
        mpz_xor(g1, g1, tmp);
    }

    polynomial_mod(g1, P);
    mpz_set(res, g1);

    mpz_clears(u, v, g1, g2, tmp, NULL);
}

