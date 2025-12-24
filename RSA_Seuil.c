#include "RSA_Seuil.h"


int main()
{
    mpz_t Hashed_Message;
    mpz_init(Hashed_Message);

    
    unsigned char* Message = NULL;

    int Message_size = ask_Message(&Message);

    printf("La taille du message est : %d\n", Message_size);
    printf("Le message est : %s\n", Message);

    bytes_to_mpz(Message, Message_size, Hashed_Message);
    gmp_printf("Le message en hexadécimal vaut :  %Zx\n", Hashed_Message);

    msg_hash_to_mpz(Message, 3, Hashed_Message);
    gmp_printf("Le haché est : %Zx\n", Hashed_Message);

    unsigned int nbr_players = 5;
    unsigned int needed_sgn = 3;

    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    get_public_keys(n, e);
    mpz_set_ui(d, 0x9efd2d14f5d85); // En théorie c'est d^(-1) mais là c'est juste random :)

    mpz_t* SKs = gen_players_sk(nbr_players, needed_sgn, d, n);
    mpz_t* VKs = gen_players_vk(nbr_players, SKs, n);

    write_players_sk(nbr_players, SKs);
    write_players_vk(nbr_players, VKs);

    return 0;
}