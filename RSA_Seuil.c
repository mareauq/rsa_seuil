#include "RSA_Seuil.h"


int main()
{

    /* Exemple de demande de message et de transformation en élément de Z_n traitable */
    mpz_t Hashed_Message;
    mpz_init(Hashed_Message);

    unsigned char* Message = NULL;

    int Message_size = ask_Message(&Message);

    printf("La taille du message est : %d\n", Message_size);
    printf("Le message est : %s\n", Message);

    bytes_to_mpz(Message, Message_size, Hashed_Message);
    gmp_printf("Le message en hexadécimal vaut :  %Zx\n", Hashed_Message);

    main_msg_hash_to_mpz(Message, 3, Hashed_Message);
    gmp_printf("Le haché est : %Zx\n", Hashed_Message);


    /* Exemple de génération des secrets etc... à 5 joeurs */

    unsigned int nbr_players = 5;
    unsigned int needed_sgn = 3;

    mpz_t n, e, d, z, c, sign;
    mpz_inits(n, e, d, z, c, sign, NULL);

    get_public_keys(n, e);
    mpz_invert(d, e, n);

    gmp_printf("n = %Zx\n", n);

    mpz_t* SKs = gen_players_sk(nbr_players, needed_sgn, d, n);
    mpz_t* VKs = gen_players_vk(nbr_players, SKs, n);

    write_players_sk(nbr_players, SKs);
    write_players_vk(nbr_players, VKs);

    /* Exemple de génération + vérification de signature du joueur 1 */

    gen_player_signature(sign, SKs[1], Hashed_Message, 120, n);

    gen_proof_of_correctness(sign, SKs[1], VKs[1], VKs[0], c, z, Hashed_Message, 120, n);

    if (check_proof_of_correctness(sign, VKs[1], VKs[0], c, z, Hashed_Message, 120, n))
        printf("La signature est valide\n");
    else
        printf("La signature n'est pas valide\n");



    mpz_clears(n, e, d, z, c, sign, NULL);
    
    return 0;
}