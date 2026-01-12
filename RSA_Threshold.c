#include "RSA_Threshold.h"

/* Fonctions principales du programme */

void ask_dealer_parameters(char* buffer)
{
    char option;
    int option_chosen = 0;

    printf("Les clés privées et publiques du dealer sont fournies par défaut avec le programme. Il est toute fois possible de les modifier.\n");
    printf("Avant de poursuivre, souhaitez-vous modifier ces paramètres ?\n");
    printf("o/O : Oui     n/N : Non\n");

    while (!option_chosen)
    {
        fgets(buffer, BUFFER_SIZE, stdin);
        option = buffer[0];
        switch (option)
        {
            case 'o':
            case 'O':

                option_chosen = 1;
                change_dealer_parameters();
                break;
            
            case 'n':
            case 'N':

                option_chosen = 1;
                break;
            
            default:

                printf("Entez un caractère valide.\n");
                break;
        }
    }
}

void ask_players_and_signatures(char* buffer, unsigned int* nbr_players, unsigned int* needed_signatures)
{
    int valid_quantity = 0;
                
                while (!valid_quantity)
                {
                    printf("Entrer le nombre de joueurs : ");
                    fgets(buffer, BUFFER_SIZE, stdin);
                    *nbr_players = (unsigned int)atoi(buffer);

                    printf("Entrer le nombre de signatures nécessaires : ");
                    fgets(buffer, BUFFER_SIZE, stdin);
                    *needed_signatures = (unsigned int)atoi(buffer);

                    if (*nbr_players > *needed_signatures)
                        valid_quantity = 1;
                    else
                        printf("Le nombre de joueurs doit être strictement supérieur au nombre de signatures nécessaires\n");
                }
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

void ask_involved_players(unsigned int* involved_players, unsigned int nbr_involved_players, unsigned int nbr_players)
{
    char* involved_players_str = malloc(BUFFER_SIZE * (nbr_involved_players));
                
    int valid_entry = 0;

    printf("Entrez les %u joueurs concernés par la signature, séparés par un espace (exemple : %c2 4 34 2 11%c pour 3 signatures nécessaires)\n", nbr_involved_players, '"', '"');

    while (!valid_entry)
    {
        printf("Les joueurs sont : ");
        fgets(involved_players_str, BUFFER_SIZE * (nbr_involved_players), stdin);
        valid_entry = get_bounded_numbers_from_str(involved_players_str, nbr_involved_players, involved_players, nbr_players);
    }

    free(involved_players_str);
}

int ask_action(char* buffer, unsigned int* nbr_players, unsigned int* needed_signatures)
{
    mpz_t Signature, Hashed_Message, Dealer_VK, n, e;
    unsigned char* Message = NULL;
    int Message_size;
    unsigned int* involved_players = NULL;
    int valid_signature;
    
    char option;
    int option_chosen = 0;
    
    printf("En cas de première utilisation du programme ou suite à la modification des clés du dealer, il est obligatoire de générer (à nouveau) les clés des joueurs. Sinon, il est possible de signer un message directement à partir des secrets des joueurs déjà générés.\n");
    printf("Que voulez-vous faire ?\n");
    printf("g/G : Générer de nouveaux joueurs/clés     s/S : Signer un message     v/V : Vérifier une signature      q/Q : Quitter le programme\n");

    while (!option_chosen)
    {
        fgets(buffer, BUFFER_SIZE, stdin);
        option = buffer[0];
        switch (option)
        {
            case 'g':
            case 'G':

                option_chosen = 1;
                ask_players_and_signatures(buffer, nbr_players, needed_signatures);
                full_players_and_keys_gen(*nbr_players, *needed_signatures);

                printf("Génération des joueurs et de leurs clés terminée.\n \n");
                
                break;
            
            case 's':
            case 'S':

                option_chosen = 1;

                Message = NULL;
                Message_size = ask_Message(&Message); // Requête du message à signer

                mpz_inits(Signature, Hashed_Message, Dealer_VK, n, e, NULL);

                main_msg_hash_to_mpz(Message, Message_size, Hashed_Message);
                unsigned int Delta = facto(*nbr_players);
                get_public_keys(n, e);
                get_dealer_verification_key(Dealer_VK);


                /* Faut trouver une solutions pour garder l'info du nombre de joueurs d'un lancement à un autre du programme (Pas nécessairement ici)*/



                /*  */

                involved_players = malloc((*needed_signatures) * sizeof(unsigned int));
                ask_involved_players(involved_players, *needed_signatures, *nbr_players);

                request_players_signatures_and_PoC(Dealer_VK, buffer, involved_players, *needed_signatures, Message, Message_size, Delta, n);

                if (!check_all_PoC(involved_players, *needed_signatures, Dealer_VK, Hashed_Message, Delta, n))
                {
                    break;
                }
                
                combine_signatures(Signature, Hashed_Message,involved_players, *needed_signatures, Delta, e, n);

                send_signed_message(Message, Signature);

                printf("Message et signature envoyés au vérifieur.\n \n");

                free(involved_players);
                mpz_clears(Signature, Hashed_Message, Dealer_VK, n, e, NULL);

                break;

            case 'v':
            case 'V':

                option_chosen = 1;

                mpz_inits(Signature, Hashed_Message, e, n);

                Message = NULL;
                Message_size = verifier_get_Message(&Message);
                verifier_get_Signature(Signature);

                main_msg_hash_to_mpz(Message, Message_size, Hashed_Message);
                get_public_keys(n, e);

                valid_signature = verify_message_signature(Hashed_Message, Signature, e, n);

                printf(" Si tout va bien, ça vaut zéro : ça vaut %d\n", valid_signature);

                mpz_clears(Signature, Hashed_Message, e, n, NULL);

                break;

            case 'q':
            case 'Q':

                // Surement à modifier pour free des pointeurs
                return 0; 
            
            default:

                printf("Entez un caractère valide.\n");
                break;
        }
    }

    return 0;
}



int main()
{

    unsigned int tab[5] = {1, 5, 6, 7, 8};
    for (int i = 1; i < 5; i++)
    {
        unsigned int j = tab[i];
        lambda(tab, 5, 0, j, 120);
    }

    /* Esquisse du vrai programme */

    char buffer[BUFFER_SIZE]; // Chaîne servant aux entrées utilisateur courtes (souvent utilisées pour la navigation dans le programme)
    unsigned int nbr_players = DEFAULT_NBR_PLAYERS; // Initialisation du nombre de joueurs
    unsigned int needed_signatures = DEFAULT_NEEDED_SIGNATURES; // Initialisation du nombre de signatures partielles nécessaires

    ask_dealer_parameters(buffer); // Requête sur la modification des clés du dealer

    ask_action(buffer, &nbr_players, &needed_signatures); // Requête sur l'action désirée par l'utilisateur





    

    /* Exemple de demande de message et de transformation en élément de Z_n traitable */



    // mpz_t Hashed_Message;
    // mpz_init(Hashed_Message);
    
    // unsigned char* Message = NULL;
    

    // int Message_size = ask_Message(&Message);


    // printf("La taille du message est : %d\n", Message_size);
    // printf("Le message est : %s\n", Message);

    // // bytes_to_mpz(Message, Message_size, Hashed_Message);
    // // gmp_printf("Le message en hexadécimal vaut :  %Zx\n", Hashed_Message);

    // main_msg_hash_to_mpz(Message, Message_size, Hashed_Message);
    // gmp_printf("Le haché est : %Zx\n", Hashed_Message);


    // /* Exemple de génération des secrets etc... à 5 joeurs */

    // mpz_t n, p, q, m, e, d, z, c, sign;
    // mpz_inits(n, p, q, m, e, d, z, c, sign, NULL);

    // get_private_primes(p, q);
    // get_public_keys(n, e);

    // mpz_sub_ui(p, p, 1);
    // mpz_tdiv_q_ui(p, p, 2);

    // mpz_sub_ui(q, q, 1);
    // mpz_tdiv_q_ui(q, q, 2);

    // mpz_mul(m, p, q);

    // mpz_invert(d, e, m);

    // mpz_t* SKs = gen_players_sk(nbr_players, needed_signatures, d, m);
    // mpz_t* VKs = gen_players_vk(nbr_players, SKs, n);

    // write_players_sk(nbr_players, SKs);
    // write_players_vk(nbr_players, VKs);

    // /* Exemple de génération + vérification de signature du joueur 1 */

    // gen_player_signature(sign, SKs[1], Hashed_Message, 120, n);

    // gen_proof_of_correctness(sign, SKs[1], VKs[1], VKs[0], z, c, Hashed_Message, 120, n);

    // if (check_proof_of_correctness(sign, VKs[1], VKs[0], z, c, Hashed_Message, 120, n))
    //     printf("La signature est valide\n");
    // else
    //     printf("La signature n'est pas valide\n");



    // mpz_clears(n, p, q, m, e, d, z, c, sign, NULL);
    
    return 0;
}