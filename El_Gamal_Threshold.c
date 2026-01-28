#include "El_Gamal_Threshold.h"

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
                change_dealer_el_gamal_parameters();
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

void ask_players_and_decrypted(char* buffer, unsigned int* nbr_players, unsigned int* needed_decrypted)
{
    int valid_quantity = 0;
                
    while (!valid_quantity)
    {
        printf("Entrer le nombre de joueurs : ");
        fgets(buffer, BUFFER_SIZE, stdin);
        *nbr_players = (unsigned int)atoi(buffer);

        printf("Entrer le nombre de déchiffrements partiels nécessaires au déchiffrement total : ");
        fgets(buffer, BUFFER_SIZE, stdin);
        *needed_decrypted = (unsigned int)atoi(buffer);

        if (*nbr_players > *needed_decrypted)
            valid_quantity = 1;
        else
            printf("Le nombre de joueurs doit être strictement supérieur au nombre de déchiffrements partielles nécessaires\n");
    }
}

unsigned int ask_Message(unsigned char** Message) // Affecte le message entré à la chaîne Message et renvoit la taille du message
{
    printf("Entrer le message à chiffrer et à envoyer au coordinateur : ");

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

    printf("Entrez les %u joueurs concernés par le déchiffrement, séparés par un espace (exemple : %c2 4 34 2 11%c pour 3 déchiffrements nécessaires)\n", nbr_involved_players, '"', '"');

    while (!valid_entry)
    {
        printf("Les joueurs sont : ");
        fgets(involved_players_str, BUFFER_SIZE * (nbr_involved_players), stdin);
        valid_entry = get_bounded_numbers_from_str(involved_players_str, nbr_involved_players, involved_players, nbr_players);
    }

    free(involved_players_str);
}

int ask_action(char* buffer, unsigned int* nbr_players, unsigned int* needed_decrypted)
{
    mpz_t Dealer_PK, Sender_PK, Message_mpz, Encrypted_Message, Primitive_Polynomial, Generator;
    unsigned char* Message = NULL;
    int Message_size;
    unsigned int* involved_players = NULL;
    
    char option;
    int option_chosen = 0;
    

    printf("Que voulez-vous faire ?\n");
    printf("g/G : Générer de nouveaux joueurs/clés     s/S : Envoyer un message chiffré     d/D : Déchiffrer un message     r/R : Supprimer les fichiers des joueurs      q/Q : Quitter le programme\n");

    while (!option_chosen)
    {
        fgets(buffer, BUFFER_SIZE, stdin);
        option = buffer[0];
        switch (option)
        {
            case 'g':
            case 'G':

                option_chosen = 1;
                ask_players_and_decrypted(buffer, nbr_players, needed_decrypted);
                send_players_param(*nbr_players, *needed_decrypted);
                full_el_gamal_players_and_keys_gen(*nbr_players, *needed_decrypted);

                printf("Génération des joueurs et de leur clé terminée.\n \n");
                
                break;
            
            
            case 's':
            case 'S':

                option_chosen = 1;

                Message = NULL;
                Message_size = ask_Message(&Message); // Requête du message à envoyer

                mpz_inits(Dealer_PK, Sender_PK, Encrypted_Message, Primitive_Polynomial, Generator, NULL);

                get_el_gamal_public_keys(Primitive_Polynomial, Generator, Dealer_PK);
                send_encrypted_message(Message, Message_size, Dealer_PK, Sender_PK, Encrypted_Message, Primitive_Polynomial, Generator);

                free(Message);
                mpz_clears(Dealer_PK, Sender_PK, Encrypted_Message, Primitive_Polynomial, Generator, NULL);

                break;

            
            case 'd':
            case 'D':

                option_chosen = 1;

                mpz_inits(Message_mpz, Dealer_PK, Encrypted_Message, Sender_PK, Primitive_Polynomial, Generator, NULL);

                coord_get_Encrypted_Message_and_PK(Encrypted_Message, Sender_PK);

                get_players_param(nbr_players, needed_decrypted);
                get_el_gamal_public_keys(Primitive_Polynomial, Generator, Dealer_PK);

                involved_players = malloc((*needed_decrypted) * sizeof(unsigned int));
                ask_involved_players(involved_players, *needed_decrypted, *nbr_players);

                int decryption_accepted = full_message_decryption(buffer, Message_mpz, Encrypted_Message, involved_players, *needed_decrypted, Sender_PK, Primitive_Polynomial, Generator);

                if (decryption_accepted)
                {
                    Message = (unsigned char*)mpz_to_bytes(Message_mpz);
                    printf("\nLe message reçu en clair est : %s\n\n", Message);
                    free(Message);
                }
                else
                    printf("Le déchiffrage a été annulé\n");

                free(involved_players);
                mpz_clears(Message_mpz, Dealer_PK, Encrypted_Message, Sender_PK, Primitive_Polynomial, Generator, NULL);
                break;
            
            
            case 'r':
            case 'R':

                option_chosen = 1;

                get_players_param(nbr_players, needed_decrypted);
                clear_el_gamal_players_files_and_folders(*nbr_players);

                break;

            
            case 'q':
            case 'Q':

                option_chosen = 1;
                return 0;
            
            
            default:

                printf("Entrez un caractère valide.\n");
                break;
        }
    }

    return 1;
}



int main()
{
    char buffer[BUFFER_SIZE]; // Chaîne servant aux entrées utilisateur courtes (souvent utilisées pour la navigation dans le programme)
    unsigned int nbr_players = DEFAULT_NBR_PLAYERS; // Initialisation du nombre de joueurs
    unsigned int needed_decrypted = DEFAULT_NEEDED_SIGNATURES; // Initialisation du nombre de signatures partielles nécessaires

    ask_dealer_parameters(buffer); // Requête sur la modification des clés du dealer

    printf("En cas de première utilisation du programme ou suite à la modification des clés du dealer, il est obligatoire de générer (à nouveau) les clés des joueurs. Sinon, il est possible de déchiffrer un message directement à partir des secrets des joueurs déjà générés.\n");

    int program_running = 1;

    while(program_running)
    {
        program_running = ask_action(buffer, &nbr_players, &needed_decrypted); // Requête sur l'action désirée par l'utilisateur
    }

    return 0;



    /* ZONE DE TESTS */

    // mpz_t v, a, b, c, r;
    // mpz_inits(v, a, b, c, r, NULL);

    // mpz_setbit(v, 1279);
    // mpz_setbit(v, 216);
    // mpz_setbit(v, 0);

    // gmp_printf("v = %Zx \n", v);

    // // mpz_setbit(b, 12);
    // // mpz_setbit(b, 342);
    // // mpz_setbit(b, 1344);
    // // mpz_setbit(b, 1234);
    // // mpz_setbit(b, 2045);
    // // polynomial_invert_mod(c, b, v);

    // // gmp_printf("b = %Zd \n", b);
    // // gmp_printf("c = %Zd \n", c);
    // // gmp_printf("v = %Zx \n", v);

    // mpz_set_str(a, "5f7e69fa6644493f302bb069bd111a6304067a266374229aee63873d3c2c1f49fb59ba0d62398f9b7ed3f4ad5b1f7cb9932b64a5431fc13d26fa7f0623ec9367ae8a3976a04b72578d1e942d02c87e9d9bb865fc3c5d45a779ded9b4187ddfcd9c80e3643b5cc0e8490672b40b89edd22b0272d441fc79a42d3c525c408563d6be3693521b214f0a4d447dcd8abc66e537f1fa6edf2be76c7347c03095b21d42", HEXA_BASE);
    // mpz_set_str(b, "2", HEXA_BASE);
    // polynomial_pow_mod(r, b, a, v);

    // // mpz_set_str(r, "10407932194664399081925240327364085538615262247266704805319112350403608059673360298012239441732324184842421613954281007791383566248323464908139906605677320762924129509389220345773183349661583550472959420547689811211693677147548478866962501384438260291732348885311160828538416585028255604667292825408879256888265733056225297083999787749911284413851571673647296763605040985567184212197376", 10);
    // // gmp_printf("r = %Zd \n", r);
    // // polynomial_mod(r, v);
    // gmp_printf("r = %Zx \n", r);


    // mpz_clears(v, a, b, c, r, NULL);

    // return 0;
}