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

void ask_players_and_decryption(char* buffer, unsigned int* nbr_players, unsigned int* needed_signatures)
{
    int valid_quantity = 0;
                
    while (!valid_quantity)
    {
        printf("Entrer le nombre de joueurs : ");
        fgets(buffer, BUFFER_SIZE, stdin);
        *nbr_players = (unsigned int)atoi(buffer);

        printf("Entrer le nombre de déchiffrements partielles nécessaires : ");
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

    printf("Entrez les %u joueurs concernés par le déchiffrement, séparés par un espace (exemple : %c2 4 34 2 11%c pour 3 déchiffrements nécessaires)\n", nbr_involved_players, '"', '"');

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
    mpz_t Signature, Hashed_Message,Hashed_Message1,Hashed_Message2, q,g,gd;
    unsigned char* Message = NULL;
    int Message_size;
    unsigned int* involved_players = NULL;
    int valid_signature;
    
    char option;
    int option_chosen = 0;
    

    printf("Que voulez-vous faire ?\n");
    printf("g/G : Générer de nouveaux joueurs/clés     s/S : Déchiffrer un message     r/R : Supprimer les fichiers des joueurs      q/Q : Quitter le programme\n");

    while (!option_chosen)
    {
        fgets(buffer, BUFFER_SIZE, stdin);
        option = buffer[0];
        switch (option)
        {
            case 'g':
            case 'G':

                option_chosen = 1;
                ask_players_and_decryption(buffer, nbr_players, needed_signatures);
                send_players_param(*nbr_players, *needed_signatures);
                full_players_and_keys_gen(*nbr_players, *needed_signatures);

                printf("Génération des joueurs et de leurs clés terminée.\n \n");
                
                break;
            
            case 's':
            case 'S':

                option_chosen = 1;

                Message = NULL;
                Message_size = ask_Message(&Message); // Requête du message à signer

                mpz_inits(Signature, Hashed_Message,Hashed_Message1,Hashed_Message2, q, g,gd,NULL);

                get_players_param(nbr_players, needed_signatures);
                get_public_keys(q,g,gd);

                full_message_decryption(buffer, Hashed_Message1, Hashed_Message2, Message, Hashed_Message, Message_size, nbr_players, needed_signatures, involved_players,  Signature, q);

                free(Message);
                mpz_clears(Signature, Hashed_Message,Hashed_Message1,Hashed_Message2, q, g,gd, NULL);

                break;

            
            case 'r':
            case 'R':

                option_chosen = 1;

                get_players_param(nbr_players, needed_signatures);
                clear_players_files_and_folders(*nbr_players);

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
    unsigned int needed_signatures = DEFAULT_NEEDED_SIGNATURES; // Initialisation du nombre de signatures partielles nécessaires

    ask_dealer_parameters(buffer); // Requête sur la modification des clés du dealer

    printf("En cas de première utilisation du programme ou suite à la modification des clés du dealer, il est obligatoire de générer (à nouveau) les clés des joueurs. Sinon, il est possible de déchiffrer un message directement à partir des secrets des joueurs déjà générés.\n");

    int program_running = 1;

    while(program_running)
    {
        program_running = ask_action(buffer, &nbr_players, &needed_signatures); // Requête sur l'action désirée par l'utilisateur
    }

    return 0;
}