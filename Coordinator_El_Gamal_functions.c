#include "El_Gamal_Threshold.h"


void get_players_param(unsigned int* nbr_player, unsigned int* needed_signature)
{

    FILE* fptr;
    fptr = fopen("./Coordinator_El_Gamal/Players_param.txt", "r");

    char param[BUFFER_SIZE]; 

    fgets(param, BUFFER_SIZE, fptr);
    *nbr_player = atoi(param);
    fgets(param, BUFFER_SIZE, fptr);
    *needed_signature = atoi(param);

    fclose(fptr);
}

void coord_get_decryption(unsigned int Player, mpz_t Player_Signature)
{
    char signature_path[60];
    snprintf(signature_path, sizeof(signature_path), "./Coordinator_El_Gamal/Player_Signature_%d.txt", Player);

    FILE* fptr;
    fptr = fopen(signature_path, "r");

    char signature_str[MAX_HEXA_MPZ_SIZE]; 

    fgets(signature_str, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Player_Signature, signature_str, HEXA_BASE);

    fclose(fptr);
}

int request_players_decryption(char* buffer, unsigned int* Players_involved, unsigned int needed_signatures, mpz_t Hashed_Message1, mpz_t q)
{    
    for (int i = 0; i < needed_signatures; i++)
    {
        unsigned int Player = Players_involved[i];
        
        printf("Requête de déchiffrement partielle au joueur %u :\n \n", Player);
        printf("Voulez-vous déchiffrer ?\n");
        printf("o/O : Oui     n/N : Non\n");

        char option;
        int option_chosen = 0;

        while (!option_chosen)
        {
            fgets(buffer, BUFFER_SIZE, stdin);
            option = buffer[0];
            switch (option)
            {
                case 'o':
                case 'O':

                    option_chosen = 1;
                    full_player_decryption(Player, Hashed_Message1, q);
                    
                    break;

                case 'n':
                case 'N':

                    option_chosen = 1;
                    printf("Le joueur %u a refusé de signer\n", Player);

                    return 0;

                default:

                printf("Entez un caractère valide.\n");
                break;
            }
        }
    }

    return 1;
}

void combine_decryption(mpz_t Message, mpz_t Hashed_Message2, unsigned int* involved_players, unsigned int needed_signatures, mpz_t q) // Cette fonction rend le représentant dans le corps Fq du message
{
    mpz_t tmp, z, Player_Signature;
    mpz_inits(tmp, z, Player_Signature, NULL);

    mpz_set_ui(z, 1);

    for (int i = 0; i < needed_signatures; i++)
    {
        
        unsigned int Player = involved_players[i];
        coord_get_decryption(Player, Player_Signature);

        L_function(tmp, involved_players, needed_signatures, 0, Player);

        mpz_powm(tmp, Player_Signature, tmp, q);

        mpz_mul(z, z, tmp);
        mpz_tdiv_r(z, z, q);
    }
    mpz_invert(z,z,q);
    mpz_mul(Message,z,Hashed_Message2);

    mpz_clears(tmp,z, Player_Signature, NULL);
}

void full_message_decryption(char* buffer, mpz_t Hashed_Message1, mpz_t Hashed_Message2, unsigned char* Message, mpz_t Hashed_Message, unsigned int Message_size, unsigned int* nbr_players, unsigned int* needed_signatures, unsigned int* involved_players, mpz_t Signature, mpz_t q)
{
    main_msg_hash_to_Fq(Message, Message_size, Hashed_Message, q);

    involved_players = malloc((*needed_signatures) * sizeof(unsigned int));
    ask_involved_players(involved_players, *needed_signatures, *nbr_players);
    request_players_decryption(buffer, involved_players, *needed_signatures, Hashed_Message1, q);

    combine_decryption(Message, Hashed_Message2,involved_players, *needed_signatures, q);
    send_decrypted_message(Message, Signature);

    printf("Message et message déchiffré envoyés au vérifieur.\n \n");
    
    clear_coord_files(involved_players, *needed_signatures);
    free(involved_players);
}

void send_signed_message(unsigned char* Message, mpz_t Signature)
{
    FILE* fptr;

    printf("Message : %s\n", Message);

    fptr = fopen("./Verifier_El_Gamal/Message.txt", "w");
    fprintf(fptr, "%s\n", Message);

    fclose(fptr);

    fptr = fopen("./Verifier_El_Gamal/Message_dechiffre.txt", "w");
    char* Signature_str = mpz_get_str(NULL, HEXA_BASE, Signature);
    fprintf(fptr, "%s\n", Signature_str);

    free(Signature_str);
    fclose(fptr);
}

void clear_coord_files(unsigned int* involved_players, unsigned int needed_signatures)
{
    char file_path[60];

    for (int i = 0; i < needed_signatures; i++)
    {
        unsigned int Player = involved_players[i];

        snprintf(file_path, sizeof(file_path), "./Coordinator_El_Gamal/Player_Signature_%d.txt", Player);
        
        if (remove(file_path))
            printf("Problème durant la suppressions à l'adresse : %s\n", file_path);

    }
}