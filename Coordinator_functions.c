#include "RSA_Threshold.h"
#include "El_Gamal_Threshold.h"


/* Fonctions relatives au coordinateur dans la signature RSA */

void get_players_param(unsigned int* nbr_player, unsigned int* needed_signature)
{

    FILE* fptr;
    fptr = fopen("./Coordinator/Players_param.txt", "r");

    char param[BUFFER_SIZE]; 

    fgets(param, BUFFER_SIZE, fptr);
    *nbr_player = atoi(param);
    fgets(param, BUFFER_SIZE, fptr);
    *needed_signature = atoi(param);

    fclose(fptr);
}

void get_player_verification_key(mpz_t Player_VK, unsigned int Player) // Récupère la clé de vérification du joueur Player
{
    char key_path[60];
    snprintf(key_path, sizeof(key_path), "./Player_%d/RSA_Verification_key_%d.txt", Player, Player);

    FILE* fptr;
    fptr = fopen(key_path, "r");

    char key[MAX_HEXA_MPZ_SIZE]; 

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Player_VK, key, HEXA_BASE);

    fclose(fptr);
}

void get_dealer_verification_key(mpz_t Dealer_VK) // Récupère la clé de vérification du Dealer
{
    char* key_path = "./Dealer/RSA_Verification_key.txt";

    FILE* fptr;
    fptr = fopen(key_path, "r");

    char key[MAX_HEXA_MPZ_SIZE]; 

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Dealer_VK, key, HEXA_BASE);

    fclose(fptr);
}

int check_proof_of_correctness(mpz_t Player_signature, mpz_t Player_VK, mpz_t Dealer_VK, mpz_t Proof_z, mpz_t Proof_c, mpz_t Hashed_Message, mpz_t Delta, mpz_t n)
{
    mpz_t tmp, Proof_c_prime;
    mpz_inits(tmp, Proof_c_prime, NULL);

    mpz_t* ptr_for_concatenation = init_mpz_ptr(6); // On veut hacher le concaténé de 6 valeurs


    mpz_set(ptr_for_concatenation[0], Dealer_VK);

    mpz_mul_ui(tmp, Delta, 4);
    mpz_powm(ptr_for_concatenation[1], Hashed_Message, tmp, n);
    
    mpz_set(ptr_for_concatenation[2], Player_VK);

    mpz_powm_ui(ptr_for_concatenation[3], Player_signature, 2, n);

    mpz_invert(tmp, Player_VK, n);
    mpz_powm(tmp, tmp, Proof_c, n);
    mpz_powm(ptr_for_concatenation[4], Dealer_VK, Proof_z, n);
    mpz_mul(ptr_for_concatenation[4], ptr_for_concatenation[4], tmp);
    mpz_tdiv_r(ptr_for_concatenation[4], ptr_for_concatenation[4], n);
    
    mpz_invert(tmp, ptr_for_concatenation[3], n);
    mpz_powm(tmp, tmp, Proof_c, n);
    mpz_powm(ptr_for_concatenation[5], ptr_for_concatenation[1], Proof_z, n);
    mpz_mul(ptr_for_concatenation[5], ptr_for_concatenation[5], tmp);
    mpz_tdiv_r(ptr_for_concatenation[5], ptr_for_concatenation[5], n);

    unsigned char* concatenation_for_hash = mpz_concatenation_to_str(ptr_for_concatenation, 6);

    unsigned int Input_Byte_Len = str_len(concatenation_for_hash);
    secondary_msg_hash_to_mpz(concatenation_for_hash, Input_Byte_Len, Proof_c_prime);

    free(concatenation_for_hash);
    free_mpz_ptr(ptr_for_concatenation, 6);

    if (mpz_cmp(Proof_c, Proof_c_prime) == 0)
    {
        mpz_clears(tmp, Proof_c_prime, NULL);
        return 1;
    }

    mpz_clears(tmp, Proof_c_prime, NULL);
    return 0;
}

void coord_get_Signature(unsigned int Player, mpz_t Player_Signature)
{
    char signature_path[60];
    snprintf(signature_path, sizeof(signature_path), "./Coordinator/Player_Signature_%d.txt", Player);

    FILE* fptr;
    fptr = fopen(signature_path, "r");

    char signature_str[MAX_HEXA_MPZ_SIZE]; 

    fgets(signature_str, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Player_Signature, signature_str, HEXA_BASE);

    fclose(fptr);
}

void coord_get_PoC(unsigned int Player, mpz_t Proof_z, mpz_t Proof_c)
{
    char PoC_path[60];
    snprintf(PoC_path, sizeof(PoC_path), "./Coordinator/Player_PoC_%d.txt", Player);

    FILE* fptr;
    fptr = fopen(PoC_path, "r");

    char PoC_str[MAX_HEXA_MPZ_SIZE]; 

    fgets(PoC_str, MAX_HEXA_MPZ_SIZE, fptr); // On lit la valeur de Proof_z
    mpz_set_str(Proof_z, PoC_str, HEXA_BASE);

    fgets(PoC_str, MAX_HEXA_MPZ_SIZE, fptr); // On lit la valeur de Proof_c
    mpz_set_str(Proof_c, PoC_str, HEXA_BASE);

    fclose(fptr);
}


int check_all_PoC(unsigned int* involved_players, unsigned int needed_signatures, mpz_t Dealer_VK, mpz_t Hashed_Message, mpz_t Delta, mpz_t n)
{
    mpz_t Player_Signature, Player_VK, Proof_z, Proof_c;
    mpz_inits(Player_Signature, Player_VK, Proof_z, Proof_c, NULL);
    
    for (int i = 0; i < needed_signatures; i++)
    {
        unsigned int Player = involved_players[i];
        
        get_player_verification_key(Player_VK, Player);
        coord_get_Signature(Player, Player_Signature);
        coord_get_PoC(Player, Proof_z, Proof_c);
        
        int valid_signature = check_proof_of_correctness(Player_Signature, Player_VK, Dealer_VK, Proof_z, Proof_c, Hashed_Message, Delta, n);

        if (!valid_signature)
        {
            printf("La signature du joueur %u n'est pas valide.\n\n", Player);

            mpz_clears(Player_Signature, Player_VK, Proof_z, Proof_c, NULL);
            return 0;
        }
    }

    mpz_clears(Player_Signature, Player_VK, Proof_z, Proof_c, NULL);

    printf("Les %u signatures sont valides\n\n", needed_signatures);
    return 1;
}

int request_players_signatures_and_PoC(mpz_t Dealer_VK, char* buffer, unsigned int* Players_involved, unsigned int needed_signatures, unsigned char* Message, unsigned int Message_size, mpz_t Delta, mpz_t n)
{    
    for (int i = 0; i < needed_signatures; i++)
    {
        unsigned int Player = Players_involved[i];
        
        printf("Requête de signature au joueur %u :\n \n", Player);
        printf("Le message à signer est : %c%s%c\n", '"', Message, '"');
        printf("Voulez-vous signer ?\n");
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
                    full_player_signature_and_PoC(Dealer_VK, Player, Message, Message_size, Delta, n);
                    
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

void combine_signatures(mpz_t Signature, mpz_t Hashed_Message, unsigned int* involved_players, unsigned int needed_signatures, mpz_t Delta, mpz_t e, mpz_t n)
{
    mpz_t tmp, w, a, b, e_prime, Player_Signature;
    mpz_inits(tmp, w, a, b, e_prime,  Player_Signature, NULL);
    
    mpz_set_ui(w, 1);

    for (int i = 0; i < needed_signatures; i++)
    {
        
        unsigned int Player = involved_players[i];
        coord_get_Signature(Player, Player_Signature);

        
        lambda_function(tmp, involved_players, needed_signatures, 0, Player, Delta);

        mpz_mul_ui(tmp, tmp, 2);
        mpz_powm(tmp, Player_Signature, tmp, n);

        mpz_mul(w, w, tmp);
        mpz_tdiv_r(w, w, n);
    }


    mpz_mul(e_prime, Delta, Delta);
    mpz_mul_ui(e_prime, e_prime, 4);
    mpz_gcdext(tmp, a, b, e_prime, e);

    mpz_powm(tmp, w, a, n);
    mpz_powm(Signature, Hashed_Message, b, n);
    mpz_mul(Signature, tmp, Signature);
    mpz_tdiv_r(Signature, Signature, n);

    mpz_clears(tmp, w, a, b, e_prime, Player_Signature, NULL);
}

void full_message_signature(char* buffer, mpz_t Hashed_Message, unsigned char* Message, unsigned int Message_size, unsigned int* nbr_players, unsigned int* needed_signatures, unsigned int* involved_players, mpz_t Dealer_VK, mpz_t Signature, mpz_t Delta, mpz_t e, mpz_t n)
{
    main_msg_hash_to_mpz(Message, Message_size, Hashed_Message, n);
    
    if (request_players_signatures_and_PoC(Dealer_VK, buffer, involved_players, *needed_signatures, Message, Message_size, Delta, n))
    {
        if (check_all_PoC(involved_players, *needed_signatures, Dealer_VK, Hashed_Message, Delta, n))
        {
            combine_signatures(Signature, Hashed_Message,involved_players, *needed_signatures, Delta, e, n);
            send_signed_message(Message, Signature);

            printf("Message et signature envoyés au vérifieur.\n \n");
        }

        clear_rsa_coord_files(involved_players, *needed_signatures);
    }


}

void send_signed_message(unsigned char* Message, mpz_t Signature)
{
    FILE* fptr;

    printf("Message : %s\n", Message);

    fptr = fopen("./Verifier/Message.txt", "w");
    fprintf(fptr, "%s\n", Message);

    fclose(fptr);

    fptr = fopen("./Verifier/Signature.txt", "w");
    char* Signature_str = mpz_get_str(NULL, HEXA_BASE, Signature);
    fprintf(fptr, "%s\n", Signature_str);

    free(Signature_str);
    fclose(fptr);
}

void clear_rsa_coord_files(unsigned int* involved_players, unsigned int needed_signatures)
{
    char file_path[60];

    for (int i = 0; i < needed_signatures; i++)
    {
        unsigned int Player = involved_players[i];

        snprintf(file_path, sizeof(file_path), "./Coordinator/Player_Signature_%d.txt", Player);
        
        if (remove(file_path))
            printf("Problème durant la suppressions à l'adresse : %s\n", file_path);

        snprintf(file_path, sizeof(file_path), "./Coordinator/Player_PoC_%d.txt", Player);
        
        if (remove(file_path))
            printf("Problème durant la suppressions à l'adresse : %s\n", file_path);
    }
}


/* Fonctions relatives au coordinateur dans le chiffrement El Gamal */

void coord_get_Encrypted_Message_and_PK(mpz_t Encrypted_Message, mpz_t Sender_PK)
{
    FILE* fptr;
    fptr = fopen("./Coordinator/Encrypted_Message.txt", "r");

    char Encrypted_Message_str[MAX_HEXA_MPZ_SIZE]; 

    fgets(Encrypted_Message_str, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Encrypted_Message, Encrypted_Message_str, HEXA_BASE);

    fgets(Encrypted_Message_str, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Sender_PK, Encrypted_Message_str, HEXA_BASE);

    fclose(fptr);
}

void coord_get_decrypted(unsigned int Player, mpz_t Player_Decrypted)
{
    char decrypted_path[60];
    snprintf(decrypted_path, sizeof(decrypted_path), "./Coordinator/Player_Decrypted_%d.txt", Player);

    FILE* fptr;
    fptr = fopen(decrypted_path, "r");

    char decrypted_str[MAX_HEXA_MPZ_SIZE]; 

    fgets(decrypted_str, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Player_Decrypted, decrypted_str, HEXA_BASE);

    fclose(fptr);
}

int request_players_decrypted(char* buffer, unsigned int* Players_involved, unsigned int needed_decrypted, mpz_t Sender_PK, mpz_t Primitive_Polynomial)
{    
    for (int i = 0; i < needed_decrypted; i++)
    {
        unsigned int Player = Players_involved[i];
        
        printf("Requête de déchiffrement au joueur %u :\n \n", Player);
        printf("Voulez-vous déchiffrer le message reçu ?\n");
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
                    full_player_decryption(Player, Sender_PK, Primitive_Polynomial);
                    
                    break;

                case 'n':
                case 'N':

                    option_chosen = 1;
                    printf("Le joueur %u a refusé de déchiffrer\n", Player);

                    return 0;

                default:

                printf("Entez un caractère valide.\n");
                break;
            }
        }
    }

    return 1;
}

void combine_decrypted(mpz_t Message_mpz, mpz_t Encrypted_Message, unsigned int* involved_players, unsigned int needed_decrypted, mpz_t Primitive_Polynomial, mpz_t Generator, mpz_t Group_order) // Cette fonction rend le représentant dans le corps Fq du message
{
    mpz_t tmp, z, Player_Decrypted;
    mpz_inits(tmp, z, Player_Decrypted, NULL);

    mpz_set_ui(z, 1);

    for (int i = 0; i < needed_decrypted; i++)
    {
        
        unsigned int Player = involved_players[i];
        coord_get_decrypted(Player, Player_Decrypted);

        L_function(tmp, involved_players, needed_decrypted, 0, Player, Group_order);

        polynomial_pow_mod(tmp, Player_Decrypted, tmp, Primitive_Polynomial);
        polynomial_mul_mod(z, z, tmp, Primitive_Polynomial);
    }

    polynomial_invert_mod(z, z, Primitive_Polynomial);
    polynomial_mul_mod(Message_mpz, z, Encrypted_Message, Primitive_Polynomial);

    mpz_clears(tmp, z, Player_Decrypted, NULL);
}

void clear_el_gamal_coord_files(unsigned int* involved_players, unsigned int needed_decrypted)
{
    char file_path[60];

    for (int i = 0; i < needed_decrypted; i++)
    {
        unsigned int Player = involved_players[i];

        snprintf(file_path, sizeof(file_path), "./Coordinator/Player_Decrypted_%d.txt", Player);
        
        if (remove(file_path))
            printf("Problème durant la suppressions à l'adresse : %s\n", file_path);
    }
}

int full_message_decryption(char* buffer, mpz_t Message_mpz, mpz_t Encrypted_Message, unsigned int* involved_players, unsigned int needed_decrypted, mpz_t Sender_PK, mpz_t Primitive_Polynomial, mpz_t Generator)
{
    mpz_t Group_order;
    mpz_init(Group_order);

    int decryption_accepted = request_players_decrypted(buffer, involved_players, needed_decrypted, Sender_PK, Primitive_Polynomial);

    compute_group_order(Primitive_Polynomial, Group_order);

    if (decryption_accepted)
        combine_decrypted(Message_mpz, Encrypted_Message, involved_players, needed_decrypted, Primitive_Polynomial, Generator, Group_order);
    
    clear_el_gamal_coord_files(involved_players, needed_decrypted);
    mpz_clear(Group_order);

    return decryption_accepted;
}