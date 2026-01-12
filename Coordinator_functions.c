#include "RSA_Threshold.h"



void get_player_verification_key(mpz_t Player_VK, unsigned int Player) // Récupère la clé de vérification du joueur Player
{
    char key_path[60];
    snprintf(key_path, sizeof(key_path), "./Player_%d/Verification_key_%d.txt", Player, Player);

    FILE* fptr;
    fptr = fopen(key_path, "r");

    char key[MAX_HEXA_MPZ_SIZE]; 

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Player_VK, key, HEXA_BASE);

    fclose(fptr);
}

void get_dealer_verification_key(mpz_t Dealer_VK) // Récupère la clé de vérification du Dealer
{
    char* key_path = "./Dealer/Verification_key.txt";

    FILE* fptr;
    fptr = fopen(key_path, "r");

    char key[MAX_HEXA_MPZ_SIZE]; 

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Dealer_VK, key, HEXA_BASE);

    fclose(fptr);
}

int check_proof_of_correctness(mpz_t Player_signature, mpz_t Player_VK, mpz_t Dealer_VK, mpz_t Proof_z, mpz_t Proof_c, mpz_t Hashed_Message, unsigned int Delta, mpz_t n)
{
    mpz_t tmp, Proof_c_prime;
    mpz_inits(tmp, Proof_c_prime, NULL);

    mpz_t* ptr_for_concatenation = init_mpz_ptr(6); // On veut hacher le concaténé de 6 valeurs


    mpz_set(ptr_for_concatenation[0], Dealer_VK);

    mpz_powm_ui(ptr_for_concatenation[1], Hashed_Message, 4 * Delta, n);
    
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

    free_mpz_ptr(ptr_for_concatenation, 6);

    unsigned int Input_Byte_Len = str_len(concatenation_for_hash);
    secondary_msg_hash_to_mpz(concatenation_for_hash, Input_Byte_Len, Proof_c_prime);

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


int check_all_PoC(unsigned int* involved_players, unsigned int needed_signatures, mpz_t Dealer_VK, mpz_t Hashed_Message, unsigned int Delta, mpz_t n)
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
            printf("La signature du joueur %u n'est pas valide.\n", Player);

            mpz_clears(Player_Signature, Player_VK, Proof_z, Proof_c, NULL);
            return 0;
        }
    }

    mpz_clears(Player_Signature, Player_VK, Proof_z, Proof_c, NULL);

    printf("Les %u signatures sont valides\n", needed_signatures);
    return 1;
}

int request_players_signatures_and_PoC(mpz_t Dealer_VK, char* buffer, unsigned int* Players_involved, unsigned int needed_signatures, unsigned char* Message, unsigned int Message_size, unsigned int Delta, mpz_t n)
{    
    for (int i = 0; i < needed_signatures; i++)
    {
        unsigned int Player = Players_involved[i];
        
        printf("Requête de signature au joueur %u :\n \n", Player);
        printf("Le message à signer est : %c%s%c\n", '"', Message, '"');
        printf("Voulez-vous signer ?\n");
        printf("o/O : Oui     p/P : Oui mais avec un signature falsifiée     n/N : Non\n");

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

                
                case 'm':
                case 'M':

                    // A faire plus tard
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

void combine_signatures(mpz_t Signature, mpz_t Hashed_Message, unsigned int* involved_players, unsigned int needed_signatures, unsigned int Delta, mpz_t e, mpz_t n)
{
    mpz_t tmp, w, a, b, e_prime, Player_Signature;
    mpz_inits(tmp, w, a, b, e_prime,  Player_Signature, NULL);
    
    mpz_set_ui(w, 1);

    for (int i = 0; i < needed_signatures; i++)
    {
        unsigned int Player = involved_players[i];
        coord_get_Signature(Player, Player_Signature);

        mpz_set_si(tmp, 2 * lambda(involved_players, needed_signatures, 0, Player, Delta));
        mpz_powm(tmp, Player_Signature, tmp, n);
        mpz_mul(w, w, tmp);
        mpz_tdiv_r(w, w, n);
    }

    mpz_set_ui(e_prime, 4 * Delta * Delta);
    mpz_gcdext(tmp, a, b, e_prime, e);

    gmp_printf("Le pgcd est %Zd on espère que c'est 1 \n", tmp);

    mpz_powm(tmp, w, a, n);
    mpz_powm(Signature, Hashed_Message, b, n);

    mpz_clears(tmp, w, a, b, e_prime,  Player_Signature, NULL);
}

void full_message_signature(unsigned char* Message, unsigned int Message_Size, unsigned int needed_signatures, unsigned int* Players_involved, unsigned int Delta)
{
    mpz_t Hashed_Message;
    mpz_init(Hashed_Message);

    main_msg_hash_to_mpz(Message, Message_Size, Hashed_Message);
}

void send_signed_message(unsigned char* Message, mpz_t Signature)
{
    FILE* fptr;

    fptr = fopen("./Verifier/Message.txt", "w");
    fprintf(fptr, "%s\n", Message);

    fptr = fopen("./Verifier/Signature.txt", "w");
    char* Signature_str = mpz_get_str(NULL, HEXA_BASE, Signature);
    fprintf(fptr, "%s\n", Signature_str);

    fclose(fptr);
}

