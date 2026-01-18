#include "El_Gamal_Threshold.h"

void get_player_secret_key(mpz_t Player_SK, unsigned int Player) // Récupère la clé secrète du joueur Player
{
    char key_path[50];
    snprintf(key_path, sizeof(key_path), "./Player_%d/Secret_key_%d.txt", Player, Player);

    FILE* fptr;
    fptr = fopen(key_path, "r");

    char key[MAX_HEXA_MPZ_SIZE]; 

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Player_SK, key, HEXA_BASE);

    fclose(fptr);
}

void gen_player_decryption(mpz_t Player_Signature, mpz_t Player_SK, mpz_t Hashed_Message1, mpz_t q) // Génère le déchiffrement partielle d'un joueur et la stock dans Player_Signature
{
    mpz_powm(Player_Signature, Hashed_Message1, Player_SK, q);
}

void send_player_decryption(unsigned int Player, mpz_t Player_Signature)
{
    FILE* fptr;
    char file_path[60] = "./Coordinator_El_Gamal/Player_Signature_0.txt"; 
    snprintf(file_path, sizeof(file_path), "./Coordinator_El_Gamal/Player_Signature_%d.txt", Player);

    fptr = fopen(file_path, "w");
    char* Signature_str = mpz_get_str(NULL, HEXA_BASE, Player_Signature);
    fprintf(fptr, "%s\n", Signature_str);

    free(Signature_str);
    fclose(fptr);
}

void full_player_decryption(unsigned int Player, mpz_t Hashed_Message1, mpz_t q)
{
    mpz_t Player_SK, Player_Signature;
    mpz_inits(Player_SK, Player_Signature, NULL);

    get_player_secret_key(Player_SK, Player);
    gen_player_decryption(Player_Signature, Player_SK, Hashed_Message1, q);

    send_player_decryption(Player, Player_Signature);

    mpz_clears(Player_SK, Player_Signature, NULL);
}