#include "RSA_Seuil.h"

void get_player_secret_key(mpz_t SK, unsigned int Player)
{
    char key_path[50];
    snprintf(key_path, sizeof(key_path), "./Player_%d/Secret_key_%d.txt", Player, Player);

    FILE* fptr;
    fptr = fopen(key_path, "r");

    char key[10000]; // On suppose les clés secrètes  des joueurs de tailles inférieur à 10000 symboles en héxadécimal

    fgets(key, 10000, fptr);
    mpz_set_str(SK, key, 16);

    fclose(fptr);
}

void gen_player_signature(mpz_t Signature, unsigned int Player, mpz_t Hashed_Message, unsigned int Delta, mpz_t n)
{
    mpz_t SK, exp;
    mpz_inits(SK, exp, NULL);

    get_player_secret_key(SK, Player);
    mpz_mul_ui(exp, SK, 2 * Delta);

    mpz_powm(Signature, Hashed_Message, exp, n);

    mpz_clears(SK, exp, NULL);
}






