#include "RSA_Seuil.h"


/* Gestion des secrets de l'autorité */


// Les nombres premiers en jeux sont de la forme 2p' + 1 avec p' premier

void get_private_keys(mpz_t p, mpz_t q) // Associe à p et q les valeurs des nombres premiers de Sophie Germain sûrs contenus dans le fichier associé
{
    FILE* fptr;
    fptr = fopen("./Dealer/Private_keys.txt", "r");

    char key[10000]; // On suppose les clés secrètes de tailles inférieur à 10000 symboles en base 10

    fgets(key, 10000, fptr);
    mpz_set_str(p, key, 10);
    fgets(key, 10000, fptr);
    mpz_set_str(q, key, 10);

    fclose(fptr);
}

void write_public_key(mpz_t n) // Ecrit dans le fichier correspondant la clé publique n = p*q
{
    FILE* fptr;
    fptr = fopen("./Dealer/Public_key.txt", "w");

    char* key = mpz_get_str(NULL, 10, n);

    fprintf(fptr, "%s\n", key);

    fclose(fptr);
}

void get_public_key(mpz_t n) // Associe à n le module RSA contenu dans le fichier correspondant
{
    FILE* fptr;
    fptr = fopen("./Dealer/Public_key.txt", "r");

    char key[10000]; // On suppose les clés secrètes de tailles inférieur à 10000 symboles en base 10

    fgets(key, 10000, fptr);
    mpz_set_str(n, key, 10);

    fclose(fptr);
}


/* Gestion des secrets des joueurs */


mpz_t* gen_players_sk(unsigned int nbr_players, unsigned int needed_signatures, mpz_t d, mpz_t m) // Génère aléatoirement les clés secrètes de chaque joueur et les stock dans un tableau
{
    gmp_randstate_t rand;
    gmp_randinit_default(rand);

    unsigned long seed = clock();
    gmp_randseed_ui(rand, seed);

    mpz_t* coeffs = init_mpz_ptr(needed_signatures + 1);
    mpz_set(coeffs[0], d);

    for (int i = 1; i < needed_signatures; i++)
    {
        mpz_urandomm(coeffs[i], rand, m);
    }

    mpz_t* SKs = init_mpz_ptr(nbr_players + 1);

    for (int i = 0; i <= nbr_players; i++)
    {
        eval_poly_mod_ui(SKs[i], coeffs, needed_signatures, i, m);
    }

    gmp_randclear(rand);
    free_mpz_ptr(coeffs, needed_signatures + 1);

    return SKs;
}

mpz_t* gen_players_vk(unsigned int nbr_players, mpz_t* SKs, mpz_t n) // Génère aléatoirement les clés de vérification du dealer et de chaque joueur et les stock dans un tableau
{
    gmp_randstate_t rand;
    gmp_randinit_default(rand);

    unsigned long seed = clock();
    gmp_randseed_ui(rand, seed);

    mpz_t v;
    mpz_init(v);
    mpz_urandomm(v, rand, n);

    mpz_t* VKs = init_mpz_ptr(nbr_players + 1);
    mpz_set(VKs[0], v);

    for (int i = 1; i <= nbr_players; i++)
    {
        mpz_powm(VKs[i], v, SKs[i], n);
    }

    gmp_randclear(rand);
    mpz_clear(v);

    return VKs;
}


/* Les seeds de nos états aléatoires devraient être choisies de manière réellement aléatoire, sans utilisation de la fonction clock().
La méthode choisie ici permet de générer des nombres aléatoires variés sans construire la seed soi-même, mais présente une faille de sécurité */



void write_players_sk(unsigned int nbr_players, mpz_t* SKs) // Créer un dossier à chaque joueur et un fichier contenant sa clé secrète
{
    FILE* fptr;
    fptr = fopen("./Dealer/Secret_key.txt", "w");

    char* key = mpz_get_str(NULL, 10, SKs[0]);

    fprintf(fptr, "%s\n", key);
    fclose(fptr);

    char folder_path[20] = "./Player_0"; 
    char file_path[50] = "./Player_0/Secret_key_0.txt"; 
    for (int i = 1; i <= nbr_players; i++)
    {
        snprintf(folder_path, sizeof(folder_path), "Player_%d", i);
        mkdir(folder_path, 0777);

        snprintf(file_path, sizeof(file_path), "./Player_%d/Secret_key_%d.txt", i, i);
        fptr = fopen(file_path, "w");
        key = mpz_get_str(NULL, 10, SKs[i]);
        fprintf(fptr, "%s\n", key);
        fclose(fptr);
    }    
}

void write_players_vk(unsigned int nbr_players, mpz_t* VKs) // Ajoute à chaque joueur sa clé de vérification (doit être appellée après write_players_sk)
{
    FILE* fptr;
    fptr = fopen("./Dealer/Verification_key.txt", "w");

    char* key = mpz_get_str(NULL, 10, VKs[0]);

    fprintf(fptr, "%s\n", key);
    fclose(fptr);
 
    char file_path[60] = "./Player_0/Verification_key_0.txt"; 
    for (int i = 1; i <= nbr_players; i++)
    {
        snprintf(file_path, sizeof(file_path), "./Player_%d/Verification_key_%d.txt", i, i);
        fptr = fopen(file_path, "w");
        key = mpz_get_str(NULL, 10, VKs[i]);
        fprintf(fptr, "%s\n", key);
        fclose(fptr);
    }    
}

void clear_players_files_and_folders(unsigned int nbr_players) // Supprime les fichiers et dossiers associés à chaque joueur
{
    
    
    // Faudra le faire un jour mais la flemme pour l'instant. En plus on est pas sur de tout ce que contiendra chaque dossier donc bon....


}

/* Les tailles des tableaux sont choisies pour pouvoir contenir au minimum n'importe quel int.
En pratique, le nombre de joueurs est très largement inférieur à 2^15 */

