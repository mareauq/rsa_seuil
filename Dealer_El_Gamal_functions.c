#include "El_Gamal_Threshold.h"


/* Gestion des secrets de l'autorité */


void write_public_keys(mpz_t q, mpz_t g, mpz_t gd) // Ecrit dans le fichier correspondant la clé publique (q,g,g^d)
{
    FILE* fptr;
    fptr = fopen("./Dealer_El_Gamal/Public_keys.txt", "w");

    char key[MAX_HEXA_MPZ_SIZE];
    mpz_get_str(key, HEXA_BASE, q);

    fprintf(fptr, "%s\n", key);

    mpz_get_str(key, HEXA_BASE, g);

    fprintf(fptr, "%s\n", key);

    mpz_get_str(key, HEXA_BASE, gd);

    fprintf(fptr, "%s\n", key);

    fclose(fptr);
}

void get_public_keys(mpz_t q, mpz_t g, mpz_t gd) // Associe à q, g et gd leurs valeurs contenus dans le fichier correspondant
{
    FILE* fptr;
    fptr = fopen("./Dealer_El_Gamal/Public_keys.txt", "r");

    char key[MAX_HEXA_MPZ_SIZE];

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(q, key, HEXA_BASE);

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(g, key, HEXA_BASE);

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(gd, key, HEXA_BASE);

    fclose(fptr);
}

void change_dealer_parameters()
{
    FILE* fptr;
    
    char key[MAX_HEXA_MPZ_SIZE];

    mpz_t q, g;
    mpz_inits(q, g, NULL);

    printf("Il est rappelé que le nombre q doit être une puisance de 2 telle que q-1 soit premier. Pour des raisons de sécurité, il est conseillé de choisir la puissance supérieure à 1000.\n");

    fptr = fopen("./Dealer_El_Gamal/Public_keys.txt", "w");

    printf("Veuillez écrire q en hexadécimal : ");
    fgets(key, MAX_HEXA_MPZ_SIZE, stdin);

    fprintf(fptr, "%s", key);

    mpz_set_str(q, key, HEXA_BASE);

    printf("Veuillez écrire g en hexadécimal : ");
    fgets(key, MAX_HEXA_MPZ_SIZE, stdin);

    fprintf(fptr, "%s", key);

    mpz_set_str(g, key, HEXA_BASE);

    fclose(fptr);

    mpz_clears(q,g , NULL);
}

/* Gestion des secrets des joueurs */


mpz_t* gen_players_sk(unsigned int nbr_players, unsigned int needed_signatures, mpz_t d, mpz_t q1) // Génère aléatoirement les clés secrètes de chaque joueur et les stock dans un tableau
{
    gmp_randstate_t rand;
    gmp_randinit_default(rand);

    unsigned long seed = clock();
    gmp_randseed_ui(rand, seed);

    mpz_t* coeffs = init_mpz_ptr(needed_signatures + 1);
    mpz_set(coeffs[0], d);

    for (int i = 1; i < needed_signatures; i++)
    {
        mpz_urandomm(coeffs[i], rand, q1);
    }

    mpz_t* SKs = init_mpz_ptr(nbr_players + 1);

    for (int i = 0; i <= nbr_players; i++)
    {
        eval_poly_mod_ui(SKs[i], coeffs, needed_signatures, i, q1);
    }

    gmp_randclear(rand);
    free_mpz_ptr(coeffs, needed_signatures + 1);

    return SKs;
}

void write_players_sk(unsigned int nbr_players, mpz_t* SKs) // Créer un dossier à chaque joueur et un fichier contenant sa clé secrète
{
    FILE* fptr;
    fptr = fopen("./Dealer_El_Gamal/Private_key.txt", "w");

    char key[MAX_HEXA_MPZ_SIZE];
    mpz_get_str(key, HEXA_BASE, SKs[0]);

    fprintf(fptr, "%s\n", key);
    fclose(fptr);

    char folder_path[20] = "./Gamal_Player_0"; 
    char file_path[50] = "./Gamal_Player_0/Secret_key_0.txt"; 
    for (int i = 1; i <= nbr_players; i++)
    {
        snprintf(folder_path, sizeof(folder_path), "Gamal_Player_%d", i);
        mkdir(folder_path, 0777);

        snprintf(file_path, sizeof(file_path), "./Gamal_Player_%d/Secret_key_%d.txt", i, i);
        fptr = fopen(file_path, "w");
        mpz_get_str(key, HEXA_BASE, SKs[i]);
        fprintf(fptr, "%s\n", key);
        fclose(fptr);
    } 
}

/* Les tailles des tableaux sont choisies pour pouvoir contenir au minimum n'importe quel int.
En pratique, le nombre de joueurs est très largement inférieur à 2^15 */

void full_players_and_keys_gen(unsigned int nbr_players, unsigned int needed_signatures)
{
    mpz_t q, g, d, gd,q1;
    mpz_inits(q, g, d, gd,q1, NULL);

    mpz_sub_ui(q1,q,1);

    get_public_keys(q, g, gd);

    // On génère les clés

    mpz_t* SKs = gen_players_sk(nbr_players, needed_signatures, d, q1);

    write_players_sk(nbr_players, SKs);

    free_mpz_ptr(SKs, nbr_players + 1);

    mpz_clears(q, g, d, gd,q1, NULL);
}

void send_players_param(unsigned int nbr_players, unsigned int needed_signatures)
{
    FILE* fptr;
    fptr = fopen("./Coordinator_El_Gamal/Players_param.txt", "w");

    fprintf(fptr, "%d\n", nbr_players);
    fprintf(fptr, "%d\n", needed_signatures);

    fclose(fptr);
}

void clear_players_files_and_folders(unsigned int nbr_players) // Supprime les fichiers et dossiers associés à chaque joueur
{
    char path[60];

    for (int Player = 1; Player <= nbr_players; Player++)
    {
        snprintf(path, sizeof(path), "./Gamal_Player_%d/Secret_key_%d.txt", Player, Player);
        
        if (remove(path))
            printf("Problème durant la suppression à l'adresse : %s\n", path);


        snprintf(path, sizeof(path), "Gamal_Player_%d", Player);
        
        if (rmdir(path))
            printf("Problème durant la suppression du dossier : %s\n", path);
    }
}