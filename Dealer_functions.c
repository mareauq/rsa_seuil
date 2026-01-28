#include "RSA_Threshold.h"
#include "El_Gamal_Threshold.h"



/* Fonctions relatives au dealer pour le programme de signature RSA */

// Les nombres premiers en jeux sont de la forme 2p' + 1 avec p' premier

void get_rsa_private_primes(mpz_t p, mpz_t q) // Associe à p et q les valeurs des nombres premiers de Sophie Germain sûrs contenus dans le fichier associé
{
    FILE* fptr;
    fptr = fopen("./Dealer/RSA_Private_primes.txt", "r");

    char key[MAX_HEXA_MPZ_SIZE]; 

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(p, key, HEXA_BASE);
    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(q, key, HEXA_BASE);

    fclose(fptr);
}

void write_rsa_public_keys(mpz_t n, mpz_t e) // Ecrit dans le fichier correspondant la clé publique (n,e) avec n = p*q
{
    FILE* fptr;
    fptr = fopen("./Dealer/Public_key.txt", "w");

    char key[MAX_HEXA_MPZ_SIZE];
    mpz_get_str(key, HEXA_BASE, n);

    fprintf(fptr, "%s\n", key);

    mpz_get_str(key, HEXA_BASE, e);

    fprintf(fptr, "%s\n", key);

    fclose(fptr);
}

void get_rsa_public_keys(mpz_t n, mpz_t e) // Associe à n le module RSA et à e l'exposant de chiffrement contenus dans le fichier correspondant
{
    FILE* fptr;
    fptr = fopen("./Dealer/RSA_Public_keys.txt", "r");

    char key[MAX_HEXA_MPZ_SIZE];

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(n, key, HEXA_BASE);

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(e, key, HEXA_BASE);

    fclose(fptr);
}

void change_dealer_rsa_parameters()
{
    FILE* fptr;
    
    char key[MAX_HEXA_MPZ_SIZE];

    mpz_t p, q, n;
    mpz_inits(p, q, n, NULL);

    printf("Il est rappelé que les nombres p et q doivent être premiers, différents et de la forme 2p' + 1 et 2q' + 1 avec p', q' deux nombres aussi premiers. Pour des raisons de sécurité, il est conseillé de choisir des nombres premiers de taille proche de 512 bits. Enfin la taille de ces entiers ne doit pas dépasser 512 bits\n");

    // Modification des nombres premiers cachés

    fptr = fopen("./Dealer/RSA_Private_primes.txt", "w");

    printf("Veuillez écrire p en hexadécimal : ");
    fgets(key, MAX_HEXA_MPZ_SIZE, stdin);

    fprintf(fptr, "%s", key);

    mpz_set_str(p, key, HEXA_BASE);

    printf("Veuillez écrire q en hexadécimal : ");
    fgets(key, MAX_HEXA_MPZ_SIZE, stdin);

    fprintf(fptr, "%s", key);

    mpz_set_str(q, key, HEXA_BASE);

    fclose(fptr);

    // Modification des clés publiques

    fptr = fopen("./Dealer/RSA_Public_keys.txt", "w");

    mpz_mul(n, p, q);
    mpz_get_str(key, HEXA_BASE, n);

    fprintf(fptr, "%s\n", key);

    printf("Il est rappelé que l'exposant publique e doit être premier et supérieur au nombre de joueurs (la valeur conseillée est 10001).\n");

    printf("Veuillez écrire e en hexadécimal : ");
    fgets(key, MAX_HEXA_MPZ_SIZE, stdin);

    fprintf(fptr, "%s", key);

    fclose(fptr);

    mpz_clears(p, q, n, NULL);
}

/* Gestion des secrets des joueurs */


mpz_t* gen_rsa_players_sk(unsigned int nbr_players, unsigned int needed_signatures, mpz_t d, mpz_t m) // Génère aléatoirement les clés secrètes de chaque joueur et les stock dans un tableau
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

mpz_t* gen_rsa_players_vk(unsigned int nbr_players, mpz_t* SKs, mpz_t n) // Génère aléatoirement les clés de vérification du dealer et de chaque joueur et les stock dans un tableau
{
    gmp_randstate_t rand;
    gmp_randinit_default(rand);

    unsigned long seed = clock();
    gmp_randseed_ui(rand, seed);

    mpz_t v;
    mpz_init(v);
    mpz_urandomm(v, rand, n);
    mpz_powm_ui(v, v, 2, n); // On s'assure que v est un carré dans Z_n

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



void write_rsa_players_sk(unsigned int nbr_players, mpz_t* SKs) // Créer un dossier à chaque joueur et un fichier contenant sa clé secrète
{
    FILE* fptr;
    fptr = fopen("./Dealer/RSA_Secret_key.txt", "w");

    char key[MAX_HEXA_MPZ_SIZE];
    mpz_get_str(key, HEXA_BASE, SKs[0]);

    fprintf(fptr, "%s\n", key);
    fclose(fptr);

    char folder_path[20] = "./Player_0"; 
    char file_path[50] = "./Player_0/RSA_Secret_key_0.txt"; 
    for (int i = 1; i <= nbr_players; i++)
    {
        snprintf(folder_path, sizeof(folder_path), "Player_%d", i);
        mkdir(folder_path, 0777);

        snprintf(file_path, sizeof(file_path), "./Player_%d/RSA_Secret_key_%d.txt", i, i);
        fptr = fopen(file_path, "w");
        mpz_get_str(key, HEXA_BASE, SKs[i]);
        fprintf(fptr, "%s\n", key);
        fclose(fptr);
    } 
}

void write_rsa_players_vk(unsigned int nbr_players, mpz_t* VKs) // Ajoute à chaque joueur sa clé de vérification (doit être appellée après write_rsa_players_sk)
{
    FILE* fptr;
    fptr = fopen("./Dealer/RSA_Verification_key.txt", "w");

    char key[MAX_HEXA_MPZ_SIZE];
    mpz_get_str(key, HEXA_BASE, VKs[0]);

    fprintf(fptr, "%s\n", key);
    fclose(fptr);
 
    char file_path[60] = "./Player_0/RSA_Verification_key_0.txt"; 
    for (int i = 1; i <= nbr_players; i++)
    {
        snprintf(file_path, sizeof(file_path), "./Player_%d/RSA_Verification_key_%d.txt", i, i);
        fptr = fopen(file_path, "w");
        mpz_get_str(key, HEXA_BASE, VKs[i]);
        fprintf(fptr, "%s\n", key);
        fclose(fptr);
    }
}

/* Les tailles des tableaux sont choisies pour pouvoir contenir au minimum n'importe quel int.
En pratique, le nombre de joueurs est très largement inférieur à 2^15 */

void full_rsa_players_and_keys_gen(unsigned int nbr_players, unsigned int needed_signatures)
{
    mpz_t p, q, n, m, e, d;
    mpz_inits(p, q, n, m, e, d, NULL);

    get_rsa_private_primes(p, q);
    get_rsa_public_keys(n, e);

    // On calcule p' = (p - 1)/2 et q' = (q - 1)/2, m = p' * q' et d tel que ed = 1 mod m

    mpz_sub_ui(p, p, 1);
    mpz_tdiv_q_2exp(p, p, 1);

    mpz_sub_ui(q, q, 1);
    mpz_tdiv_q_2exp(q, q, 1);

    
    mpz_mul(m, p, q);
    mpz_invert(d, e, m);

    // On génère les clés

    mpz_t* SKs = gen_rsa_players_sk(nbr_players, needed_signatures, d, m);
    mpz_t* VKs = gen_rsa_players_vk(nbr_players, SKs, n);

    write_rsa_players_sk(nbr_players, SKs);
    write_rsa_players_vk(nbr_players, VKs);

    free_mpz_ptr(SKs, nbr_players + 1);
    free_mpz_ptr(VKs, nbr_players + 1);

    mpz_clears(p, q, n, m, e, d, NULL);
}

void send_players_param(unsigned int nbr_players, unsigned int needed_signatures)
{
    FILE* fptr;
    fptr = fopen("./Coordinator/Players_param.txt", "w");

    fprintf(fptr, "%d\n", nbr_players);
    fprintf(fptr, "%d\n", needed_signatures);

    fclose(fptr);
}

void clear_rsa_players_files_and_folders(unsigned int nbr_players) // Supprime les fichiers et dossiers associés à chaque joueur
{
    char path[60];

    for (int Player = 1; Player <= nbr_players; Player++)
    {
        snprintf(path, sizeof(path), "./Player_%d/RSA_Secret_key_%d.txt", Player, Player);
        
        if (remove(path))
            printf("Problème durant la suppression à l'adresse : %s\n", path);

        snprintf(path, sizeof(path), "./Player_%d/RSA_Verification_key_%d.txt", Player, Player);
        
        if (remove(path))
            printf("Problème durant la suppression à l'adresse : %s\n", path);

        snprintf(path, sizeof(path), "Player_%d", Player);
        
        if (rmdir(path))
            printf("Problème durant la suppression du dossier : %s\n", path);
    }
}




/* Fonctions relatives au dealer pour le programme de signature RSA */


void get_el_gamal_private_key(mpz_t Dealer_SK) // Associe à d la valeur contenu dans le fichier correspondant
{
    FILE* fptr;
    fptr = fopen("./Dealer/El_Gamal_Private_key.txt", "r");

    char key[MAX_HEXA_MPZ_SIZE];

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Dealer_SK, key, HEXA_BASE);

    fclose(fptr);
}

void write_el_gamal_public_keys(mpz_t q, mpz_t g, mpz_t gd) // Ecrit dans le fichier correspondant la clé publique (q,g,g^d)
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

void get_el_gamal_public_keys(mpz_t Primitive_Polynomial, mpz_t Generator, mpz_t Dealer_PK) // Associe à chaque partie de la clé publique sa valeur contenue dans le fichier correspondant
{
    FILE* fptr;
    fptr = fopen("./Dealer/El_Gamal_Public_keys.txt", "r");

    char key[MAX_HEXA_MPZ_SIZE];

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Primitive_Polynomial, key, HEXA_BASE);

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Generator, key, HEXA_BASE);

    fgets(key, MAX_HEXA_MPZ_SIZE, fptr);
    mpz_set_str(Dealer_PK, key, HEXA_BASE);

    fclose(fptr);
}

void change_dealer_el_gamal_parameters()
{
    FILE* fptr;
    
    char key[MAX_HEXA_MPZ_SIZE];

    mpz_t Primitive_Polynomial, Generator, Dealer_PK, Dealer_SK;
    mpz_inits(Primitive_Polynomial, Generator, Dealer_PK, Dealer_SK, NULL);

    printf("Il est rappelé que le corps dans lequel on se fixe doit avoir pour cardinal q une puisance de 2 telle que q-1 soit premier. Pour des raisons de sécurité, il est conseillé de choisir la puissance supérieure à 1000.\n");

    fptr = fopen("./Dealer/El_Gamal_Public_keys.txt", "w");

    printf("Veuillez écrire la représention du polynôme primitif associé à votre corps en hexadécimal : ");
    fgets(key, MAX_HEXA_MPZ_SIZE, stdin);

    fprintf(fptr, "%s", key);

    mpz_set_str(Primitive_Polynomial, key, HEXA_BASE);

    printf("Veuillez écrire la représentation de votre générateur g en hexadécimal : ");
    fgets(key, MAX_HEXA_MPZ_SIZE, stdin);

    fprintf(fptr, "%s", key);

    mpz_set_str(Generator, key, HEXA_BASE);

    printf("Un nouveau couple de clés secrète/publique est créé en conséquence.\n");

    gmp_randstate_t rand;
    gmp_randinit_default(rand);

    unsigned long seed = clock();
    gmp_randseed_ui(rand, seed);

    mpz_urandomb(Dealer_SK, rand, polynomial_deg(Primitive_Polynomial));
    polynomial_pow_mod(Dealer_PK, Generator, Dealer_SK, Primitive_Polynomial);

    mpz_get_str(key, HEXA_BASE, Dealer_PK);
    fprintf(fptr, "%s\n", key);

    gmp_randclear(rand);

    fclose(fptr);

    fptr = fopen("./Dealer/El_Gamal_Private_key.txt", "w");

    mpz_get_str(key, HEXA_BASE, Dealer_SK);
    fprintf(fptr, "%s\n", key);

    fclose(fptr);

    mpz_clears(Primitive_Polynomial, Generator, Dealer_PK, Dealer_SK, NULL);
}


mpz_t* gen_el_gamal_players_sk(unsigned int nbr_players, unsigned int needed_decrypted, mpz_t Dealer_SK, mpz_t Group_order) // Génère aléatoirement les clés secrètes de chaque joueur et les stock dans un tableau
{
    gmp_randstate_t rand;
    gmp_randinit_default(rand);

    unsigned long seed = clock();
    gmp_randseed_ui(rand, seed);

    mpz_t* coeffs = init_mpz_ptr(needed_decrypted + 1);
    mpz_set(coeffs[0], Dealer_SK);

    for (int i = 1; i < needed_decrypted; i++)
    {
        mpz_urandomm(coeffs[i], rand, Group_order);
    }

    mpz_t* SKs = init_mpz_ptr(nbr_players + 1);

    for (int i = 0; i <= nbr_players; i++)
    {
        eval_poly_mod_ui(SKs[i], coeffs, needed_decrypted, i, Group_order);
    }

    gmp_randclear(rand);
    free_mpz_ptr(coeffs, needed_decrypted + 1);

    return SKs;
}

void write_el_gamal_players_sk(unsigned int nbr_players, mpz_t* SKs) // Créer un dossier à chaque joueur et un fichier contenant sa clé secrète
{
    FILE* fptr;

    char key[MAX_HEXA_MPZ_SIZE];

    char folder_path[30] = "./Gamal_Player_0"; 
    char file_path[60] = "./Gamal_Player_0/El_Gamal_Secret_key_0.txt"; 
    for (int i = 1; i <= nbr_players; i++)
    {
        snprintf(folder_path, sizeof(folder_path), "Player_%d", i);
        mkdir(folder_path, 0777);

        snprintf(file_path, sizeof(file_path), "./Player_%d/El_Gamal_Secret_key_%d.txt", i, i);
        fptr = fopen(file_path, "w");
        mpz_get_str(key, HEXA_BASE, SKs[i]);
        fprintf(fptr, "%s\n", key);
        fclose(fptr);
    } 
}

void full_el_gamal_players_and_keys_gen(unsigned int nbr_players, unsigned int needed_signatures)
{
    mpz_t Dealer_PK, Dealer_SK, Primitive_Polynomial, Generator, Group_Order;
    mpz_inits(Dealer_PK, Dealer_SK, Primitive_Polynomial, Generator, Group_Order, NULL);

    get_el_gamal_private_key(Dealer_SK);
    get_el_gamal_public_keys(Primitive_Polynomial, Generator, Dealer_PK);

    compute_group_order(Primitive_Polynomial, Group_Order);

    // On génère les clés

    mpz_t* SKs = gen_el_gamal_players_sk(nbr_players, needed_signatures, Dealer_SK, Group_Order);
    write_el_gamal_players_sk(nbr_players, SKs);

    free_mpz_ptr(SKs, nbr_players + 1);

    mpz_clears(Dealer_PK, Dealer_SK, Primitive_Polynomial, Generator, Group_Order, NULL);
}

void clear_el_gamal_players_files_and_folders(unsigned int nbr_players) // Supprime les fichiers et dossiers associés à chaque joueur
{
    char path[60];

    for (int Player = 1; Player <= nbr_players; Player++)
    {
        snprintf(path, sizeof(path), "./Player_%d/El_Gamal_Secret_key_%d.txt", Player, Player);
        
        if (remove(path))
            printf("Problème durant la suppression à l'adresse : %s\n", path);

        snprintf(path, sizeof(path), "Player_%d", Player);
        
        if (rmdir(path))
            printf("Problème durant la suppression du dossier : %s\n", path);
    }
}