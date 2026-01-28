#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <gmp.h>

/* Macros */

#define DEFAULT_NBR_PLAYERS 5 // Nombre de joueurs par défaut prévus par le programme

#define DEFAULT_NEEDED_SIGNATURES 3 // Nombre de signatures partielles nécessaires à une signature complète  

#define BUFFER_SIZE 64 // Taille des entrées courtes de l'utilisateur (souvent utilisées pour la navigation dans le programme)

#define HEXA_BASE 16 // Base correspondant à une écriture en hexadécimal

#define MAIN_HASHED_MESSAGES_BYTES_LEN 128 // Nombres d'octets de sortie de la fonction de hachage principale pour une sécurite en 1024 bits

#define SECONDARY_HASHED_MESSAGES_BYTES_LEN 16 // Nombres d'octets de sortie de la fonction de hachage secondaire pour une sécurite en 1024 bits

#define MAX_HEXA_MPZ_SIZE 500 // Nombre maximal de caractères nécessaire pour écrire tous les entiers du programme en héxadécimal
// Cette valeur doit être supérieure à 1024/4 = 256 (2 symbole hexadécimaux par octet)



/* Prototypes : Fonctions générales */

unsigned int str_len(unsigned char*);
unsigned int facto(unsigned int);
int collision_in_array(unsigned int*, unsigned int);
int get_bounded_numbers_from_str(char*, unsigned int, unsigned int*, unsigned int);
mpz_t* init_mpz_ptr(unsigned int);
void free_mpz_ptr(mpz_t*, unsigned int);
void eval_poly_mod(mpz_t, mpz_t*, unsigned int, mpz_t, mpz_t);
void eval_poly_mod_ui(mpz_t, mpz_t*, unsigned int, unsigned long, mpz_t);
int L_function(mpz_t, unsigned int*, unsigned int, unsigned int, unsigned int, mpz_t);
unsigned char* mpz_concatenation_to_str(mpz_t*, unsigned int);


/* Prototypes : Lois du corps F_q = F_2[X]/(Primitive_Polynomial) */

int polynomial_deg(mpz_t);
void compute_group_order(mpz_t, mpz_t);
void polynomial_mod(mpz_t, mpz_t);
void polynomial_mul_mod(mpz_t, mpz_t, mpz_t, mpz_t);
void polynomial_pow_mod(mpz_t, mpz_t, mpz_t, mpz_t);
void polynomial_invert_mod(mpz_t, mpz_t, mpz_t);


/* Prototypes : Fonctions relatives aux fonctions d'encodage */

void bytes_to_mpz(const unsigned char*, unsigned int, mpz_t);
char* mpz_to_bytes(mpz_t Number_mpz);




/* Prototypes : Fonctions de gestions des secrets (Dealer) */

void get_el_gamal_private_key(mpz_t);
void write_el_gamal_public_keys(mpz_t, mpz_t, mpz_t);
void get_el_gamal_public_keys(mpz_t, mpz_t, mpz_t);
void change_dealer_el_gamal_parameters();



/* Prototypes : Fonctions de gestions des clés des joueurs (Dealer) */

mpz_t* gen_el_gamal_players_sk(unsigned int, unsigned int, mpz_t, mpz_t);
void write_el_gamal_players_sk(unsigned int, mpz_t*);
void full_el_gamal_players_and_keys_gen(unsigned int, unsigned int);
void send_players_param(unsigned int, unsigned int);
void clear_el_gamal_players_files_and_folders(unsigned int);



/* Prototypes : Fonctions des joueurs */

//void get_private_keys(mpz_t, mpz_t);
void get_player_secret_key(mpz_t, unsigned int);
void gen_player_decryption(mpz_t, mpz_t, mpz_t);
void send_player_decryption(unsigned int, mpz_t);
void full_player_decryption(unsigned int, mpz_t, mpz_t);


/* Prototypes : Fonctions du coordinateur */

void get_players_param(unsigned int*, unsigned int*);
void coord_get_Encrypted_Message_and_PK(mpz_t, mpz_t);
int full_message_decryption(char*, mpz_t, mpz_t, unsigned int*, unsigned int, mpz_t, mpz_t , mpz_t);
int request_players_decrypted(char*, unsigned int*, unsigned int, mpz_t, mpz_t);
void coord_get_decrypted(unsigned int, mpz_t);
void combine_decrypted(mpz_t, mpz_t, unsigned int*, unsigned int, mpz_t, mpz_t, mpz_t);
void clear_el_gamal_coord_files(unsigned int*, unsigned int);


/* Prototypes : Fonctions du sender */

void encrypt_message(unsigned char*, unsigned int, mpz_t, mpz_t, mpz_t, mpz_t, mpz_t);
void send_encrypted_message(unsigned char*, unsigned int, mpz_t, mpz_t, mpz_t, mpz_t, mpz_t);