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



/* Prototypes : Fonctions principales */


void ask_dealer_parameters(char*);
unsigned int ask_Message(unsigned char**);
void ask_involved_players(unsigned int*, unsigned int, unsigned int);
void ask_players_and_signatures(char*, unsigned int*, unsigned int*);
int ask_action(char*, unsigned int*, unsigned int*);



/* Prototypes : Fonctions générales */

unsigned int str_len(unsigned char*);
unsigned int facto(unsigned int);
int collision_in_array(unsigned int*, unsigned int);
int get_bounded_numbers_from_str(char*, unsigned int, unsigned int*, unsigned int);
mpz_t* init_mpz_ptr(unsigned int);
void free_mpz_ptr(mpz_t*, unsigned int);
void eval_poly_mod(mpz_t, mpz_t*, unsigned int, mpz_t, mpz_t);
void eval_poly_mod_ui(mpz_t, mpz_t*, unsigned int, unsigned long, mpz_t);
int lambda_function(mpz_t, unsigned int*, unsigned int, unsigned int, unsigned int, mpz_t);
int L_function(mpz_t, unsigned int*, unsigned int, unsigned int, mpz_t);
unsigned char* mpz_concatenation_to_str(mpz_t*, unsigned int);



/* Prototypes : Fonctions relatives aux fonctions de hachage */

void Keccak_1024(const unsigned char*, unsigned int, unsigned char*);
void Keccak_128(const unsigned char*, unsigned int, unsigned char*);
void bytes_to_mpz(const unsigned char*, unsigned int, mpz_t);
void main_msg_hash_to_mpz(const unsigned char*, unsigned int, mpz_t, mpz_t);
void main_msg_hash_to_Fq(const unsigned char*, unsigned int, mpz_t, mpz_t);
void secondary_msg_hash_to_mpz(const unsigned char* Message, unsigned int MessageByteLen, mpz_t Hashed_Message);



/* Prototypes : Fonctions de gestions des secrets (Dealer) */

void get_private_primes(mpz_t, mpz_t);
void write_public_keys(mpz_t, mpz_t);
void get_public_keys(mpz_t, mpz_t);
void change_dealer_parameters();



/* Prototypes : Fonctions de gestions des clés des joueurs (Dealer) */
mpz_t* gen_players_sk(unsigned int, unsigned int, mpz_t, mpz_t);
void write_players_sk(unsigned int, mpz_t*);
void full_players_and_keys_gen(unsigned int, unsigned int);
void send_players_param(unsigned int, unsigned int);
void clear_players_files_and_folders(unsigned int);



/* Prototypes : Fonctions des joueurs */

void get_private_keys(mpz_t, mpz_t);
void write_public_keys(mpz_t, mpz_t);
void get_player_secret_key(mpz_t, unsigned int);
void gen_player_decryption(mpz_t, mpz_t, mpz_t, mpz_t, mpz_t);
void send_player_decryption(unsigned int, mpz_t);
void full_player_decryption(unsigned int, mpz_t, mpz_t);


/* Prototypes : Fonctions du coordinateur */

void get_players_param(unsigned int*, unsigned int*);
void full_message_decryption(char*, mpz_t, unsigned char*, unsigned int, unsigned int*, unsigned int*, unsigned int*, mpz_t, mpz_t, mpz_t, mpz_t, mpz_t);
void send_signed_message(unsigned char*, mpz_t);
int request_players_decryption(mpz_t, char*, unsigned int*, unsigned int, unsigned char*, unsigned int, mpz_t, mpz_t);
void coord_get_decryption(unsigned int, mpz_t);
void combine_decryption(mpz_t, mpz_t, unsigned int*, unsigned int, mpz_t, mpz_t, mpz_t);
void clear_coord_files(unsigned int*, unsigned int);

/* Prototypes : Fonctions du vérifieur */

unsigned int verifier_get_Message(unsigned char**);
void verifier_get_Signature(mpz_t);
int verify_message_signature(mpz_t, mpz_t);