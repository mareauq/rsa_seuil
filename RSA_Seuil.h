#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gmp.h>

/* Notes : - J'hésite à ajouter sur chaqu fonction un flag pour dire si elle est interne (n'accede à aucune donnée autre que celle du joueur/coord/dealer concerné),
 et externe (par exemple quand le dealer créé les secrets des joueurs ou que les joueurs récupèrent la clé publique). Ca permettrait d'évaluer la sécurité des échanges
 dans l'implémentation (Faudrait en parler à Quisquater à la réunion de mi parours)*/



/* Macros */

#define HEXA_BASE 16 // Base correspondant à une écriture en hexadécimal

#define MAIN_HASHED_MESSAGES_BYTES_LEN 128 // Nombres d'octets de sortie de la fonction de hachage principale pour une sécurite en 1024 bits

#define SECONDARY_HASHED_MESSAGES_BYTES_LEN 16 // Nombres d'octets de sortie de la fonction de hachage secondaire pour une sécurite en 1024 bits

#define MAX_HEXA_MPZ_SIZE 500 // Nombre maximal de caractères nécessaire pour écrire tous les entiers du programme en héxadécimal
// Cette valeur doit juste être supérieure à 1024/4 = 256 (2 symbole hexadécimaux par octet)


/* Fonctions générales */

unsigned int ask_Message(unsigned char**);
unsigned int str_len(unsigned char*);
mpz_t* init_mpz_ptr(unsigned int);
void free_mpz_ptr(mpz_t*, unsigned int);
void eval_poly_mod(mpz_t, mpz_t*, unsigned int, mpz_t, mpz_t);
void eval_poly_mod_ui(mpz_t, mpz_t*, unsigned int, unsigned long, mpz_t);
void Keccak_1024(const unsigned char*, unsigned int, unsigned char*);
void Keccak_128(const unsigned char*, unsigned int, unsigned char*);
void bytes_to_mpz(const unsigned char*, unsigned int, mpz_t);
void main_msg_hash_to_mpz(const unsigned char*, unsigned int, mpz_t);
void secondary_msg_hash_to_mpz(const unsigned char* Message, unsigned int MessageByteLen, mpz_t Hashed_Message);
unsigned char* mpz_concatenation_to_str(mpz_t*, unsigned int);


/* Prototypes : Fonctions du dealer */

mpz_t* gen_players_sk(unsigned int, unsigned int, mpz_t, mpz_t);
mpz_t* gen_players_vk(unsigned int, mpz_t*, mpz_t);
void write_players_sk(unsigned int, mpz_t*);
void write_players_vk(unsigned int, mpz_t*);
void clear_players_files_and_folders(unsigned int);


/* Prototypes : Fonctions de génération de signature */

void get_private_keys(mpz_t, mpz_t);
void get_public_keys(mpz_t, mpz_t);
void write_public_keys(mpz_t, mpz_t);
void get_player_secret_key(mpz_t, unsigned int);
void gen_player_signature(mpz_t, mpz_t, mpz_t, unsigned int, mpz_t);
void gen_proof_of_correctness(mpz_t, mpz_t, mpz_t, mpz_t, mpz_t, mpz_t, mpz_t, unsigned int, mpz_t);


/* Prototypes : Fonctions de partage de signatures */

int check_proof_of_correctness(mpz_t, mpz_t, mpz_t, mpz_t, mpz_t, mpz_t, unsigned int, mpz_t);