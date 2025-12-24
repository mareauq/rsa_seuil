#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gmp.h>

/* Macros */


/* Fonctions générales */

unsigned int ask_Message(unsigned char**);
mpz_t* init_mpz_ptr(unsigned int);
void free_mpz_ptr(mpz_t*, unsigned int);
void eval_poly_mod(mpz_t, mpz_t*, unsigned int, mpz_t, mpz_t);
void eval_poly_mod_ui(mpz_t, mpz_t*, unsigned int, unsigned long, mpz_t);
void FIPS202_SHA3_512(const unsigned char*, unsigned int, unsigned char*);
void bytes_to_mpz(const unsigned char*, unsigned int, mpz_t);
void msg_hash_to_mpz(const unsigned char* Message, unsigned int MessageByteLen, mpz_t Hashed_Message);


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


/* Prototypes : Fonctions de partage de signatures */


