#include "RSA_Seuil.h"

int main(int argc, char** argv)
{
    mpz_t m, d;
    mpz_inits(m, d, NULL);
    mpz_set_str(m, "8840408529881936829763560450272908327242636839824644967569288920408445396376786169788279696054151164516357580435950077070877588063578741079430510906855937", 10);
    mpz_set_ui(d, 11555);

    mpz_t* SKs = gen_players_sk(5, 3, d, m);
    mpz_t* VKs = gen_players_vk(5, SKs, m);

    write_players_sk(5, SKs);
    write_players_vk(5, VKs);
}