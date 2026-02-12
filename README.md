# Implémentation de protocoles à seuil

## Description du projet

Ce projet universitaire a pour but l'implémentation d'une signature RSA et d'un chiffrement El Gamal à seuil. Le but étant que pour un nombre de joueurs donné, il est nécessaire qu'une partie de taille fixée soit d'accord avec la/le signature/chiffrement pour qu'elle/il s'exécute. L'accent de ce projet a été mis sur la simulation des différents protagonistes en jeu dans chacun des protocoles et non sur l'optimisation de la plupart des calculs. 

## Compilation 

make Signature_RSA : compile le programme de signature RSA.  
make Chiffrement_El_Gamal : compile le programme de chiffrement El Gamal.  
make : compile les deux programmes d'un coup.  

## Critique sur l'état actuel

Le programme n'étant pas très coûteux en ressources et ayant pour vocation d'être utilisé avec de petites valeurs (par exemple $l = 5$ et $k = 3$), le principal objectif dans la programmation a été la simulation du transfert d'informations entre les joueurs. Aussi, même si des efforts ont été fait pour optimiser certains calculs, il est certains que la complexité de nombreuses fonctions puisse être réduite.
Il est d'usage en programmation de faire de la gestion d'erreurs. Par exemple lors d'allocation mémoire, rien n'a été prévu s'il l'espace mémoire nécessaire au bon fonctionnement du programme est insuffisant. Ce genre de considérations ne sont pas principales dans le contexte de ce projet, mais constituent des pistes d'améliorations importantes.

## Notes diverses

Les différents programmes sont fournis avec les clés des "Dealers". Elles regroupent toutes les propriétés nécessaires au bon fonctionnement des programmes. La génération de ces clés a été faite de manière annexe et n'est pas comprise dans ce programme. Ainsi, il est conseillé d'utiliser les clés par défaut ou d'avoir sous la main d'autres clés adéquates. 