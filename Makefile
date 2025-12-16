## Makefile du projet

# Compilateur utilisé
CC := gcc

# Flags de compilation utilisés
CFLAGS := -Wall -g

# Headers du projet
HDRS := RSA_Seuil.h

# Fichiers sources du projet
SRCS := Keccak.c RSA_Seuil.c Signature_Gen.c Signature_Share.c

# Fichiers objects associés aux fichiers sources
OBJS := $(SRCS:.c=.o)

# Nom des exécutables
EXEC := Signature

# Nom des bibliothèques
LIBS := -lgmp

# Recette de compliation
all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) -o $@ $(OBJS) $(CFLAGS) $(LIBS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

# Clean du projet
clean:
	rm -f $(EXEC) $(OBJS)