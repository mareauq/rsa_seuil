## Makefile du projet

# Compilateur utilisé
CC := gcc

# Flags de compilation utilisés
CFLAGS := -Wall -g -fsanitize=address

# Headers du projet
RSA_HDRS := RSA_Threshold.h
El_GAMAL_HDRS := El_Gamal_Threshold.h

# Fichiers sources du projet
RSA_SRCS := Keccak.c RSA_Threshold.c Players_functions.c Coordinator_functions.c General_functions.c Dealer_functions.c Verifier_functions.c
EL_GAMAL_SRCS := Keccak.c El_Gamal_Threshold.c Players_functions.c Coordinator_functions.c General_functions.c Dealer_functions.c Sender_functions.c

# Fichiers objects associés aux fichiers sources
RSA_OBJS := $(RSA_SRCS:.c=.o)
EL_GAMAL_OBJS := $(EL_GAMAL_SRCS:.c=.o)

# Nom des exécutables
RSA_EXEC := Signature_RSA
EL_GAMAL_EXEC := Chiffrement_El_Gamal

# Nom des bibliothèques
LIBS := -lgmp

# Recette de compliation
all: $(RSA_EXEC) $(EL_GAMAL_EXEC)

$(RSA_EXEC): $(RSA_OBJS)
	$(CC) -o $@ $(RSA_OBJS) $(CFLAGS) $(LIBS)

$(EL_GAMAL_EXEC): $(EL_GAMAL_OBJS)
	$(CC) -o $@ $(EL_GAMAL_OBJS) $(CFLAGS) $(LIBS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

# Clean du projet
clean:
	rm -f $(RSA_EXEC) $(EL_GAMAL_EXEC) *.o