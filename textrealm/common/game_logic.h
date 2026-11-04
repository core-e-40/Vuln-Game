#ifndef GAME_LOGIC_H
#define GAME_LOGIC_H

#include <stddef.h>

/* ---- Protocol limits ------------------------------------------------- */
#define MAX_NAME_LEN   32   /* max length of a character name token      */
#define MAX_TOKEN_LEN  32   /* max length of a class/enemy/item token    */
#define MAX_INVENTORY  10   /* max number of items a character can carry */
#define MAX_LINE_LEN   512  /* max length of one line of client input    */

typedef struct {
    char name[MAX_NAME_LEN + 1];
    char class_name[16];
    int  level;
    int  hp;
    int  max_hp;
    int  gold;
    int  xp;
    char inventory[MAX_INVENTORY][MAX_TOKEN_LEN + 1];
    int  inventory_count;
    int  created;   /* 0 = no character yet, 1 = character exists */
} Character;

/* Reset a Character to its "no character created yet" state. */
void character_init(Character *ch);

/*
 * Parse one line of client input and produce a text response.
 * `response` must be a caller-supplied buffer of size `response_size`;
 * the function always NUL-terminates it and never writes past it.
 * Returns -1 if the client asked to QUIT (caller should drop the
 * connection after sending `response`), otherwise 0.
 */
int process_command(Character *ch, const char *input,
                      char *response, size_t response_size);

#endif /* GAME_LOGIC_H */
