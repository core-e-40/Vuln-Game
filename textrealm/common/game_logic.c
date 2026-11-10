/*
 * game_logic.c
 *
 * All game rules for TextRealm live here. This file has no knowledge of
 * sockets, threads, or any particular OS - it is shared verbatim between
 * the Linux and Windows servers, which only differ in how bytes get to
 * and from process_command().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "game_logic.h"

/* ---- Static game data -------------------------------------------------- */

typedef struct {
    const char *name;
    int hp;
    int attack;
    int xp_reward;
    int gold_reward;
} Enemy;

static const Enemy ENEMIES[] = {
    { "GOBLIN", 20,  4,  15,  10 },
    { "SLIME",  12,  2,   8,   5 },
    { "ORC",    35,  7,  30,  20 },
    { "DRAGON", 100, 15, 150, 100 },
};
#define NUM_ENEMIES (sizeof(ENEMIES) / sizeof(ENEMIES[0]))

typedef struct {
    const char *name;
    int price;
} ShopItem;

static const ShopItem SHOP[] = {
    { "POTION", 10 },
    { "SHIELD", 20 },
    { "SWORD",  25 },
    { "BOW",    30 },
};
#define NUM_SHOP_ITEMS (sizeof(SHOP) / sizeof(SHOP[0]))

/* ---- Small helpers ------------------------------------------------------ */

static void to_upper_inplace(char *s) {
    for (; *s; s++) {
        *s = (char)toupper((unsigned char)*s);
    }
}

static int str_equal_ci(const char *a, const char *b) {
    while (*a && *b) {
        if (toupper((unsigned char)*a) != toupper((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

/* ---- Public API ---------------------------------------------------------*/

void character_init(Character *ch) {
    memset(ch, 0, sizeof(*ch));
    ch->created = 0;
}

/* ---- Command implementations -------------------------------------------*/

static void help_text(char *response, size_t size) {
    snprintf(response, size,
        "Available commands (formal syntax):\r\n"
        "  HELP\r\n"
        "  CREATE <name> <class>      class = WARRIOR | MAGE | ROGUE\r\n"
        "  STATUS\r\n"
        "  ATTACK <enemy>             enemy = GOBLIN | SLIME | ORC | DRAGON\r\n"
        "  INVENTORY\r\n"
        "  BUY <item>                 item  = POTION | SHIELD | SWORD | BOW\r\n"
        "  ECHO\r\n"                       
        "  BIO <text>                 save character biography\r\n"
        "  BIO SHOW                   display biography\r\n"

        "  QUIT\r\n");
}

static void cmd_create(Character *ch, const char *args, char *response, size_t size) {
    /* Set name buffer large enough to accommodate the full exploit stream */
    char name[2048] = {0};
    char class_buf[MAX_TOKEN_LEN + 1] = {0};

    /* 1. REMOVE the %32s boundary clamp constraint from the name parameter */
    int fields = sscanf(args, "%2047s %32s", name, class_buf);
    if (fields != 2) {
        snprintf(response, size,
            "Usage: CREATE <name> <class>  (class: WARRIOR, MAGE, ROGUE)");
        return;
    }

    to_upper_inplace(class_buf);

    int base_hp, base_atk;
    if (str_equal_ci(class_buf, "WARRIOR"))      { base_hp = 120; base_atk = 8;  }
    else if (str_equal_ci(class_buf, "MAGE"))    { base_hp = 80;  base_atk = 12; }
    else if (str_equal_ci(class_buf, "ROGUE"))   { base_hp = 100; base_atk = 10; }
    else {
        snprintf(response, size,
            "Unknown class '%s'. Choose WARRIOR, MAGE, or ROGUE.", class_buf);
        return;
    }
    (void)base_atk;

    memset(ch, 0, sizeof(*ch));
    
    strcpy(ch->name, name);
    
    strncpy(ch->class_name, class_buf, sizeof(ch->class_name) - 1);
    ch->class_name[sizeof(ch->class_name) - 1] = '\0';
    ch->level = 1;
    ch->max_hp = base_hp;
    ch->hp = base_hp;
    ch->gold = 50;
    ch->xp = 0;
    ch->inventory_count = 0;
    ch->created = 1;

    snprintf(response, size,
        "Character '%s' the %s created! HP:%d Gold:%d",
        ch->name, ch->class_name, ch->hp, ch->gold);
}


static void cmd_status(const Character *ch, char *response, size_t size) {
    snprintf(response, size,
        "Name: %s | Class: %s | Level: %d | HP: %d/%d | Gold: %d | XP: %d",
        ch->name, ch->class_name, ch->level, ch->hp, ch->max_hp, ch->gold, ch->xp);
}

static void cmd_inventory(const Character *ch, char *response, size_t size) {
    if (ch->inventory_count == 0) {
        snprintf(response, size, "Your inventory is empty.");
        return;
    }

    char buf[1024];
    size_t used = 0;
    used += (size_t)snprintf(buf + used, sizeof(buf) - used, "Inventory:");
    for (int i = 0; i < ch->inventory_count && used < sizeof(buf) - 1; i++) {
        used += (size_t)snprintf(buf + used, sizeof(buf) - used, " %s", ch->inventory[i]);
    }
    snprintf(response, size, "%s", buf);
}

static void cmd_attack(Character *ch, const char *args, char *response, size_t size) {
    char enemy_name[MAX_TOKEN_LEN + 1];
    if (sscanf(args, "%32s", enemy_name) != 1) {
        snprintf(response, size, "Usage: ATTACK <enemy>");
        return;
    }
    to_upper_inplace(enemy_name);

    const Enemy *enemy = NULL;
    for (size_t i = 0; i < NUM_ENEMIES; i++) {
        if (str_equal_ci(enemy_name, ENEMIES[i].name)) { enemy = &ENEMIES[i]; break; }
    }
    if (!enemy) {
        snprintf(response, size, "There is no enemy called '%s' here.", enemy_name);
        return;
    }

    int player_atk_base = 5 + ch->level * 2;
    if (str_equal_ci(ch->class_name, "MAGE"))         player_atk_base += 4;
    else if (str_equal_ci(ch->class_name, "WARRIOR")) player_atk_base += 2;

    int player_hp = ch->hp;
    int enemy_hp  = enemy->hp;
    int rounds    = 0;

    while (player_hp > 0 && enemy_hp > 0 && rounds < 50) {
        int player_dmg = player_atk_base + (rand() % 5);
        enemy_hp -= player_dmg;
        if (enemy_hp <= 0) break;

        int enemy_dmg = enemy->attack + (rand() % 3);
        player_hp -= enemy_dmg;
        rounds++;
    }

    if (enemy_hp <= 0) {
        ch->hp = player_hp > 0 ? player_hp : 1;
        ch->xp   += enemy->xp_reward;
        ch->gold += enemy->gold_reward;

        int leveled_up = 0;
        while (ch->xp >= ch->level * 50) {
            ch->xp -= ch->level * 50;
            ch->level++;
            ch->max_hp += 15;
            ch->hp = ch->max_hp;
            leveled_up = 1;
        }

        snprintf(response, size,
            "You defeated the %s! +%d XP, +%d gold.%s HP: %d/%d",
            enemy->name, enemy->xp_reward, enemy->gold_reward,
            leveled_up ? " LEVEL UP!" : "", ch->hp, ch->max_hp);
    } else {
        ch->hp = 1;
        int gold_lost = ch->gold / 4;
        ch->gold -= gold_lost;
        snprintf(response, size,
            "You were defeated by the %s! You limp away, losing %d gold. HP: %d/%d",
            enemy->name, gold_lost, ch->hp, ch->max_hp);
    }
}

static void cmd_buy(Character *ch, const char *args, char *response, size_t size) {
    char item_name[MAX_TOKEN_LEN + 1];
    if (sscanf(args, "%32s", item_name) != 1) {
        snprintf(response, size, "Usage: BUY <item>");
        return;
    }
    to_upper_inplace(item_name);

    const ShopItem *item = NULL;
    for (size_t i = 0; i < NUM_SHOP_ITEMS; i++) {
        if (str_equal_ci(item_name, SHOP[i].name)) { item = &SHOP[i]; break; }
    }
    if (!item) {
        snprintf(response, size, "The shop does not sell '%s'.", item_name);
        return;
    }
    if (ch->gold < item->price) {
        snprintf(response, size, "You can't afford %s (costs %d, you have %d gold).",
            item->name, item->price, ch->gold);
        return;
    }
    if (ch->inventory_count >= MAX_INVENTORY) {
        snprintf(response, size, "Your inventory is full.");
        return;
    }

    strncpy(ch->inventory[ch->inventory_count], item->name, MAX_TOKEN_LEN);
    ch->inventory[ch->inventory_count][MAX_TOKEN_LEN] = '\0';
    ch->inventory_count++;
    ch->gold -= item->price;

    snprintf(response, size, "You bought a %s for %d gold. Gold remaining: %d",
        item->name, item->price, ch->gold);
}

/* ---- Dispatcher ---------------------------------------------------------*/

int process_command(Character *ch, const char *input, char *response, size_t response_size) {
    if (response_size == 0) {
        return 0;
    }

    char line[2048];
    strcpy(line, input);
    line[sizeof(line) - 1] = '\0';

    char cmd[MAX_TOKEN_LEN + 1] = {0};
    if (sscanf(line, "%32s", cmd) != 1) {
        snprintf(response, response_size, "Please enter a command. Type HELP for options.");
        return 0;
    }
    to_upper_inplace(cmd);

    const char *args = line + strlen(cmd);
    while (*args == ' ') args++;

    if (str_equal_ci(cmd, "HELP")) {
        help_text(response, response_size);
        return 0;
    }
    if (str_equal_ci(cmd, "QUIT")) {
        snprintf(response, response_size, "Goodbye, adventurer!");
        return -1;
    }

    if (!ch->created && !str_equal_ci(cmd, "CREATE")) {
        snprintf(response, response_size,
            "You must CREATE a character first. Type HELP for syntax.");
        return 0;
    }

    if (str_equal_ci(cmd, "CREATE"))          cmd_create(ch, args, response, response_size);
    else if (str_equal_ci(cmd, "STATUS"))     cmd_status(ch, response, response_size);
    else if (str_equal_ci(cmd, "ATTACK"))     cmd_attack(ch, args, response, response_size);
    else if (str_equal_ci(cmd, "INVENTORY"))  cmd_inventory(ch, response, response_size);
    else if (str_equal_ci(cmd, "BUY"))        cmd_buy(ch, args, response, response_size);
    else
        snprintf(response, response_size, "Unknown command '%s'. Type HELP for options.", cmd);

    return 0;
}
