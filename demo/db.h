#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int open_db(sqlite3** db);
int close_db(sqlite3* db);
sqlite3* create_db();
int exec(sqlite3* db, char* sql);
int insert_meter_information(sqlite3* db, int id, char* moteid, char* voltage, char* current);
int insert_attack_information(sqlite3* db, char* moteid, char* description);