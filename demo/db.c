#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "db.h"

static int index_attack = 0;

int dummy_input_db(sqlite3* db){
    char temp[1024];
    memset(temp, 0x00, sizeof(temp));
    sprintf(temp, "INSERT INTO Meters VALUES(1, 2, 3, 4, 5);");
    exec(db, temp);
    return 0;
}

int open_db(sqlite3** pdb){
    int rc = sqlite3_open("test5.db", pdb);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(*pdb));
        sqlite3_close(*pdb);
        return 1;
    }
    return 0;
}

int close_db(sqlite3* db){
    sqlite3_close(db);
    return 0;
}

sqlite3* create_db(void){
    sqlite3 *db = NULL;
    if (open_db(&db) != 0) {
        return NULL;
    }
    
    char temp[1024];

    memset(temp, 0x00, sizeof(temp));
    sprintf(temp, "DROP TABLE IF EXISTS Meters; CREATE TABLE Meters(Id INT, MoteID TEXT, Voltage TEXT, Current TEXT);");
    exec(db, temp);

    memset(temp, 0x00, sizeof(temp));
    sprintf(temp, "DROP TABLE IF EXISTS Alarms; CREATE TABLE Alarms(Id INT, MoteID TEXT, Description TEXT);");
    exec(db, temp);
    // dummy_input_db(db);
    close_db(db);
    return db;
}

int exec(sqlite3 *db, char* sql){
    char *err_msg = 0;
    printf("exec sql = %s\n", sql);
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_free(err_msg);
        return 1;
    }
    sqlite3_free(err_msg);
    return 0;
}

int insert_meter_information(sqlite3* db, int id, char* moteid, char* voltage, char* current){
    open_db(&db);
    
    char temp[1024];
    memset(temp, 0x00, sizeof(temp));
    sprintf(temp, "INSERT INTO Meters VALUES(%d, '%s', '%s', '%s');", id, moteid, voltage, current);
    exec(db, temp);

    close_db(db);
    return 0;
}

int insert_attack_information(sqlite3* db, char* moteid, char* description){
    open_db(&db);
    
    char temp[1024];
    memset(temp, 0x00, sizeof(temp));
    sprintf(temp, "INSERT INTO Alarms VALUES(%d, '%s', '%s');", index_attack++, moteid, description);
    exec(db, temp);

    close_db(db);
    return 0;
}