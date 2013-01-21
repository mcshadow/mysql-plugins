/*
   Copyright (c) 2012, PaynetEasy. All rights reserved.
   Author: Mikhail Goryachkin
   Licence: GPL
   Description: mysql query cache view plugin.
*/

#include "mysql_query_cache.h"
#include <mysql/plugin.h>

bool schema_table_store_record(THD *thd,TABLE *table);

#define MAX_SCHEMA_NAME_LENGTH 127
#define MAX_TABLE_NAME_LENGTH 127

#define COLUMN_SCHEMA_NAME 0
#define COLUMN_TABLE_NAME 1
 
ST_FIELD_INFO query_cache_table_fields[]=
{
  {"SCHEMA_NAME",    MAX_SCHEMA_NAME_LENGTH,    MYSQL_TYPE_STRING, 0, 0, "Schema Name"},
  {"TABLE_NAME",     MAX_TABLE_NAME_LENGTH,     MYSQL_TYPE_STRING, 0, 0, "Table Name"},
  {0,0, MYSQL_TYPE_STRING, 0, 0, 0}
};

static int query_cache_table_fill_table(THD *thd, TABLE_LIST *tables, COND *cond)
{
  // character set information to store varchar values
  CHARSET_INFO *cs = system_charset_info;
  TABLE *is_query_cache_tables = (TABLE *)tables->table;
  // query_cache defined in sql_cache.h is MySQL Query Cache implementation;
  MySQL_IS_Query_Cache *qc = (MySQL_IS_Query_Cache *)&query_cache;

  HASH *h_tables;
  const uchar *query_cache_block_hash;
  Query_cache_block* query_cache_block_current;
 
  query_cache.lock();
  h_tables = qc->get_tables_hash();
 
  for(uint i = 0; i < h_tables->records; i++)
  {
   query_cache_block_hash = my_hash_element(h_tables, i);
   query_cache_block_current = (Query_cache_block*)query_cache_block_hash;
   Query_cache_table* query_cache_table = query_cache_block_current->table();

   // get tables data
   const char *schema_name = (const char*)query_cache_table->db();
   size_t schema_name_length = strlen(schema_name)>MAX_SCHEMA_NAME_LENGTH?MAX_SCHEMA_NAME_LENGTH:strlen(schema_name);
   is_query_cache_tables->field[COLUMN_SCHEMA_NAME]->store((char*)schema_name, schema_name_length, cs);

   const char *table_name = (const char*)query_cache_table->table();
   size_t table_name_length = strlen(table_name)>MAX_TABLE_NAME_LENGTH?MAX_TABLE_NAME_LENGTH:strlen(table_name);
   is_query_cache_tables->field[COLUMN_TABLE_NAME]->store((char*)table_name, table_name_length, cs);
   
   if (schema_table_store_record(thd, is_query_cache_tables)) {
       query_cache.unlock();
       return 1;
     }
  }

  query_cache.unlock();
  return 0;
}
 
static int query_cache_table_plugin_init(void *p)
{
  ST_SCHEMA_TABLE *schema = (ST_SCHEMA_TABLE *)p;
 
  schema->fields_info = query_cache_table_fields;
  schema->fill_table = query_cache_table_fill_table;
 
  return 0;
}
 
static int query_cache_table_plugin_deinit(void *p)
{
  return 0;
}
 
struct st_mysql_information_schema query_cache_table_plugin =
{
  MYSQL_INFORMATION_SCHEMA_INTERFACE_VERSION  /* interface version    */
};
 
/*
 Plugin library descriptor
*/
mysql_declare_plugin(mysql_is_query_cache_table)
{
  MYSQL_INFORMATION_SCHEMA_PLUGIN,               /* type                            */
  &query_cache_table_plugin,                     /* descriptor                      */
  "QUERY_CACHE_TABLES",                          /* name                            */
  "Mikhail Goryachkin",                          /* author                          */
  "Lists all tables in the query cache",         /* description                     */
  PLUGIN_LICENSE_GPL,
  query_cache_table_plugin_init,                 /* init function (when loaded)     */
  query_cache_table_plugin_deinit,               /* deinit function (when unloaded) */
  0x0010,                                        /* version                         */
  NULL,                                          /* status variables                */
  NULL,                                          /* system variables                */
  NULL,                                          /* config options                  */
  0,                                             /* flags                           */
}
mysql_declare_plugin_end;
