/*
   Original author: Roland Bouman
   Licence: GPL

   Copyright (c) 2012, PaynetEasy. All rights reserved.
   Author: Mikhail Goryachkin
   Licence: GPL
   Description: mysql query cache view plugin.
*/

#include "mysql_query_cache.h"
#include <mysql/plugin.h>

bool schema_table_store_record(THD *thd,TABLE *table);
 
#define MAX_STATEMENT_TEXT_LENGTH 1024

#define COLUMN_STATEMENT_TEXT 0
#define COLUMN_FOUND_ROWS 1
#define COLUMN_RESULT_BLOCKS_COUNT 2
#define COLUMN_RESULT_BLOCKS_SIZE 3
#define COLUMN_RESULT_BLOCKS_SIZE_USED 4
 
ST_FIELD_INFO query_cache_result_fields[]=
{
  {"STATEMENT_TEXT",          MAX_STATEMENT_TEXT_LENGTH,MYSQL_TYPE_STRING, 0, 0, "Cached statement text"},
  {"FOUND_ROWS",              21, MYSQL_TYPE_LONGLONG, 0, 0, "Result row count"},
  {"RESULT_BLOCKS_COUNT",     21, MYSQL_TYPE_LONG, 0, 0, "Result Blocks count"},
  {"RESULT_BLOCKS_SIZE",      21, MYSQL_TYPE_LONGLONG, 0, 0,"Result Blocks size"},
  {"RESULT_BLOCKS_SIZE_USED", 21, MYSQL_TYPE_LONGLONG, 0, 0,"Result Blocks used size"},
  {0,0, MYSQL_TYPE_STRING, 0, 0, 0}
};

#if MYSQL_VERSION_ID > 50600
static int query_cache_result_fill_table(THD *thd, TABLE_LIST *tables, Item *item)
#else
static int query_cache_result_fill_table(THD *thd, TABLE_LIST *tables, COND *cond)
#endif
{
  // character set information to store varchar values
  CHARSET_INFO *cs = system_charset_info;
  TABLE *is_query_cache_results = (TABLE *)tables->table;
  // query_cache defined in sql_cache.h is MySQL Query Cache implementation;
  MySQL_IS_Query_Cache *qc = (MySQL_IS_Query_Cache *)&query_cache;

  HASH *h_queries;
  const uchar *query_cache_block_hash;
  Query_cache_block* query_cache_block_current;
 
  const char *statement_text;
  size_t statement_text_length;
 
  query_cache.lock();
  h_queries = qc->get_queries_hash();
 
  for(uint i = 0; i < h_queries->records; i++)
  {
   query_cache_block_hash = my_hash_element(h_queries, i);
   query_cache_block_current = (Query_cache_block*)query_cache_block_hash;
   Query_cache_query *query_cache_query = query_cache_block_current->query();

   // get statement data
   statement_text = (const char*)query_cache_query->query();
   statement_text_length = strlen(statement_text)>MAX_STATEMENT_TEXT_LENGTH?MAX_STATEMENT_TEXT_LENGTH:strlen(statement_text);
   is_query_cache_results->field[COLUMN_STATEMENT_TEXT]->store((char*)statement_text, statement_text_length, cs);
   
   ulonglong found_rows = query_cache_query->found_rows();
   is_query_cache_results->field[COLUMN_FOUND_ROWS]->store(found_rows, 0);
   
   // calculate result size
   uint result_blocks_count = 0;
   ulonglong result_blocks_size = 0;
   ulonglong result_blocks_size_used = 0;
   Query_cache_block *first_result_block = query_cache_query->result();
   if(   first_result_block 
      && first_result_block->type != Query_cache_block::RES_INCOMPLETE /* This type of block can be not lincked yet (in multithread environment)*/)
    {
     Query_cache_block *result_block = first_result_block;
     result_blocks_count = 1;    
     result_blocks_size = result_block->length;    // length of all block
     result_blocks_size_used = result_block->used; // length of data
     
     // loop all query result blocks for current query
     while(   (result_block= result_block->next) != first_result_block 
	       && result_block->type != Query_cache_block::RES_INCOMPLETE)
     {
       result_blocks_count++;              
       result_blocks_size += result_block->length;
       result_blocks_size_used += result_block->used;
     }
    }
   is_query_cache_results->field[COLUMN_RESULT_BLOCKS_COUNT]->store(result_blocks_count, 0);
   is_query_cache_results->field[COLUMN_RESULT_BLOCKS_SIZE]->store(result_blocks_size, 0);
   is_query_cache_results->field[COLUMN_RESULT_BLOCKS_SIZE_USED]->store(result_blocks_size_used, 0);
   
   if (schema_table_store_record(thd, is_query_cache_results)) {
       query_cache.unlock();
       return 1;
     }
  }

  query_cache.unlock();
  return 0;
}
 
static int query_cache_result_plugin_init(void *p)
{
  ST_SCHEMA_TABLE *schema = (ST_SCHEMA_TABLE *)p;
 
  schema->fields_info = query_cache_result_fields;
  schema->fill_table = query_cache_result_fill_table;
 
  return 0;
}
 
static int query_cache_result_plugin_deinit(void *p)
{
  return 0;
}
 
struct st_mysql_information_schema query_cache_result_plugin =
{
  MYSQL_INFORMATION_SCHEMA_INTERFACE_VERSION  /* interface version    */
};
 
/*
 Plugin library descriptor
*/
mysql_declare_plugin(mysql_is_query_cache_result)
{
  MYSQL_INFORMATION_SCHEMA_PLUGIN,               /* type                            */
  &query_cache_result_plugin,                    /* descriptor                      */
  "QUERY_CACHE_RESULTS",                         /* name                            */
  "Roland Bouman aka Mikhail Goryachkin",        /* author                          */
  "Lists all query results in the query cache",  /* description                     */
  PLUGIN_LICENSE_GPL,
  query_cache_result_plugin_init,                /* init function (when loaded)     */
  query_cache_result_plugin_deinit,              /* deinit function (when unloaded) */
  0x0010,                                        /* version                         */
  NULL,                                          /* status variables                */
  NULL,                                          /* system variables                */
  NULL,                                          /* config options                  */
  0,                                             /* flags                           */
}
mysql_declare_plugin_end;
