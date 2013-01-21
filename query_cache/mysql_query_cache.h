#ifndef MYSQL_IS_QUERY_CACHE
#define MYSQL_IS_QUERY_CACHE
/*
   Copyright (c) 2012, PaynetEasy. All rights reserved.
   Author:  Mikhail Goryachkin
   Licence: GPL
   Description: mysql query cache view plugin.
*/

#include <stdlib.h>
#include <ctype.h>
#ifndef MYSQL_SERVER
#define MYSQL_SERVER
#endif

#include <sql_cache.cc>

class MySQL_IS_Query_Cache : private Query_cache {
public:

  HASH *get_queries_hash() {
    return &this->queries;
  }

  HASH *get_tables_hash() {
    return &this->tables;
  }
};

#endif