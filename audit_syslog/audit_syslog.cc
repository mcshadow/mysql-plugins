/*
   Copyright (c) 2012, PaynetEasy. All rights reserved.
   Author:  Mikhail Goryachkin
   Licence: GPL
   Description: syslog audit plugin.
*/
#define MYSQL_SERVER

#include <my_pthread.h>
#include <sql_priv.h>
#include <mysql/plugin.h>
#include <sql_class.h>

#include <mysql/plugin_audit.h>
#include <syslog.h>                             // syslog
#include <string.h>                             // strcasestr

#include "my_global.h"                          // 
#include "typelib.h"                            // TYPELIB

#if !defined(__attribute__) && (defined(__cplusplus) || !defined(__GNUC__)  || __GNUC__ == 2 && __GNUC_MINOR__ < 8)
#define __attribute__(A)
#endif

#ifndef MAX_SYSLOG_LEN
#define MAX_SYSLOG_LEN 1024
#endif

#ifndef BUF_LEN
#define BUF_LEN 4096
#endif

#define NVL(value, ifnull) (value ? value : ifnull)

/* static counters for SHOW STATUS */
static volatile int total_number_of_calls;
static volatile int number_of_calls_general;
static volatile int number_of_calls_connection;

/* static variables for SHOW VARIABLES */
static char *audit_host=NULL;
static char *audit_crit_schema=NULL;
static char *audit_ignore_username=NULL;
static my_bool inc_log_level=0;

/* thread variabes */
static const char * log_level_names[] = {"LOG_EMERG", "LOG_ALERT", "LOG_CRIT", "LOG_ERR", "LOG_WARNING", "LOG_NOTICE", "LOG_INFO", "LOG_DEBUG"};
static TYPELIB log_levels = { 8, NULL, log_level_names, NULL }; // need to set variables count and names only

/* function prototypes */
static void update_log_level(MYSQL_THD thd, struct st_mysql_sys_var *var, void *tgt, const void *save);
static bool verify_schemas_owner(MYSQL_THD thd, const char * current_user);
static bool check_crit_schema(MYSQL_THD thd, const char * audit_crit_schema);

void syslog_strip_string(char *result_string, const char *source_string, int source_string_len);
bool schema_belongs_to_user(const char * current_user, const char * current_schema);
bool schema_is_technical(const char* schema_name);
bool host_ignored(const char* current_user);
bool user_ignored(const char* current_host_or_ip);
/*
   Plugin system variables for SHOW VARIABLES
*/
static MYSQL_SYSVAR_STR(host, audit_host,
                        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY | PLUGIN_VAR_MEMALLOC,
                        "User can specify the log host for auditing",
                        NULL, NULL, "localhost");
static MYSQL_SYSVAR_STR(crit_schema, audit_crit_schema,
                        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY | PLUGIN_VAR_MEMALLOC,
                        "User can specify schema to send critical alert",
                        NULL, NULL, "paynet_card");
static MYSQL_SYSVAR_STR(ignore_username, audit_ignore_username,
                        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY | PLUGIN_VAR_MEMALLOC,
                        "User can specify username to exclude it from logging",
                        NULL, NULL, "paynet_repl");
static MYSQL_SYSVAR_BOOL(alert_all, inc_log_level,
                         PLUGIN_VAR_NOCMDARG | PLUGIN_VAR_READONLY,
                         "Log all user actions as LOG_CRIT",
                         NULL, NULL, 0);
/*
   Plugin local variables for SHOW VARIABLES
*/
static MYSQL_THDVAR_ENUM(log_level, 
                         0,
                         "User can specify log level during runtime",
                         NULL, &update_log_level, 6, &log_levels);

static struct st_mysql_sys_var* audit_syslog_sysvars[] = {
    MYSQL_SYSVAR(host),
    MYSQL_SYSVAR(crit_schema),
    MYSQL_SYSVAR(ignore_username),
    MYSQL_SYSVAR(log_level),
    MYSQL_SYSVAR(alert_all),
    NULL
};

/*
   Check and Update functions
*/
static void update_log_level(MYSQL_THD thd, struct st_mysql_sys_var *var,
                             void *tgt, const void *save)
{
  *(long *)tgt= *(long *) save;
  const Security_context *sctx= &((THD*)thd)->main_security_ctx;
  if (    sctx->host_or_ip && sctx->user
       && strcasestr(sctx->host_or_ip, audit_host) != NULL
       && strcasestr(sctx->user, audit_ignore_username) == NULL)
    syslog(inc_log_level ? LOG_CRIT : LOG_WARNING,"[LOG LEVEL CHANGED] host:%s user:%s \n", sctx->host_or_ip, sctx->user);
}

/*
   Initialize the plugin at server start or plugin installation.
*/
static int audit_syslog_init(void *arg __attribute__((unused)))
{
    /*
      Include PID with each message.
      (Not in POSIX.1-2001.) Print to stderr as well.
      Write directly to system console if there is an error while sending to system logger.
  */
    openlog("mysql_audit", LOG_PID|LOG_CONS, LOG_USER); 
    total_number_of_calls      = 0;
    number_of_calls_general    = 0;
    number_of_calls_connection = 0;
    return(0);
}

/*
   Terminate the plugin at server shutdown or plugin deinstallation.
*/
static int audit_syslog_deinit(void *arg __attribute__((unused)))
{
    closelog();
    return(0);
}

/* 
   Event notifier function
*/ 
void syslog_strip_string(char *result_string,const char *source_string, int source_string_len)
{
  int strip_query_len = min(MAX_SYSLOG_LEN - 1, source_string_len);
  if (strip_query_len > 0)
  {
  memcpy(result_string, source_string, strip_query_len);
  result_string[strip_query_len] = '\0';
  char *src, *dst;
  for (src = dst = result_string; *src != '\0'; src++) 
  {
    *dst = *src;
    if (*dst != '\r' && *dst != '\n') dst++;
  }
  *dst = '\0';
  }
  result_string[strip_query_len] = '\0';
}

bool schema_belongs_to_user(const char * current_user, const char * current_schema)
{
  int current_user_len = strlen(current_user);
  int current_schema_len = strlen(current_schema);
  if (current_user_len == 0 && current_schema_len == 0)
    return false;

  int max_value_len = (current_user_len > current_schema_len ? current_user_len : current_schema_len);

  if (current_user_len == current_schema_len && strncasecmp(current_user, current_schema, max_value_len) == 0)
    return true;
  else
  {
    const char sandbox[9] = "_sandbox";
    const char paynet[8] = "paynet_";

    if (   current_user_len > 7 
        && current_schema_len > 7 
        && strncasecmp(&current_user[current_user_len - 8], sandbox, max_value_len) == 0
        && strncasecmp(&current_schema[current_schema_len - 8], sandbox, max_value_len) == 0
        && strncasecmp(current_user, paynet, max_value_len) == 0
        && strncasecmp(current_schema, paynet, max_value_len) == 0
        )
      return true;
  };  

  return false;
}

bool schema_is_technical(const char* schema_name)
{
  const char allowed_schema[19] = "information_schema";

  return strncasecmp(allowed_schema, schema_name, (19 > strlen(schema_name) ? 19 : strlen(schema_name))) == 0;
}

bool user_ignored(const char* current_user)
{
  return strncasecmp(current_user, audit_ignore_username, 
                     ( strlen(current_user) > strlen(audit_ignore_username) ? strlen(current_user) : strlen(audit_ignore_username) )) == 0;
}

bool host_ignored(const char* current_host_or_ip)
{
  return strncasecmp(current_host_or_ip, audit_host, 
                     ( strlen(current_host_or_ip) > strlen(audit_host) ? strlen(current_host_or_ip) : strlen(audit_host) )) != 0;
}


static bool verify_schemas_owner(MYSQL_THD thd, const char * current_user)
{
  TABLE_LIST *table_list;
  bool user_verified;
  bool user_in_own_schema = false;

  if (thd && thd->db)
  {
    user_in_own_schema = schema_belongs_to_user(current_user, thd->db);
  }

  user_verified = user_in_own_schema;

  if (thd && thd->lex && thd->lex->query_tables)
  {
    for(table_list = thd->lex->query_tables; table_list && table_list->db && user_verified; table_list = table_list->next_local)
    {
      if (!schema_is_technical(table_list->db) && !schema_belongs_to_user(current_user, table_list->db))
        user_verified = false;
    }
  }

  return user_verified;
}

static bool check_crit_schema(MYSQL_THD thd, const char * audit_crit_schema)
{
  TABLE_LIST *table_list;

  int audit_crit_schema_len = strlen(audit_crit_schema);
  if( audit_crit_schema_len <=0 || audit_crit_schema_len > 64 ) {
      syslog(LOG_ERR,"[SCHEMA IS WRONG] len:%d\n", audit_crit_schema_len);
      return false;
  }

  if (thd && thd->lex && thd->lex->query_tables)
  {
    for(table_list = thd->lex->query_tables; table_list && table_list->db; table_list = table_list->next_local)
    {
      int db_len = table_list->db_length;

      if(db_len <=0 || db_len > 64) {
        syslog(LOG_ERR,"[TABLE SCHEMA IS WRONG] len:%d\n", db_len);
        continue;
      }

      if(table_list->db == NULL) {
        syslog(LOG_ERR,"[TABLE SCHEMA DB IS NULL] len:%d\n", db_len);
        continue;
      }

      int max_curr_str_len = db_len > audit_crit_schema_len ? db_len : audit_crit_schema_len;

      if (strncasecmp(audit_crit_schema, table_list->db, max_curr_str_len) == 0)
        return true;
    }    
  }

  return false;
}

static void audit_syslog_notify(MYSQL_THD thd, unsigned int event_class, const void *event)
{
  total_number_of_calls++;

  if(thd)
  {
    const char * current_user = NVL(thd->main_security_ctx.user, "NULL");
    const char * current_host_or_ip = NVL(thd->main_security_ctx.host_or_ip, "NULL");
    
    bool verified_schemas_only = verify_schemas_owner(thd, current_user);

    if (event_class == MYSQL_AUDIT_GENERAL_CLASS)         
    {
      const struct mysql_event_general *event_general = (const struct mysql_event_general *) event;

      if (  event_general
         && event_general->general_user
         && NVL(event_general->general_user_length, 0) >  0
         && !host_ignored(current_host_or_ip)
         && !user_ignored(current_user)
         )
      {
        char strip_query[MAX_SYSLOG_LEN];
        char strip_command[MAX_SYSLOG_LEN];
        syslog_strip_string(strip_query, event_general->general_query, event_general->general_query_length);
        syslog_strip_string(strip_command, event_general->general_command, event_general->general_command_length);        
        
        int current_log_level = THDVAR(thd, log_level);
        int notify_level;

        number_of_calls_general++;
        switch (event_general->event_subclass)
        {
        case MYSQL_AUDIT_GENERAL_LOG: // LOG events occurs before emitting to the general query log.
          break;
        // in case of using stored procedures exceptions raised during procedure execution
        // would be logged in the name of user created stored procedure
        // even if procedure called from the remote host using the remote user
        case MYSQL_AUDIT_GENERAL_ERROR: // ERROR events occur before transmitting errors to the user.
          notify_level = (inc_log_level || check_crit_schema(thd, audit_crit_schema) ? LOG_CRIT : LOG_WARNING);

          if (current_log_level >= notify_level)
              syslog(notify_level,"[QUERY FAILED] %lu: User: %s  Command: %s  Query: %s\n",
                     event_general->general_thread_id, event_general->general_user, strip_command, strip_query); 
          break;
        case MYSQL_AUDIT_GENERAL_RESULT: // RESULT events occur after transmitting a resultset to the user.
          notify_level = (inc_log_level || check_crit_schema(thd, audit_crit_schema) ? LOG_CRIT : LOG_NOTICE);

          if (current_log_level >= notify_level && !verified_schemas_only)
              syslog(notify_level,
                     "[QUERY SUCCEEDED] %lu: User: %s  Command: %s  Query: %s\n",
                     event_general->general_thread_id, event_general->general_user, strip_command, strip_query);
          break;
        case MYSQL_AUDIT_GENERAL_STATUS: // STATUS events occur after transmitting a resultset or errors
          notify_level = (inc_log_level || check_crit_schema(thd, audit_crit_schema) ? LOG_CRIT : LOG_NOTICE);

          if (    current_log_level >= notify_level
               && (!verified_schemas_only || NVL(event_general->general_error_code, 0) != 0)
            )
              syslog(notify_level,"[QUERY DETAILS] %lu: User: %s  Command: %s  Query: %s Error Code: %d\n",
                     event_general->general_thread_id, event_general->general_user, strip_command, strip_query, event_general->general_error_code);
          break;
        default:
          break;
        }
      }
    }
    else if (event_class == MYSQL_AUDIT_CONNECTION_CLASS)
    {
      const struct mysql_event_connection *event_connection = (const struct mysql_event_connection *) event;
      if (   event_connection
          && event_connection->host
          && NVL(event_connection->host_length, 0) > 0
          && event_connection->user
          && NVL(event_connection->user_length, 0) > 0
          && !host_ignored(current_host_or_ip)
          && !user_ignored(current_user)
         )
      {
          int current_log_level = THDVAR(thd, log_level);
          int notify_level;

          number_of_calls_connection++;
          switch (event_connection->event_subclass)
          {
          case MYSQL_AUDIT_CONNECTION_CONNECT: // CONNECT occurs after authentication phase is completed.
            notify_level = (inc_log_level ? LOG_CRIT : (NVL(event_connection->status, 0) != 0 ? LOG_ERR : LOG_NOTICE));

            if (    current_log_level >= notify_level 
                 && (!verified_schemas_only || NVL(event_connection->status, 0) != 0)
                )
                syslog(notify_level,
                       "[CONNECT] %lu: User: %s@%s[%s]  Event: %d  Status: %d\n",
                       event_connection->thread_id, event_connection->user, event_connection->host,
                       event_connection->ip, event_connection->event_subclass, event_connection->status );
            break;
          case MYSQL_AUDIT_CONNECTION_DISCONNECT: // DISCONNECT occurs after connection is terminated.
            break;
          case MYSQL_AUDIT_CONNECTION_CHANGE_USER: // CHANGE_USER occurs after COM_CHANGE_USER RPC is completed.
            notify_level = (inc_log_level ? LOG_CRIT : (NVL(event_connection->status, 0) != 0 ? LOG_ERR : LOG_NOTICE));
            
            if (    current_log_level >= notify_level 
                 && (!verified_schemas_only || NVL(event_connection->status, 0) != 0)
                )
                syslog(notify_level,
                       "[CHANGE USER] %lu: User: %s@%s[%s]  Event: %d  Status: %d\n",
                       event_connection->thread_id, event_connection->user, event_connection->host,
                       event_connection->ip, event_connection->event_subclass, event_connection->status);
            break;
          default:
            break;
        }
      }
    }
  }
}  

/*
  Plugin type-specific descriptor
*/

static struct st_mysql_audit audit_syslog_descriptor=
{
  MYSQL_AUDIT_INTERFACE_VERSION,                        /* interface version    */
  NULL,                                                 /* release_thd function */
  audit_syslog_notify,                                  /* notify function      */
  { (unsigned long) MYSQL_AUDIT_GENERAL_CLASSMASK |
                    MYSQL_AUDIT_CONNECTION_CLASSMASK }  /* class mask           */
};


/*
   Plugin status variables for SHOW STATUS
*/
static struct st_mysql_show_var audit_syslog_status[]=
{
  { "Audit_syslog_total_calls",       (char *) &total_number_of_calls,      SHOW_INT },
  { "Audit_syslog_general_events",    (char *) &number_of_calls_general,    SHOW_INT },
  { "Audit_syslog_connection_events", (char *) &number_of_calls_connection, SHOW_INT },
  { 0, 0, SHOW_INT }
};

/*
  Plugin library descriptor
*/
mysql_declare_plugin(audit_syslog)
{
  MYSQL_AUDIT_PLUGIN,         /* type                            */
  &audit_syslog_descriptor,   /* descriptor                      */
  "audit_syslog",             /* name                            */
  "Mikhail Goryachkin",       /* author                          */
  "Syslog Audit Plugin",      /* description                     */
  PLUGIN_LICENSE_GPL,
  audit_syslog_init,          /* init function (when loaded)     */
  audit_syslog_deinit,        /* deinit function (when unloaded) */
  0x0003,                     /* version                         */
  audit_syslog_status,        /* status variables                */
  audit_syslog_sysvars,       /* system variables                */
  NULL,
  0,
}
mysql_declare_plugin_end;

