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

#define MAX_SYSLOG_LEN 1024

/* static counters for SHOW STATUS */
static volatile int total_number_of_calls;
static volatile int number_of_calls_general;
static volatile int number_of_calls_connection;

/* static variables for SHOW VARIABLES */
static char *audit_host=NULL;
static char *audit_table=NULL;
static char *replica_username=NULL;
static my_bool is_alert_all=0;

/* thread variabes */
static const char * log_level_names[] = {"LOG_EMERG", "LOG_ALERT", "LOG_CRIT", "LOG_ERR", "LOG_WARNING", "LOG_NOTICE", "LOG_INFO", "LOG_DEBUG"};
static TYPELIB log_levels = { 8, NULL, log_level_names, NULL }; // need to set variables count and names only

/* function prototypes */
static void update_log_level(MYSQL_THD thd, struct st_mysql_sys_var *var,
                             void *tgt, const void *save);

/*
   Plugin system variables for SHOW VARIABLES
*/
static MYSQL_SYSVAR_STR(host, audit_host,
                        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY | PLUGIN_VAR_MEMALLOC,
                        "User can specify the log host for auditing",
                        NULL, NULL, "localhost");
static MYSQL_SYSVAR_STR(table, audit_table,
                        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY | PLUGIN_VAR_MEMALLOC,
                        "User can specify table to send critical alert",
                        NULL, NULL, "encrypted_card_numbers");
static MYSQL_SYSVAR_STR(replica, replica_username,
                        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY | PLUGIN_VAR_MEMALLOC,
                        "User can specify username to exclude it from logging",
                        NULL, NULL, "paynet_repl");
static MYSQL_SYSVAR_BOOL(alert_all, is_alert_all,
                         PLUGIN_VAR_NOCMDARG | PLUGIN_VAR_READONLY,
                         "Log all user actions as LOG_ALERT",
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
	  MYSQL_SYSVAR(table),
	  MYSQL_SYSVAR(replica),
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
  if (   sctx->host_or_ip && sctx->user
	  && strcasestr(sctx->host_or_ip, audit_host)  != NULL
	  && strcasestr(sctx->user, replica_username) == NULL)
    syslog(is_alert_all ? LOG_ALERT : LOG_WARNING,"[LOG LEVEL CHANGED] host:%s user:%s \n", sctx->host_or_ip, sctx->user);
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
    openlog("mysql_audit:", LOG_PID|LOG_CONS, LOG_USER); 
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

static void audit_syslog_notify(MYSQL_THD thd __attribute__((unused)),
                              unsigned int event_class,
                              const void *event)
{
  total_number_of_calls++;
  if (event_class == MYSQL_AUDIT_GENERAL_CLASS)         
  {
    const struct mysql_event_general *event_general=    
      (const struct mysql_event_general *) event;
	 if (   event_general != NULL && event_general->general_user_length >  0
	     && strcasestr(event_general->general_user, audit_host)  != NULL
	     && strcasestr(event_general->general_user, replica_username) == NULL)
	{
	  char strip_query[MAX_SYSLOG_LEN];
	  char strip_command[MAX_SYSLOG_LEN];
	  syslog_strip_string(strip_query, event_general->general_query, event_general->general_query_length);
	  syslog_strip_string(strip_command, event_general->general_command, event_general->general_command_length);
	  
      number_of_calls_general++;
      switch (event_general->event_subclass)
      {
      case MYSQL_AUDIT_GENERAL_LOG: // LOG events occurs before emitting to the general query log.
        break;
	  // in case of using stored procedures exceptions raised during procedure execution
	  // would be logged in the name of user created stored procedure
	  // even if procedure called from the remote host using the remote user
      case MYSQL_AUDIT_GENERAL_ERROR: // ERROR events occur before transmitting errors to the user.
	    if (THDVAR(thd, log_level) >= (is_alert_all ? LOG_ALERT : LOG_WARNING))
          syslog(is_alert_all ? LOG_ALERT : LOG_WARNING,"[QUERY FAILED] %lu: User: %s  Command: %s  Query: %s\n",
                 event_general->general_thread_id, event_general->general_user, strip_command, strip_query); 
        break;
      case MYSQL_AUDIT_GENERAL_RESULT: // RESULT events occur after transmitting a resultset to the user.
	    if (THDVAR(thd, log_level) >= 
           (is_alert_all ? 
              LOG_ALERT : 
              (event_general->general_query_length > 0 && strcasestr(event_general->general_query, audit_table) != NULL ? LOG_CRIT : LOG_NOTICE)
           )
         )
          syslog(is_alert_all ? 
                   LOG_ALERT : 
                   (event_general->general_query_length > 0 && strcasestr(event_general->general_query, audit_table) != NULL ? LOG_CRIT : LOG_NOTICE),
		             "[QUERY SUCCEEDED] %lu: User: %s  Command: %s  Query: %s\n",
                 event_general->general_thread_id, event_general->general_user, strip_command, strip_query);
        break;
      case MYSQL_AUDIT_GENERAL_STATUS: // STATUS events occur after transmitting a resultset or errors
	    if (THDVAR(thd, log_level) >= (is_alert_all ? LOG_ALERT : LOG_NOTICE))
          syslog(is_alert_all ? LOG_ALERT : LOG_NOTICE,"[QUERY DETAILS] %lu: User: %s  Command: %s  Query: %s\n",
                 event_general->general_thread_id, event_general->general_user, strip_command, strip_query);
        break;
      default:
        break;
      }
	}
  }
  else if (event_class == MYSQL_AUDIT_CONNECTION_CLASS)
  {
    const struct mysql_event_connection *event_connection=
      (const struct mysql_event_connection *) event;
	if (   event_connection != NULL 
      && event_connection->host_length > 0
	    && strcasestr(event_connection->host, audit_host) != NULL
      && event_connection->user_length > 0
      && strcasestr(event_connection->user, replica_username) == NULL
	   )
	{
      number_of_calls_connection++;
      switch (event_connection->event_subclass)
      {
      case MYSQL_AUDIT_CONNECTION_CONNECT: // CONNECT occurs after authentication phase is completed.
	    if (THDVAR(thd, log_level) >= 
           (is_alert_all ? 
              LOG_ALERT :
              (event_connection->status > 0 ? LOG_ERR : LOG_NOTICE)
           )
         )
          syslog(is_alert_all ? 
                   LOG_ALERT :
                   (event_connection->status > 0 ? LOG_ERR : LOG_NOTICE),
		             "[CONNECT] %lu: User: %s@%s[%s]  Event: %d  Status: %d\n",
                 event_connection->thread_id, event_connection->user, event_connection->host,
                 event_connection->ip, event_connection->event_subclass, event_connection->status );
        break;
      case MYSQL_AUDIT_CONNECTION_DISCONNECT: // DISCONNECT occurs after connection is terminated.
        break;
      case MYSQL_AUDIT_CONNECTION_CHANGE_USER: // CHANGE_USER occurs after COM_CHANGE_USER RPC is completed.
	    if (THDVAR(thd, log_level) >= 
           (is_alert_all ? 
              LOG_ALERT :
              (event_connection->status > 0 ? LOG_ERR : LOG_NOTICE)
           )
         )
          syslog(is_alert_all ? 
                   LOG_ALERT :
                   (event_connection->status > 0 ? LOG_ERR : LOG_NOTICE),
		             "[CHANGE USER] %lu: User: %s@%s[%s]  Event: %d  Status: %d\n",
                 event_connection->thread_id, event_connection->user, event_connection->host,
                 event_connection->ip, event_connection->event_subclass, event_connection->status );
        break;
      default:
        break;
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
  0x0001,                     /* version                         */
  audit_syslog_status,        /* status variables                */
  audit_syslog_sysvars,       /* system variables                */
  NULL,
  0,
}
mysql_declare_plugin_end;

