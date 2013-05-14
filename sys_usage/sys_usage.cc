#include "sql_class.h"                          // TABLE
#include <mysql/plugin.h>
#include "my_global.h"                          // 

bool schema_table_store_record(THD *thd,TABLE *table);

#include <sys/sysinfo.h>    //getrusage

/*insert macro*/
#define INSERT(NAME,VALUE)                            \
  table->field[0]->store(NAME, sizeof(NAME)-1, cs);   \
  table->field[1]->store(VALUE);                      \
  if (schema_table_store_record(thd, table))          \
    return 1;

/*define table fields*/
 
ST_FIELD_INFO sys_usage_fields[]=
{
  {"RESOURCE", 255, MYSQL_TYPE_STRING, 0, 0, 0, 0},
  {"VALUE", 20, MYSQL_TYPE_LONGLONG, 0, 0, 0, 0},
  {0, 0, MYSQL_TYPE_NULL, 0, 0, 0, 0}
};
  
#if MYSQL_VERSION_ID > 50600
static int fill_sys_usage(THD *thd, TABLE_LIST *tables, Item *item)
#else
static int fill_sys_usage(THD *thd, TABLE_LIST *tables, COND *cond)
#endif
{
  CHARSET_INFO *cs= system_charset_info;
  TABLE *table= tables->table;
  	  
  INSERT("Total physical memory",
         get_phys_pages() * getpagesize());
  INSERT("Available physical memory",
         get_avphys_pages() * getpagesize());
  INSERT("Number of CPUs", get_nprocs());

  rusage r_usage;
  /*
   struct rusage {
	   struct timeval ru_utime; // user CPU time used 
	   struct timeval ru_stime; // system CPU time used 
	   long   ru_maxrss;        // maximum resident set size 
	   long   ru_ixrss;         // integral shared memory size 
	   long   ru_idrss;         // integral unshared data size 
	   long   ru_isrss;         // integral unshared stack size 
	   long   ru_minflt;        // page reclaims (soft page faults) 
	   long   ru_majflt;        // page faults (hard page faults) 
	   long   ru_nswap;         // swaps 
	   long   ru_inblock;       // block input operations 
	   long   ru_oublock;       // block output operations 
	   long   ru_msgsnd;        // IPC messages sent 
	   long   ru_msgrcv;        // IPC messages received 
	   long   ru_nsignals;      // signals received 
	   long   ru_nvcsw;         // voluntary context switches 
	   long   ru_nivcsw;        // involuntary context switches 
   };
  */  
  if (getrusage(RUSAGE_SELF, &r_usage))
    return 1;
  INSERT("user CPU time used",  r_usage.ru_utime.tv_sec);
  INSERT("system CPU time used", r_usage.ru_stime.tv_sec);
  INSERT("maximum resident set size", r_usage.ru_maxrss);
  INSERT("integral shared memory size", r_usage.ru_ixrss);         
  INSERT("integral unshared data size", r_usage.ru_idrss);          
  INSERT("integral unshared stack size", r_usage.ru_isrss);           
  INSERT("page reclaims (soft page faults)", r_usage.ru_minflt);          
  INSERT("page faults (hard page faults)", r_usage.ru_majflt);         
  INSERT("swaps", r_usage.ru_nswap);        
  INSERT("block input operations", r_usage.ru_inblock);         
  INSERT("block output operations", r_usage.ru_oublock);         
  INSERT("IPC messages sent", r_usage.ru_msgsnd);          
  INSERT("IPC messages received", r_usage.ru_msgrcv);
  INSERT("signals received", r_usage.ru_nsignals);        
  INSERT("voluntary context switches", r_usage.ru_nvcsw);          
  INSERT("involuntary context switches", r_usage.ru_nivcsw);   
  
  rlimit r_limit;
  /*
   struct rlimit {
	   rlim_t rlim_cur;  // Soft limit 
	   rlim_t rlim_max;  // Hard limit (ceiling for rlim_cur) 
   };
  */
  if (getrlimit(RLIMIT_AS, &r_limit))
    return 1;
  INSERT("Maximum virtual memory", r_limit.rlim_cur);
  if (getrlimit(RLIMIT_DATA, &r_limit))
    return 1;
  INSERT("Maximum data memory", r_limit.rlim_cur);
  if (getrlimit(RLIMIT_FSIZE, &r_limit))
    return 1;
  INSERT("Maximum file size", r_limit.rlim_cur);
  if (getrlimit(RLIMIT_NOFILE, &r_limit))
    return 1;
  INSERT("Maximum number of files", r_limit.rlim_cur);

  return 0;
}
 
int sys_usage_init(void *p)
{
  ST_SCHEMA_TABLE *schema= (ST_SCHEMA_TABLE*) p;
  schema->fields_info= sys_usage_fields;
  schema->fill_table= fill_sys_usage;
  return 0;
}

static int sys_usage_deinit(void *p)
{
  return 0;
}
 
struct st_mysql_information_schema is_sys_usage=
{
  MYSQL_INFORMATION_SCHEMA_INTERFACE_VERSION  /* interface version    */
};
 
/*
 Plugin library descriptor
*/
mysql_declare_plugin(mysql_is_sys_usage)
{
  MYSQL_INFORMATION_SCHEMA_PLUGIN,            /* type                            */
  &is_sys_usage,                              /* descriptor                      */
  "SYS_USAGE",                                /* name                            */
  "Andrew Hutchings",                         /* author                          */
  "Information about system resource usage",  /* description                     */
  PLUGIN_LICENSE_GPL,
  sys_usage_init,                             /* init function (when loaded)     */
  sys_usage_deinit,                           /* deinit function (when unloaded) */
  0x0010,                                     /* version                         */
  NULL,                                       /* status variables                */
  NULL,                                       /* system variables                */
  NULL,                                       /* config options                  */
  0,                                          /* flags                           */
}
mysql_declare_plugin_end;
