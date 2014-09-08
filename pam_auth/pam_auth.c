/*
   Copyright (c) 2012, Oracle and/or its affiliates. All rights reserved.
   Author:  Sergei Golubchik for habrahabr.ru aka PaynetEasy team
   Licence: GPL
   Description: PAM authentication plugin.
*/
#include <string.h>
#include <mysql/plugin_auth.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <syslog.h>                             // syslog

struct param {
  unsigned char buf[10240], *ptr;
  MYSQL_PLUGIN_VIO *vio;
};

static int conv(int n, const struct pam_message **msg,
                struct pam_response **resp, void *data)
{
  struct param *param = (struct param *)data;
  unsigned char *end = param->buf + sizeof(param->buf) - 1;
  int i;

  for (i= 0; i < n; i++) {
     /* if there's a message - append it to the buffer */
    if (msg[i]->msg) {
      int len = strlen(msg[i]->msg);
      if (len > end - param->ptr)
        len = end - param->ptr;
      memcpy(param->ptr, msg[i]->msg, len);
      param->ptr+= len;
      *(param->ptr)++ = '\n';
    }

    /* if the message style is *_PROMPT_*, meaning PAM asks a question,
       send the accumulated text to the client, read the reply */
    if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
        msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
      int pkt_len;
      unsigned char *pkt;

      /* allocate the response array.
         freeing it is the responsibility of the caller */
      if (*resp == 0) {
        *resp = calloc(sizeof(struct pam_response), n);
        if (*resp == 0)
          return PAM_BUF_ERR;
      }

      /* dialog plugin interprets the first byte of the packet
         as the magic number.
         2 means "read the input with the echo enabled"
         4 means "password-like input, echo disabled"
         C'est la vie. */
      param->buf[0] = msg[i]->msg_style == PAM_PROMPT_ECHO_ON ? 2 : 4;
      if (param->vio->write_packet(param->vio, param->buf, param->ptr - param->buf - 1))
        return PAM_CONV_ERR;

      pkt_len = param->vio->read_packet(param->vio, &pkt);
      if (pkt_len < 0)
        return PAM_CONV_ERR;
      /* allocate and copy the reply to the response array */
      (*resp)[i].resp= strndup((char*)pkt, pkt_len);
      param->ptr = param->buf + 1;
    }
  }

  return PAM_SUCCESS;
}

#define DO_PAM(X)                       \
  do {                                  \
    status = (X);                       \
    if (status != PAM_SUCCESS)          \
    {                                   \
      syslog(LOG_ERR, "[AUTH FAILED] Reason: %s", pam_strerror(pamh, status)); \
      goto ret;                         \
    }                                   \
  } while(0)

static int pam_auth(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  pam_handle_t *pamh = NULL;
  int status;
  const char *new_username;
  struct param param;
  struct pam_conv c = { &conv, &param };

  const char *service = info->auth_string ? info->auth_string : "mysql";

  param.ptr = param.buf + 1;
  param.vio = vio;

  DO_PAM(pam_start(service, info->user_name, &c, &pamh));
  DO_PAM(pam_authenticate (pamh, 0));
  DO_PAM(pam_acct_mgmt(pamh, 0));
  DO_PAM(pam_get_item(pamh, PAM_USER, (const void**)&new_username));
  if (new_username)
    strncpy(info->authenticated_as, new_username, sizeof(info->authenticated_as));

ret:
  pam_end(pamh, status);
  return status == PAM_SUCCESS ? CR_OK : CR_ERROR;
}

static struct st_mysql_auth pam_auth_handler =
{
  MYSQL_AUTHENTICATION_INTERFACE_VERSION,       /* auth API version     */
  "dialog",                                     /* client plugin name   */
  pam_auth                                      /* main auth function   */
};

mysql_declare_plugin(pam_auth)
{
  MYSQL_AUTHENTICATION_PLUGIN,                  /* plugin type          */
  &pam_auth_handler,                            /* auth plugin handler  */
  "pam_auth",                                   /* plugin name          */
  "Sergei Golubchik",                           /* author               */
  "PAM based authentication",                   /* description          */
  PLUGIN_LICENSE_GPL,                           /* license              */
  NULL,                                         /* init function        */
  NULL,                                         /* deinit function      */
  0x0100,                                       /* version 1.0          */
  NULL,                                         /* for SHOW STATUS      */
  NULL,                                         /* for SHOW VARIABLES   */
  NULL,                                         /* unused               */
  0,                                            /* flags                */
}
mysql_declare_plugin_end;