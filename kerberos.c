#include "kerberos.h"
#include <gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <stdlib.h>
#include "spnegokrb5/spnegokrb5.h"
#include "base64.h"

/**GSS-API VARS**/
static gss_OID_desc gss_mech_spnego = { 6, (void *) "\x2b\x06\x01\x05\x05\x02" };

/** KERBEROS VARS **/
static krb5_context context;
static krb5_keytab keytab;
static krb5_ccache cache;
static krb5_principal principal;


/*
* To initialize your Kerberos context:
*/

void krb5_init_error(int level, const char* mesg){
  switch(level){
    default:
    case 4:
      krb5_cc_close(context, cache);
    case 3:
      krb5_free_principal(context,principal);
    case 2:
      krb5_free_context(context);
    case 1:
    case 0:
      fprintf(stderr,"%d. %s\n",level,mesg);
  }
}


OM_uint32 import_name(char *name, gss_name_t* desired_name){
  OM_uint32 minor_status;
  gss_buffer_desc input_name_buf;
  input_name_buf.value = name;
  input_name_buf.length=strlen(name)+1;
  return gss_import_name(&minor_status, &input_name_buf, (const gss_OID)GSS_C_NT_HOSTBASED_SERVICE, desired_name);
}


OM_uint32 spnego_auth(char* username){
  gss_cred_id_t gss_cred;
  gss_name_t target_name;

  gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;

  OM_uint32 minor_status;
  OM_uint32 err=0;

  gss_buffer_desc input_buf=GSS_C_EMPTY_BUFFER;
  gss_buffer_desc output_buf=GSS_C_EMPTY_BUFFER;

  input_buf.length=0;

  err=import_name(username,&target_name);

  err=gss_krb5_import_cred(&minor_status, cache,principal, keytab,&gss_cred);
  if(err){
    krb5_init_error(8,"converting kerberos ticket in gss error");
    return err;
  }
  do{
    err = gss_init_sec_context_spnego(&minor_status,gss_cred,
                              &gss_context,
                              target_name,
                              &gss_mech_spnego,
                              0,
                              0,
                              GSS_C_NO_CHANNEL_BINDINGS,
                              &input_buf,
                              NULL,
                              &output_buf,
                              NULL,
                              NULL);
    switch(err){
    case 0:
      printf("LOOK :%s\n",(char*)output_buf.value);
    default:
      printf("ERR:%s!\n",krb5_get_error_message(context,minor_status));
      break;
    }
  } while(err==-1);

  //encode64(output_buf.value,mybuf,669);
  //printf("\n\ninput token length=%d\ndata:\n%s\n",output_buf.length,mybuf);


  return err;
}

krb5_error_code krb5_get_ticket(const char* user, const char* realm, const char* keytabName) {
  krb5_creds* cred;
  krb5_error_code err;

  if(!(realm && user)){
    krb5_init_error(0,"params error");
    return -1;
  }

  err = krb5_init_secure_context(&context);
  if(err){
    krb5_init_error(1,"init secure context error");
    return err;
  }
  err = krb5_build_principal(context, &principal, strlen(realm),realm,user,NULL);
  if(err){
    krb5_init_error(2,"build Principal error");
    return err;
  }
  err = krb5_cc_default(context, &cache);
  if(err){
    krb5_init_error(3,"cache: no default cache");
    return err;
  }
  err = krb5_cc_initialize(context, cache,principal);
  if(err){
    krb5_init_error(4,"cache: initialization error");
    return err;
  }

  cred = malloc(sizeof(krb5_creds));
  memset(cred, 0, sizeof(krb5_creds));
  if(keytabName){
    char str_buf[256];
    char str_buf2[256];
    realpath(keytabName,str_buf2);
    sprintf(str_buf,"FILE:%s",str_buf2);
    err = krb5_kt_resolve(context, str_buf, &keytab);
  }
  else{
    err = krb5_kt_default(context,&keytab);
  }
  if(err){
    krb5_init_error(5, "keytab not valid");
    return err;
  }
  err = krb5_get_init_creds_keytab(context, cred, principal, keytab, 0, NULL, NULL);
  if(err){
    krb5_init_error(6,"credential error: using a keytab");
    return err;
  }
  err = krb5_cc_store_cred(context, cache, cred);
  if(err){
    krb5_init_error(6,"credentials cache error");
    return err;
  }

  err = spnego_auth("HTTP@HADOOP.ADALTAS.COM");
  if(err){
    krb5_init_error(7, "spnego error");
    return err;
  }
  return 0;
}

void krb5_releaseAll(){
  krb5_free_principal(context,principal);
  krb5_cc_close(context, cache);
  krb5_free_context(context);
}
