#ifndef KERBEROS_H_INCLUDED
#define KERBEROS_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <krb5.h>
#include <fcntl.h>
#include <string.h>
#define BOOL char

krb5_error_code krb5_get_ticket(const char* user, const char* realm, const char* keytabName);
void krb5_releaseAll();

#endif // KERBEROS_H_INCLUDED
