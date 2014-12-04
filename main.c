#include "kerberos.h"
#include <stdio.h>

int main(){
  int err = krb5_get_ticket("pierre","HADOOP.ADALTAS.COM","/home/pierrotws/pierre.keytab");
  if(!err){
      printf("NO ERROR !\nHoura !");
      krb5_releaseAll();
  }
  else printf("error = %d",err);
  return 0;
}
