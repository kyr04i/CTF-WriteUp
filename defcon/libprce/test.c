#include <stdio.h>
#include <pcre.h>
#include <string.h>

int
main(int argc, char *argv[])
{

  if(argc < 3)
  {
    fprintf(stderr,"usage: %s \"regex\" subject\n",argv[0]);
    return EXIT_FAILURE;
  }

  /* for pcre_compile */
  pcre *re;
  const char *error;
  int erroffset;

  /* for pcre_exec */
  int rc;
  int ovector[30];

  /* to get substrings from regex */
  int rc2;
  const char *substring;

  // we'll start after the first quote and chop off the end quote
  const char *regex = argv[1];
  const char *subject = argv[2];
  re = pcre_compile(regex, 0, &error, &erroffset, NULL);

  rc = pcre_exec(re, NULL, subject, strlen(subject), 0, 0, ovector, 30);

  if(rc == PCRE_ERROR_NOMATCH)
  {
    fprintf(stderr,"no match\n");
  }
  else if(rc < -1)
  {
    fprintf(stderr,"error %d from regex\n",rc);
  }
  else
  {
    // loop through matches and return them
    for(int i=0; i<rc; i++)
    {
      rc2 = pcre_get_substring(subject, ovector, rc, i, &substring);
      printf("%d: %s\n",i,substring);
      pcre_free_substring(substring);
    }
  }
  pcre_free(re);

  return rc;
}