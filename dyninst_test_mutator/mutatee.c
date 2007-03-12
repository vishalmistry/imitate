#include <stdio.h>

int main(int argc, char **argv)
{
  int i;

  printf("Loop Up: ");
  for (i=0; i < 40; i++)
  {
    printf("%d ", i);
  }

  sleep(1);

  printf("\nLoop Down: ");
  for (; i > 20; i--)
  {
    printf("%d ", i);
  }
  
  printf("\n");
  return 0;
}
