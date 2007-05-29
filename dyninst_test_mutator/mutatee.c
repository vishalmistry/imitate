#include <stdio.h>

void a()
{
    printf("Called function a()\n");
}

int main(int argc, char **argv)
{
  int i;

  a();
  a();

  printf("Loop Up: ");
  for (i=0; i < 40; i++)
  {
    printf("%d ", i);
  }

  printf("\nLoop Down: ");
  for (; i > 20; i--)
  {
    printf("%d ", i);
  }
  
  printf("\n");
  return 0;
}
