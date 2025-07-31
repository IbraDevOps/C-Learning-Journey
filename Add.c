//# cat hello.c
#include <stdio.h>
//int main() {

   // printf("Hello World from C\n");
  //  return 0;

//}
           
#include <stdio.h>
int main() {

    int num1, num2,sum;


    printf("please enter num1\n");
    scanf("%d", &num1);
    printf("please enter num2\n");
    scanf("%d", &num2);
    sum = num1+num2;
    printf("The sumation is %d\n",sum);
    return 0;
}
