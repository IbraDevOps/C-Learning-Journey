// this is the firs ex1    */
#include <stdio.h>
int main() {
    char grad_label[50],name[50];
    int math,ENglish,science,total;
    printf("Enter student name\n");
    scanf("%49s",name);
    printf("%s, please enter you maths marks\n", name);
    scanf("%d", &math);
    printf("%s, please enter you ENglish  marks\n",name);
    scanf("%d", &ENglish);
    printf("%s, please enter you science marks\n",name);
    scanf("%d", &science);

    total= math+ENglish+science;
    float average = total/3.0;
    if (average> 80) {
        sprintf(grad_label, "excellent");
    } else {
        sprintf(grad_label, "Not excellent");
    }
//else grade= below excellent
    //printf("Result: %s\n",grad_label);
    printf("Result for %s: %s (Average: %.2f)\n", name, grad_label, average);
    return 0;

}
