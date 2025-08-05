/* ATM simulation Console App
The output should be like this:
*/
#include <stdio.h>
int main() {
    int pin,choice;
    long long Account_No;
    float amount,balance = 0.0; 
    char menu[49];
    printf("Hello customer and welcome to ChatBank ATM \n");
    printf("***************************************************\n");
    printf("Please enter your PIN\n");
    scanf("%d", &pin);
    if (pin == 202553){
        printf("Access Granted!\n");
        do {
        printf(" --------MENU ---------\n");
        printf("1 --------Check balance ---------\n");

        printf("2 --------Deposit ---------\n");

        printf("3 --------Withdraw ---------\n");
        printf("4 --------Exit ---------\n");
        printf("Enter your choice\n");
        scanf("%d",&choice);
        if (choice == 1) {
       printf("Your curent balance is : %.2f\n",balance);
        } else if (choice == 2) {
        printf("Please enter your acccount: ");
        scanf("%lld", &Account_No);
        if(Account_No == 36524533001) {
        printf("Enter amount to deposit: ");
        scanf("%f",&amount);
        balance += amount;
       printf("Deposit succefull! New balance is : %.2f\n",balance);
      } else { 
       printf("Wrong Accout number\n");
      }  
      } else if (choice == 3) {
      printf("Please enter amount to withdraw: ");
      scanf("%f", &amount);
      
      if (amount <= balance) {
      balance -= amount;
      printf("Withdrawal succeful! New balance is %.2f\n",balance);
      } else { 
      printf("Sorry insufficnrt funds!\n");
      }
}
//start you menu excutions
if(choice != 4) {
//printf(" What do you want to do?");
}
} while (choice != 4);

        printf("Thank you for using ChatBank ATM!\n");

}  else {
   printf("Wrong Password,Access Denied\n");


}
}
//}
//}


