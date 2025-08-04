#include "NuMicro.h"

extern void SYS_Init(void);

int main(void)
{
    SYS_UnlockReg();
    SYS_Init();

    UART_Open(UART0, 115200);

    printf("helloworld\n");

    while(1);
}