#include "openssl_stack_standalone.h"

typedef struct example_st
{
    int a;
    float b;
} example_t;

DECLARE_STACK_OF(example_t);
DECLARE_ASN1_FUNCTIONS(example_t);
DECLARE_ASN1_ITEM(example_t);
DECLARE_ASN1_SET_OF(example_t);
DEFINE_STACK_OF(example_t);

int main(void)
{
    STACK_OF(example_t) *stackex = sk_example_t_new_null();
    example_t one;
    example_t two;
    example_t* current = NULL;
    int i = 0;

    one.a = 9;
    one.b = (float)3.4;

    two.a = 2;
    two.b = (float)2.1;

    sk_example_t_push(stackex, &one);
    sk_example_t_push(stackex, &one);
    sk_example_t_push(stackex, &two);
    sk_example_t_push(stackex, &one);

    for (i = 0; i < 4; i++)
    {
        current = sk_example_t_pop(stackex);
        if (NULL != current)
        {
            printf("\n a: %d - b: %f \n", current->a, current->b);
        }
    }

    puts("\npress enter to close.");

    getchar();



    return 0;
}