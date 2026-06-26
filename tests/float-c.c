#include <math.h>
#include <stdio.h>

// Exercises SSE scalar/packed float, integer<->float conversions, float
// comparisons, and the x87 long-double path (including printf's %f/%Lf
// formatting). The volatile inputs keep the compiler from constant-folding the
// whole computation away, so the emulator really executes the float opcodes.

static int close_d(double a, double b) { return fabs(a - b) < 1e-9; }
static int close_f(float a, float b) { return fabsf(a - b) < 1e-5f; }

int main(void)
{
    volatile double x = 3.0, y = 2.0;
    volatile float fx = 1.5f, fy = 0.25f;

    double sum = x + y;                       // ADDSD            -> 5
    double diff = x - y;                      // SUBSD            -> 1
    double prod = x * y;                      // MULSD            -> 6
    double quot = x / y;                      // DIVSD            -> 1.5
    double root = sqrt(prod);                 // SQRTSD           -> 2.449...
    float fsum = fx + fy;                     // ADDSS            -> 1.75
    float fprod = fx * fy;                    // MULSS            -> 0.375
    int itrunc = (int)(x * y + 0.9);          // CVTTSD2SI        -> 6
    double from_int = (double)itrunc;         // CVTSI2SD         -> 6
    double widened = (double)fsum;            // CVTSS2SD         -> 1.75
    long double ld = (long double)x * (long double)y + 1.0L; // x87 -> 7

    int ok = 1;
    ok &= close_d(sum, 5.0);
    ok &= close_d(diff, 1.0);
    ok &= close_d(prod, 6.0);
    ok &= close_d(quot, 1.5);
    ok &= close_d(root, 2.449489742783178);
    ok &= close_f(fsum, 1.75f);
    ok &= close_f(fprod, 0.375f);
    ok &= (itrunc == 6);
    ok &= close_d(from_int, 6.0);
    ok &= close_d(widened, 1.75);
    ok &= (ld > 6.9999L && ld < 7.0001L);
    ok &= (x > y);                            // COMISD / ordered compare
    ok &= !(x < y);

    printf("float: sum=%.1f prod=%.1f root=%.4f fsum=%.2f ld=%.1Lf\n",
        sum, prod, root, fsum, ld);
    if (ok) {
        printf("float ok\n");
        return 0;
    }
    printf("float FAIL\n");
    return 1;
}
