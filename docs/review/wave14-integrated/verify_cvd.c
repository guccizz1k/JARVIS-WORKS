/* Compile against the actual installed ClamAV >=1.5 headers. No guessed flags.
 * The caller must stage pinned CVD, matching .sign and trusted vendor certs.
 * Failure or absent modern API is BLOCKED; no fallback to legacy signatures. */
#include <clamav.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) return 2;
    cl_error_t rc = cl_cvdverify_ex(argv[1], argv[2], CL_DB_FIPS_LIMITS);
    if (rc != CL_SUCCESS) { fprintf(stderr,"CVD_VENDOR_VERIFY_FAILED\n"); return 1; }
    return 0;
}
