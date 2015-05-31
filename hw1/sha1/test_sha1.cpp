#include "sha1.hpp"
#include <string>
#include <iostream>
using std::string;
using std::cout;
using std::endl;


void compare(const string &result, const string &expected)
{
    const string &state = (result == expected) ? "OK" : "Failure";
    cout << "Result:   " << result << endl;
    cout << "Expected: " << expected << "  (" << state << ")" << endl;
}


/*
 * The 3 test vectors from FIPS PUB 180-1
 */

void test_standard()
{
    SHA1 checksum;

    cout << endl;
    cout << "Test:     No string" << endl;
    compare(checksum.final(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}


/*
 * Other tests
 */

void test_other()
{
    SHA1 checksum;

  

    cout << endl;
    checksum.update("");
    cout << "Test:     Empty string" << endl;
    compare(checksum.final(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    cout << endl;
    cout << "Test:     ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" << endl;
    checksum.update("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    compare(checksum.final(), "03de6c570bfe24bfc328ccd7ca46b76eadaf4334");

    cout << endl;
    cout << "Test:     Two concurrent checksum calculations" << endl;
    SHA1 checksum1, checksum2;
    checksum1.update("abc");
    compare(checksum2.final(), "da39a3ee5e6b4b0d3255bfef95601890afd80709"); /* "" */
    compare(checksum1.final(), "a9993e364706816aba3e25717850c26c9cd0d89d"); /* "abc" */

    cout << endl;
    cout << "Test:     abc" << endl;
    checksum.update("abc");
    compare(checksum.final(), "a9993e364706816aba3e25717850c26c9cd0d89d");

    cout << endl;
    cout << "Test:     abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" << endl;
    checksum.update("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    compare(checksum.final(), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");

    cout << endl;
    cout << "Test:     A million repetitions of 'a'" << endl;
    for (int i = 0; i < 1000000/200; ++i)
    {
        checksum.update("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                       );
    }
    compare(checksum.final(), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
}


int main(int argc, const char *argv[])
{

        test_standard();
        //test_other();
        cout << endl;
        cout << endl;

    return 0;
}
