// g++ -o test Test.cpp GM.cpp -lssl -lcrypto

#include <iostream>
#include <cstdlib>
#include <ctime>
#include <chrono>
#include "GM.h"

using namespace std;
using namespace chrono;

int main(int argc, char* argv[]){
    srand((unsigned int)time(NULL));

    system_clock::time_point start_time = system_clock::now();

    /*
        GM based Equality Protocol Test
        message : 0 ~ 2047 (11bits binary)

        padding : -1 
    */

    // Initial Step 
    GM gm = GM();
    PK gm_pk; 
    SK gm_sk; 
   
    // Step 1
    int m1 = 2000;

    char bin_m[11];
    int i = 0;

	while(m1 != 0){
		bin_m[i] = m1 % 2;
		i++;
		m1 /= 2;
	}
    while(i < 11){
        bin_m[i] = -1;
        i++;
    }

    unsigned char* gm_c[11];
   
    for(int i=0; i<11; i++){
        gm_c[i] = gm.Enc(gm_pk, bin_m[i]);
    }
    // for(int i=0; i<11; i++){
    //     cout << bin_m[i];
    // }
    // cout << endl;

    // for(int i=0; i<11; i++){
    //     bool dm = gm.Dec(gm_pk, gm_sk, gm_c[i]);
    //     if(dm)
    //         cout << '1';
    //     else
    //         cout << '0';
    // }
    // cout << endl;


    // printf("m1 : %d\n", m1);
    // printf("m2 : %d\n", m2);
    // printf("m3 : %d\n", m3);
    // gm.KeyGen(1024, gm_pk, gm_sk);

    // unsigned char* c1 = gm.Enc(gm_pk, &m1);
    // unsigned char* c2 = gm.Enc(gm_pk, &m2);
    // unsigned char* c3 = gm.Enc(gm_pk, &m3);
    // unsigned char* c1_c2 = gm.XOR(gm_pk, c1, c2); 
    // unsigned char* c1_c3 = gm.XOR(gm_pk, c1, c3); 

    // cout << gm.Dec(gm_pk, gm_sk, c1_c2) << endl;
    // cout << gm.Dec(gm_pk, gm_sk, c1_c3) << endl;
    

    // system_clock::time_point end_time = system_clock::now();
    // microseconds micros = duration_cast<microseconds>(end_time - start_time);
    // cout << micros.count() << "ms" << endl;

}

