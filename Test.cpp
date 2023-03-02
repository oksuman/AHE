// g++ -o test Test.cpp GM.cpp -lssl -lcrypto

#include <iostream>
#include <cstdlib>
#include <ctime>
#include <chrono>
#include "GM/GM.h"

using namespace std;
using namespace chrono;

int main(int argc, char* argv[]){
    srand((unsigned int)time(NULL));

    system_clock::time_point gm_total_start_time = system_clock::now();

    /*
        GM based Equality Protocol Test
        message : 0 ~ 2047 (11bits binary)
        padding : -1 
    */
    int m_Alice = rand() % 2048;
    int m_Bob = rand() % 2048;

    // Initial Step 
    GM gm = GM();
    PK gm_pk; 
    SK gm_sk; 
    gm.KeyGen(1024, gm_pk, gm_sk);
   
    // Step 1
    char bin_m_Alice[11];
    int i = 0;
    if(m_Alice == 0){
        bin_m_Alice[i] = 0;
        i++;
    } 
	while(m_Alice != 0){
		bin_m_Alice[i] = m_Alice % 2;
		i++;
		m_Alice /= 2;
	}
    while(i < 11){
        bin_m_Alice[i] = -1;
        i++;
    }
    unsigned char* gm_c_Alice[11];
    for(int i=0; i<11; i++){
        gm_c_Alice[i] = gm.Enc(gm_pk, bin_m_Alice[i]);
    }

    // Step 2
    char bin_m_Bob[11];
    int j = 0;
    if(m_Bob == 0){
        bin_m_Bob[j] = 0;
        j++;
    } 
	while(m_Bob != 0){
		bin_m_Bob[j] = m_Bob % 2;
		j++;
		m_Bob /= 2;
	}
    while(j < 11){
        bin_m_Bob[j] = -1;
        j++;
    }
    unsigned char* gm_c_Bob[11];
    for(int j=0; j<11; j++){
        gm_c_Bob[j] = gm.Enc(gm_pk, bin_m_Bob[j]);
    }

    unsigned char* gm_c_xor[11];
    for(int j=0; j<11; j++){
        gm_c_xor[j] = gm.XOR(gm_pk, gm_c_Alice[j],  gm_c_Bob[j]);
    }
    

    // Step 3
    // 다르면 1 같으면 0

    for(int i=0; i<11; i++){
        bool dm = gm.Dec(gm_pk, gm_sk, gm_c_Alice[i]);
        if(dm)
            cout << '1';
        else
            cout << '0';
    }
    cout << endl;

    system_clock::time_point gm_total_end_time = system_clock::now();
    microseconds micros = duration_cast<microseconds>(gm_total_end_time - gm_total_start_time);
    cout << micros.count() << "ms" << endl;

}

