// g++ -o pa_test Pa_Test.cpp Paillier.cpp -lssl -lcrypto

#include <iostream>
#include <cstdlib>
#include <stdlib.h>
#include <ctime>
#include <chrono>
#include "Paillier.h"

using namespace std;
using namespace chrono;

int main(int argc, char* argv[]){

        /*
                Paillier based Equality Protocol Test
                message : 0 ~ 2047 (char *)
        */
    system_clock::time_point Pa_total_start_time = system_clock::now();
    for(int k=0; k<1000; k++){
        srand((unsigned int)time(NULL));
        int m_Alice = rand() % 2048;
        int m_Bob = rand() % 2048;
        
        int remainder;
        int Alice_size, Bob_size;
        
        if(m_Alice < 16)
            Alice_size = 2;
        else if(m_Alice < 256)
            Alice_size = 3;
        else if(m_Alice < 4096)
            Alice_size = 4;
        else
            Alice_size = 0;

        if(m_Bob < 16)
            Bob_size = 2;
        else if(m_Bob < 256)
            Bob_size = 3;
        else if(m_Bob < 4096)
            Bob_size = 4;
        else
            Bob_size = 0;
       
        unsigned char hex_m_Alice[4] = {'\0','\0','\0','\0'};
        unsigned char hex_m_Bob[4] = {'\0','\0','\0','\0'};
       
        for(int i=0; i<Alice_size; i++){
            remainder = m_Alice % 16;
            m_Alice /= 16;
            char ch;
            if(remainder >= 10)
                ch = remainder + 55;
            else
                ch = remainder + 48;
            hex_m_Alice[Alice_size - i -1] = ch; 
        }
        
        for(int i=0; i<Bob_size; i++){
            remainder = m_Bob % 16;
            m_Bob /= 16;
            char ch;
            if(remainder >= 10)
                ch = remainder + 55;
            else
                ch = remainder + 48;
            hex_m_Bob[Bob_size - i -1] = ch; 
        }
        
  
        // Initial Step
        PAILLIER pa = PAILLIER();
        PK pa_pk;
        SK pa_sk;
        pa.KeyGen(pa_pk,pa_sk);
       
        // // Step 1
        unsigned char *c_Alice = pa.Enc(pa_pk, hex_m_Alice);

        // // Step 2
        unsigned char *c_Bob = pa.Enc(pa_pk, hex_m_Bob);
        unsigned char *sub_result = pa.Sub(pa_pk, c_Alice, c_Bob);
        unsigned char *s = pa.generate_random_element2(pa_pk);
        unsigned char *c_result = pa.Scalar_Mul(pa_pk, s, sub_result);

        // // Step 3
        unsigned char *res = pa.Dec(pa_pk, pa_sk, c_result);

    }
    system_clock::time_point Pa_total_end_time = system_clock::now();
    milliseconds milli_pa = duration_cast<milliseconds>(Pa_total_end_time - Pa_total_start_time);
    cout << milli_pa.count() << "ms" << endl;
}

