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
    for(int k=0; k<1; k++){
        srand((unsigned int)time(NULL));
        int m_Alice = 1000;
        int m_Bob = 100;
        // int m_Alice = rand() % 2048;
        // int m_Bob = rand() % 2048;
        cout << m_Alice << endl;
        cout << m_Bob << endl;
        
        unsigned char hex_m_Alice[4] = {0,0,0,0};
        unsigned char hex_m_Bob[4] = {0,0,0,0};
        int remainder, index = 0;
        
        while(m_Alice !=0){
            remainder = m_Alice % 16;
            m_Alice /= 16;
            char ch;
            if(remainder >= 10)
                ch = remainder + 55;
            else
                ch = remainder + 48;
            hex_m_Alice[index] = ch;
            index++; 
        }
        index = 0;
        while(m_Bob !=0){
            remainder = m_Bob % 16;
            m_Bob /= 16;
            char ch;
            if(remainder >= 10)
                ch = remainder + 55;
            else
                ch = remainder + 48;
            hex_m_Bob[index] = ch;
            index++; 
        }

        
        // Initial Step
        
        
        PAILLIER pa = PAILLIER();
        PK pa_pk;
        SK pa_sk;
        pa.KeyGen(pa_pk,pa_sk);
       
        // Step 1
        unsigned char *c_Alice = pa.Enc(pa_pk, hex_m_Alice);
        cout << c_Alice << endl;
        cout << "cA" << pa.Dec(pa_pk, pa_sk, c_Alice) << endl;

        // Step 2
        unsigned char *c_Bob = pa.Enc(pa_pk, hex_m_Bob);
        cout << c_Bob << endl;
        cout << "cB" << pa.Dec(pa_pk, pa_sk, c_Bob) << endl;

        unsigned char *sub_result = pa.Sub(pa_pk, c_Alice, c_Bob);
        cout << sub_result << endl;
        cout << "sr" << pa.Dec(pa_pk, pa_sk, sub_result) << endl;

        unsigned char *s = pa.generate_random_element2(pa_pk);
        cout << s << endl;

        unsigned char *c_result = pa.Scalar_Mul(pa_pk, s, sub_result);
        cout << "cres" << c_result << endl;

        // Step 3
        unsigned char *res = pa.Dec(pa_pk, pa_sk, c_result);
        cout << res << endl;
    }
    system_clock::time_point Pa_total_end_time = system_clock::now();
    milliseconds milli_pa = duration_cast<milliseconds>(Pa_total_end_time - Pa_total_start_time);
    cout << milli_pa.count() << "ms" << endl;
}

