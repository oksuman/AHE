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
    srand((unsigned int)time(NULL));

        /*
                Paillier based Equality Protocol Test
                message : 0 ~ 2047 (char *)
        */


    system_clock::time_point Pa_total_start_time = system_clock::now();
        // Initial Step
    system_clock::time_point Pa_initial_start_time = system_clock::now();    
    PAILLIER pa = PAILLIER();
    PK pa_pk;
    SK pa_sk;
    pa.KeyGen(pa_pk,pa_sk);

    system_clock::time_point Pa_initial_end_time = system_clock::now();
    milliseconds pa_initial = duration_cast<milliseconds>(Pa_initial_end_time - Pa_initial_start_time);
    
    chrono::duration<double> Pa_step1(0);
    chrono::duration<double> Pa_step2(0);
    chrono::duration<double> Pa_step3(0);

    for(int k=0; k<1000; k++){
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
        
  
        system_clock::time_point Pa_step1_start_time = system_clock::now();  
        // // Step 1
        unsigned char *c_Alice = pa.Enc(pa_pk, hex_m_Alice);
        system_clock::time_point Pa_step1_end_time = system_clock::now();    
        Pa_step1 += Pa_step1_end_time-Pa_step1_start_time;

        system_clock::time_point Pa_step2_start_time = system_clock::now();  
        // // Step 2
        unsigned char *c_Bob = pa.Enc(pa_pk, hex_m_Bob);
        unsigned char *sub_result = pa.Sub(pa_pk, c_Alice, c_Bob);
        unsigned char *s = pa.generate_random_element2(pa_pk);
        unsigned char *c_result = pa.Scalar_Mul(pa_pk, s, sub_result);
        system_clock::time_point Pa_step2_end_time = system_clock::now();  
        Pa_step2 += Pa_step2_end_time-Pa_step2_start_time;

        system_clock::time_point Pa_step3_start_time = system_clock::now();  
        // // Step 3
        unsigned char *res = pa.Dec(pa_pk, pa_sk, c_result);
        system_clock::time_point Pa_step3_end_time = system_clock::now();  
        Pa_step3 += Pa_step3_end_time-Pa_step3_start_time;

    }
    system_clock::time_point Pa_total_end_time = system_clock::now();
    milliseconds milli_pa = duration_cast<milliseconds>(Pa_total_end_time - Pa_total_start_time);
    milliseconds pa_step1 = duration_cast<milliseconds>(Pa_step1);
    milliseconds pa_step2 = duration_cast<milliseconds>(Pa_step2);
    milliseconds pa_step3 = duration_cast<milliseconds>(Pa_step3);
    cout << "initial : " << pa_initial.count() << "ms" << endl;
    cout << "ece_step1 : " << pa_step1.count() << "ms" << endl;
    cout << "ece_step2 : " << pa_step2.count() << "ms" << endl;
    cout << "ece_step3 : " << pa_step3.count() << "ms" << endl;
    cout << milli_pa.count() << "ms" << endl;
}

