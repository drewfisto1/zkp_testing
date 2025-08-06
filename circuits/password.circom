pragma circom 2.1.4;

include "circomlib/circuits/mimc.circom";

template PasswordCircuit() {
    signal input password;
    signal input nonce;
    signal input salt[16];

    signal temp[18];  

    component mimc0 = MiMC7(91);
    mimc0.x_in <== salt[0];
    mimc0.k <== 0;
    temp[0] <== mimc0.out;

    component mimc_i[15];
    for (var i = 1; i < 16; i++) {
        mimc_i[i - 1] = MiMC7(91);
    }
    for (var i = 1; i < 16; i++) {
        mimc_i[i - 1].x_in <== temp[i - 1];
        mimc_i[i - 1].k <== salt[i];
        temp[i] <== mimc_i[i - 1].out;
    }

    component mimc_password = MiMC7(91);
    mimc_password.x_in <== temp[15];
    mimc_password.k <== password;
    temp[16] <== mimc_password.out;

    component mimc_nonce = MiMC7(91);
    mimc_nonce.x_in <== temp[16];
    mimc_nonce.k <== nonce;
    temp[17] <== mimc_nonce.out;

    signal output out;
    out <== temp[17];
}

component main = PasswordCircuit();