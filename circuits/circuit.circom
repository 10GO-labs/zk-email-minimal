pragma circom 2.1.6;
include "@zk-email/circuits/email-verifier.circom";
include "@zk-email/circuits/utils/regex.circom";
include "@zk-email/circuits/utils/array.circom";
include "circomlib/circuits/comparators.circom";

include "./regex/nro-cuenta.circom";

template MercadoPagoTransferencia(maxHeaderLength, maxBodyLength, n, k, packSize) {
    assert(n * k > 1024); // constraints for 1024 bit RSA

    signal input emailHeader[maxHeaderLength]; // prehashed email data, includes up to 512 + 64? bytes of padding pre SHA256, and padded with lots of 0s at end after the length
    signal input emailHeaderLength;
    signal input pubkey[k]; // rsa pubkey, verified with smart contract + DNSSEC proof. split up into k parts of n bits each.
    signal input signature[k]; // rsa signature. split up into k parts of n bits each.
    signal input bodyHashIndex;
    signal input precomputedSHA[32];
    signal input emailBody[maxBodyLength];
    signal input emailBodyLength;
    signal input decodedEmailBodyIn[maxBodyLength];

    // DKIM Verification
    component EV = EmailVerifier(maxHeaderLength, maxBodyLength, n, k, 1, 1, 0);
    EV.emailHeader <== emailHeader;
    EV.emailHeaderLength <== emailHeaderLength;
    EV.pubkey <== pubkey;
    EV.signature <== signature;
    // EV.bodyHashIndex <== bodyHashIndex;
    // EV.precomputedSHA <== precomputedSHA;
    // EV.emailBody <== emailBody;
    // EV.emailBodyLength <== emailBodyLength;
    // EV.decodedEmailBodyIn <== decodedEmailBodyIn;
    
    // CBU/CVU extraction
    signal input userRegexIdx;
    var userMaxLength = 22;
    signal userRegexOut, userRegexReveal[maxBodyLength];

    (userRegexOut, userRegexReveal) <== RegexNroCuenta(maxBodyLength)(decodedEmailBodyIn);

    userRegexOut === 1;
    signal input CBU[22];
    
    component sub = SelectSubArray(maxBodyLength, userMaxLength);
    sub.in <== userRegexReveal;
    sub.startIndex <== userRegexIdx;
    sub.length <== 22;

    component check[22];
    for (var i = 0; i < 22; i++) {
        check[i] = IsEqual();
        check[i].in[0] <== sub.out[i];
        check[i].in[1] <== CBU[i];
        check[i].out === 1;
    }
    
}


component main = MercadoPagoTransferencia(576, 7040, 121, 17, 7);