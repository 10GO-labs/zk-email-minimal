pragma circom 2.1.6;
include "@zk-email/circuits/email-verifier.circom";
include "@zk-email/circuits/utils/regex.circom";
// regex-sdk currently does not support directly generating the regex for to and from address
include "@zk-email/zk-regex-circom/circuits/common/from_addr_regex.circom";
include "@zk-email/zk-regex-circom/circuits/common/to_addr_regex.circom";

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
    component EV = EmailVerifier(maxHeaderLength, maxBodyLength, n, k, 0, 1, 0);
    EV.emailHeader <== emailHeader;
    EV.emailHeaderLength <== emailHeaderLength;
    EV.pubkey <== pubkey;
    EV.signature <== signature;
    EV.bodyHashIndex <== bodyHashIndex;
    EV.precomputedSHA <== precomputedSHA;
    EV.emailBody <== emailBody;
    EV.emailBodyLength <== emailBodyLength;
    EV.decodedEmailBodyIn <== decodedEmailBodyIn;
    
    // CBU/CVU extraction
    signal input userRegexIdx;
    var userMaxLength = 22;
    signal userRegexOut, userRegexReveal[maxBodyLength];

    (userRegexOut, userRegexReveal) <== ToAddrRegex(maxBodyLength)(decodedEmailBodyIn);

    userRegexOut === 1;

    signal output userPackedOut[computeIntChunkLength(userMaxLength)];
    userPackedOut <== PackRegexReveal(maxBodyLength, userMaxLength)(userRegexReveal, userRegexIdx);

}


component main = MercadoPagoTransferencia(512, 7040, 121, 17, 7);
