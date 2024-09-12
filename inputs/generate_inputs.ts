import { generateEmailVerifierInputs } from "@zk-email/helpers/dist/input-generators";

export const STRING_PRESELECTOR = "N=FAmero de cuenta:";
export type IExampleCircuitInputs = {
  emailHeader: string[];
  emailHeaderLength: string;
  pubkey: string[];
  signature: string[];
  emailBody?: string[] | undefined;
  emailBodyLength?: string | undefined;
  precomputedSHA?: string[] | undefined;
  bodyHashIndex?: string | undefined;
  decodedEmailBodyIn?: string[] | undefined;
  userRegexIdx?: string | undefined;
  CBU?: string[] | undefined;
};

function stringToAsciiArray(s: string): number[] {
  return s.split('').map(char => char.charCodeAt(0));
}


export async function generateExampleVerifierCircuitInputs(
  email: string | Buffer
): Promise<IExampleCircuitInputs> {
  const emailVerifierInputs = await generateEmailVerifierInputs(email, {
    shaPrecomputeSelector: STRING_PRESELECTOR,
    maxBodyLength: 7040,
    maxHeadersLength: 576,
    removeSoftLineBreaks: true,
  });

  const bodyRemaining = emailVerifierInputs.decodedEmailBodyIn!.map((c) => Number(c)); // Char array to Uint8Array
  const selectorBuffer = Buffer.from(STRING_PRESELECTOR);
  const userRegexIdx =
    Buffer.from(bodyRemaining).indexOf(selectorBuffer) + selectorBuffer.length + 10;

  const cbu = stringToAsciiArray("0170341040000031187538");

  return {
    ...emailVerifierInputs,
    userRegexIdx: userRegexIdx.toString(),
    CBU: cbu.map((c) => c.toString()),
  };
}

import fs from "fs";
(async () => {
    const raw_email = fs.readFileSync("./emls/email-mp.eml");
    const data  = await generateExampleVerifierCircuitInputs(raw_email);
    fs.writeFileSync("./inputs/inputs.json", JSON.stringify(data));
}) ();