import { Uint8ArrayToCharArray } from "@zk-email/helpers";
import { generateEmailVerifierInputs } from "@zk-email/helpers/dist/input-generators";

export const STRING_PRESELECTOR = "N=FAmero de cuenta: ";
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
};

export async function generateExampleVerifierCircuitInputs(
  email: string | Buffer
): Promise<IExampleCircuitInputs> {
  const emailVerifierInputs = await generateEmailVerifierInputs(email, {
    shaPrecomputeSelector: STRING_PRESELECTOR,
    maxBodyLength: 7040,
    removeSoftLineBreaks: true,
  });

  return {
    ...emailVerifierInputs,
  };
}

import fs from "fs";
(async () => {
    const raw_email = fs.readFileSync("../emls/email-mp.eml");
    const data  = await generateExampleVerifierCircuitInputs(raw_email);
    fs.writeFileSync("../inputs/inputs.json", JSON.stringify(data));
}) ();